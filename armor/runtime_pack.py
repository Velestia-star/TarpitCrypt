#!/usr/bin/env python3
"""运行时加固：把程序包加密成「双击即可运行」的单文件 exe。

与 container（.armored）的区别
------------------------------
container 是「加密保管」：必须先用口令还原到磁盘才能使用，明文长期留在本机。
runtime  是「加密运行」：加密包内嵌在启动器 exe 尾部，双击后输入口令，
          解密到临时目录、启动原程序、退出后覆写擦除，磁盘上不长期保留明文。

边界（务必如实告知使用者）
--------------------------
* 程序要运行，明文必然在某一时刻进入内存。本工具抬高静态取证门槛，
  无法阻止运行中的内存 dump / 调试器抓取 / 屏幕录制。
* 不注入第三方进程、不反沙箱、不绕过任何安全产品检测。
* 仅用于加固你自己拥有或已获授权的程序包。

数据格式 RTPK v1
----------------
    MAGIC(8)=b"RTPK0001" | VERSION(1) | FLAGS(1)
    MEM(4) | TIME(1) | PARA(1) | SALT(16) | NONCE(12)
    PAYLOAD_LEN(8) | MANIFEST_LEN(4) | MANIFEST(json) | CIPHERTEXT | TAG(16)

FLAGS bit0 = 需要口令；bit1 = 免密模式（密钥内嵌，仅混淆，保护极弱）。

尾部注入（单文件 exe）
----------------------
    [runner.exe 原始字节][RTPK 包][FOOTER]
    FOOTER = MAGIC(8)=b"RTPKEND1" | PACK_OFFSET(8) | PACK_LEN(8) | CRC32(8) | RESERVED(8)
    PE loader 忽略 overlay 之后的额外数据，因此追加不影响 exe 执行。
"""

from __future__ import annotations

import argparse
import binascii
import io
import json
import os
import struct
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"RTPK0001"
FOOTER_MAGIC = b"RTPKEND1"
FOOTER_LEN = 40
VERSION = 1

FLAG_PASSWORD = 0x01
FLAG_NO_PASSWORD = 0x02

# (memory KiB, time_cost, parallelism)
PROFILES: dict[str, tuple[int, int, int]] = {
    "轻": (32 * 1024, 2, 1),
    "中": (64 * 1024, 2, 1),
    "狠": (256 * 1024, 3, 2),
}
DEFAULT_PROFILE = "中"

# 免密模式的固定密钥来源（文档明确标注：等价于混淆壳，挡不住定向逆向）
_NO_PASSWORD_SECRET = b"RTPK-NO-PASSWORD-DEMO-ONLY-not-a-real-secret"

MAX_PACKAGE_BYTES = 512 * 1024 * 1024  # 内存打包上限，防止单包吃光内存

Progress = Callable[[int, int, str], None]


class RuntimePackError(Exception):
    """运行时加固过程中的可预期错误。"""


def _notify(cb: Progress | None, done: int, total: int, text: str) -> None:
    if cb:
        cb(done, total, text)


@dataclass(frozen=True)
class Manifest:
    entry: str
    files: int
    unpacked_bytes: int
    profile: str
    created: str

    def to_bytes(self) -> bytes:
        return json.dumps(self.__dict__, ensure_ascii=False, sort_keys=True).encode("utf-8")

    @classmethod
    def from_bytes(cls, raw: bytes) -> "Manifest":
        data = json.loads(raw.decode("utf-8"))
        return cls(**data)


def _detect_entry(src: Path, explicit: str | None) -> str:
    """确定入口程序：优先显式指定，其次根目录唯一 exe / bat / py。"""
    if explicit:
        rel = explicit.replace("\\", "/").lstrip("/")
        target = src / rel if src.is_dir() else src
        if not target.is_file():
            raise RuntimePackError(f"入口文件不存在：{explicit}")
        return rel

    if src.is_file():
        return src.name

    roots = [p for p in src.iterdir() if p.is_file()]
    for suffix in (".exe", ".bat", ".cmd", ".py"):
        matches = [p for p in roots if p.suffix.lower() == suffix]
        if len(matches) == 1:
            return matches[0].name
    raise RuntimePackError(
        "无法自动识别入口程序。请用 --entry 指定程序包内的相对路径，"
        "例如 --entry MyApp/start.exe"
    )


def _zip_package(src: Path, entry: str, profile: str,
                 cb: Progress | None = None) -> tuple[bytes, Manifest]:
    """把文件或文件夹流式打成 zip（保存在内存）。"""
    buf = io.BytesIO()
    files: list[Path] = []
    if src.is_file():
        files = [src]
    else:
        files = sorted(p for p in src.rglob("*") if p.is_file())
    if not files:
        raise RuntimePackError(f"目录为空：{src}")

    total_bytes = 0
    for p in files:
        total_bytes += p.stat().st_size
    if total_bytes > MAX_PACKAGE_BYTES:
        raise RuntimePackError(
            f"程序包 {total_bytes:,} 字节超过上限 {MAX_PACKAGE_BYTES:,} 字节。"
            "请拆分或加固较小的程序包。"
        )

    # 归一化入口：相对包根，正斜杠
    entry_rel = entry.replace("\\", "/").lstrip("/")

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for i, p in enumerate(files, 1):
            rel = p.name if src.is_file() else p.relative_to(src).as_posix()
            zf.write(p, rel)
            if i % 20 == 0 or i == len(files):
                _notify(cb, i, len(files), f"打包中 {i}/{len(files)}：{rel[:48]}")

    manifest = Manifest(
        entry=entry_rel,
        files=len(files),
        unpacked_bytes=total_bytes,
        profile=profile,
        created=time.strftime("%Y-%m-%d %H:%M:%S"),
    )
    return buf.getvalue(), manifest


def _derive(password: bytes, salt: bytes, mem: int, time_cost: int,
            para: int) -> bytes:
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=time_cost,
        memory_cost=mem,
        parallelism=para,
        hash_len=32,
        type=Type.ID,
    )


def build_pack(
    src: str | Path,
    password: str | bytes | None,
    *,
    entry: str | None = None,
    profile: str = DEFAULT_PROFILE,
    no_password: bool = False,
    cb: Progress | None = None,
) -> bytes:
    """把 src 加密成 RTPK v1 字节。password 为空且 no_password=True 时走免密模式。"""
    src_path = Path(src)
    if not src_path.exists():
        raise RuntimePackError(f"源不存在：{src_path}")
    if profile not in PROFILES:
        raise RuntimePackError(f"未知强度档：{profile}（可选 {', '.join(PROFILES)}）")
    if no_password:
        secret = _NO_PASSWORD_SECRET
        flags = FLAG_NO_PASSWORD
    else:
        if not password:
            raise RuntimePackError("口令不能为空；确需免密请显式传 no_password=True")
        secret = password.encode("utf-8") if isinstance(password, str) else password
        flags = FLAG_PASSWORD

    mem, time_cost, para = PROFILES[profile]
    entry_rel = _detect_entry(src_path, entry)
    _notify(cb, 0, 1, "正在打包程序包…")
    payload, manifest = _zip_package(src_path, entry_rel, profile, cb)
    man_bytes = manifest.to_bytes()
    _notify(cb, 1, 1, "正在派生密钥…")

    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive(secret, salt, mem, time_cost, para)
    ct = AESGCM(key).encrypt(nonce, payload, man_bytes)
    _notify(cb, 1, 1, "加密完成")

    return b"".join((
        MAGIC,
        bytes((VERSION, flags)),
        struct.pack("<IBB", mem, time_cost, para),
        salt,
        nonce,
        struct.pack("<Q", len(ct) - 16),
        struct.pack("<I", len(man_bytes)),
        man_bytes,
        ct,
    ))


def parse_pack(blob: bytes) -> dict:
    """只解析头部与清单，不解密。供 inspect / GUI 显示用。"""
    if not blob.startswith(MAGIC):
        raise RuntimePackError("MAGIC 不匹配，不是 RTPK v1 包")
    if len(blob) < 8 + 1 + 1 + 4 + 1 + 1 + 16 + 12 + 8 + 4:
        raise RuntimePackError("包长度不足，头部被截断")
    pos = 8
    version, flags = blob[pos], blob[pos + 1]
    pos += 2
    if version != VERSION:
        raise RuntimePackError(f"不支持的版本：{version}")
    mem, time_cost, para = struct.unpack("<IBB", blob[pos:pos + 6])
    pos += 6
    salt = blob[pos:pos + 16]
    pos += 16
    nonce = blob[pos:pos + 12]
    pos += 12
    payload_len = struct.unpack("<Q", blob[pos:pos + 8])[0]
    pos += 8
    man_len = struct.unpack("<I", blob[pos:pos + 4])[0]
    pos += 4
    man_bytes = blob[pos:pos + man_len]
    pos += man_len
    manifest = Manifest.from_bytes(man_bytes)
    return {
        "version": version,
        "flags": flags,
        "password_required": bool(flags & FLAG_PASSWORD),
        "no_password": bool(flags & FLAG_NO_PASSWORD),
        "mem": mem, "time": time_cost, "para": para,
        "salt": salt, "nonce": nonce,
        "payload_len": payload_len,
        "manifest": manifest,
        "ciphertext": blob[pos:pos + payload_len + 16],
    }


def decrypt_pack(blob: bytes, password: str | bytes | None = None,
                 *, cb: Progress | None = None) -> tuple[bytes, Manifest]:
    """解密 RTPK 包，返回 (zip 字节, 清单)。口令错误抛 RuntimePackError。"""
    info = parse_pack(blob)
    if info["password_required"]:
        if not password:
            raise RuntimePackError("该包需要口令")
        secret = password.encode("utf-8") if isinstance(password, str) else password
    elif info["no_password"]:
        secret = _NO_PASSWORD_SECRET
    else:
        raise RuntimePackError("包标志位异常：既非口令模式也非免密模式")

    _notify(cb, 0, 1, "正在派生密钥（可能数秒）…")
    started = time.time()
    key = _derive(secret, info["salt"], info["mem"], info["time"], info["para"])
    _notify(cb, 1, 1, f"密钥派生完成，用时 {time.time() - started:.2f}s；正在解密…")
    try:
        plain = AESGCM(key).decrypt(info["nonce"], info["ciphertext"],
                                    info["manifest"].to_bytes())
    except InvalidTag as exc:
        raise RuntimePackError("口令错误或数据被篡改（认证失败）") from exc
    return plain, info["manifest"]


def safe_extract(zip_bytes: bytes, out_dir: Path) -> list[Path]:
    """解压并拒绝 Zip Slip / 绝对路径 / 符号链接，返回解出的文件列表。"""
    out = out_dir.resolve()
    written: list[Path] = []
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        for info in zf.infolist():
            name = info.filename.replace("\\", "/")
            if name.startswith("/") or ":" in name.split("/")[0]:
                raise RuntimePackError(f"拒绝不安全路径：{info.filename}")
            target = (out / name).resolve()
            if target != out and out not in target.parents:
                raise RuntimePackError(f"拒绝路径穿越：{info.filename}")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as reader, target.open("wb") as writer:
                while chunk := reader.read(1024 * 1024):
                    writer.write(chunk)
            written.append(target)
    return written


def embed(runner: str | Path, pack: bytes, out: str | Path) -> Path:
    """把 RTPK 包追加到 runner.exe 尾部并写 footer，生成单文件 exe。"""
    runner_path = Path(runner)
    if not runner_path.is_file():
        raise RuntimePackError(f"启动器不存在：{runner_path}")
    if not runner_path.suffix.lower() == ".exe":
        raise RuntimePackError(f"启动器必须是 .exe：{runner_path}")
    runner_bytes = runner_path.read_bytes()
    offset = len(runner_bytes)
    footer = FOOTER_MAGIC + struct.pack(
        "<QQQ8s", offset, len(pack), binascii.crc32(pack) & 0xFFFFFFFF, b""
    )
    assert len(footer) == FOOTER_LEN
    out_path = Path(out)
    out_path.write_bytes(runner_bytes + pack + footer)
    return out_path


def read_embedded(exe_path: str | Path) -> bytes:
    """从自包含 exe 尾部读出 RTPK 包。"""
    path = Path(exe_path)
    size = path.stat().st_size
    if size < FOOTER_LEN:
        raise RuntimePackError("文件太小，不含嵌入式程序包")
    with path.open("rb") as f:
        f.seek(size - FOOTER_LEN)
        footer = f.read(FOOTER_LEN)
    if not footer.startswith(FOOTER_MAGIC):
        raise RuntimePackError("未找到 RTPK 尾部标记；这不是加固后的 exe")
    offset, length, crc = struct.unpack("<QQQ", footer[8:32])
    if offset + length > size - FOOTER_LEN:
        raise RuntimePackError("尾部索引越界，文件可能损坏")
    with path.open("rb") as f:
        f.seek(offset)
        pack = f.read(length)
    if (binascii.crc32(pack) & 0xFFFFFFFF) != crc:
        raise RuntimePackError("程序包 CRC 校验失败，文件可能被篡改")
    return pack


def wipe_dir(path: Path) -> None:
    """退出后擦除临时目录：先覆写每个文件一遍，再删除整棵树。

    说明：现代 SSD 的磨损均衡会让覆写不保证物理层不可恢复；
    这里做到的程度是「同机上普通文件恢复工具读不到」。
    """
    path = Path(path)
    if not path.exists():
        return
    for root, dirs, files in os.walk(path, topdown=False):
        for name in files:
            p = Path(root) / name
            try:
                size = p.stat().st_size
                if size:
                    with p.open("r+b", buffering=0) as fh:
                        fh.write(os.urandom(size))
                        fh.flush()
                        os.fsync(fh.fileno())
            except OSError:
                pass
            try:
                p.unlink()
            except OSError:
                pass
        for name in dirs:
            try:
                (Path(root) / name).rmdir()
            except OSError:
                pass
    try:
        path.rmdir()
    except OSError:
        pass


def _cli(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="运行时加固：加密程序包并生成可直接运行的单文件 exe")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_build = sub.add_parser("build", help="加密程序包")
    p_build.add_argument("src", help="源文件或文件夹")
    p_build.add_argument("-o", "--out", required=True, help="输出 .rpk 或单文件 exe")
    p_build.add_argument("--entry", help="入口程序相对路径；默认自动识别根目录唯一 exe/bat/py")
    p_build.add_argument("--password", help="口令；不传则交互式输入")
    p_build.add_argument("--no-password", action="store_true",
                         help="免密模式（密钥内嵌，仅混淆，保护极弱）")
    p_build.add_argument("--profile", choices=list(PROFILES), default=DEFAULT_PROFILE)
    p_build.add_argument("--runner", help="通用启动器 exe；提供则生成单文件 exe")

    p_inspect = sub.add_parser("inspect", help="查看包信息（不解密）")
    p_inspect.add_argument("file", help=".rpk 或加固后的 exe")

    p_run = sub.add_parser("run", help="直接运行 .rpk（调试用）")
    p_run.add_argument("file")
    p_run.add_argument("--password")
    p_run.add_argument("--no-wipe", action="store_true", help="调试：保留临时目录")

    args = ap.parse_args(argv)

    if args.cmd == "build":
        pw = args.password
        if not args.no_password and not pw:
            import getpass
            pw = getpass.getpass("口令：")
        blob = build_pack(args.src, pw, entry=args.entry, profile=args.profile,
                          no_password=args.no_password)
        out = Path(args.out)
        if args.runner:
            out = embed(args.runner, blob, out)
        else:
            out.write_bytes(blob)
        print(f"已生成 {out}（{out.stat().st_size:,} 字节）")
        return 0

    if args.cmd == "inspect":
        path = Path(args.file)
        blob = read_embedded(path) if path.suffix.lower() == ".exe" else path.read_bytes()
        info = parse_pack(blob)
        man = info["manifest"]
        print(f"版本          : {info['version']}")
        print(f"模式          : {'免密（弱保护）' if info['no_password'] else '口令保护'}")
        print(f"强度档        : {man.profile}  (mem={info['mem']}KiB, time={info['time']}, para={info['para']})")
        print(f"入口          : {man.entry}")
        print(f"文件数        : {man.files}")
        print(f"解压后总字节  : {man.unpacked_bytes:,}")
        print(f"密文字节      : {info['payload_len']:,}")
        print(f"创建时间      : {man.created}")
        return 0

    if args.cmd == "run":
        path = Path(args.file)
        blob = read_embedded(path) if path.suffix.lower() == ".exe" else path.read_bytes()
        info = parse_pack(blob)
        pw = args.password
        if info["password_required"] and not pw:
            import getpass
            pw = getpass.getpass("口令：")
        plain, man = decrypt_pack(blob, pw)
        tmp = Path(tempfile.mkdtemp(prefix="rtpk_"))
        safe_extract(plain, tmp)
        entry = tmp / man.entry
        print(f"临时目录：{tmp}")
        print(f"启动：{entry}")
        proc = __import__("subprocess").Popen([str(entry)], cwd=str(entry.parent))
        try:
            return proc.wait()
        finally:
            if args.no_wipe:
                print(f"调试：保留 {tmp}")
            else:
                wipe_dir(tmp)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(_cli())
    except RuntimePackError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        raise SystemExit(2)
