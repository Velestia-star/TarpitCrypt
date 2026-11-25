#!/usr/bin/env python3
"""TarpitCrypt 0.5 —— 「正常运行 + 反 AI 逆向成本陷阱」。

设计目标
--------
1. 正常路径：双击即用，不弹口令，启动 < 1s（低成本 KDF + AES-GCM）。
2. 反分析路径：分发包里同时埋入
   - 若干结构合法、头部宣称高成本 Argon2id 的假包（真实密钥随机，永远解不开）；
   - 可被读码者解开的诱饵源码农场，内含大量逼真假工程与嵌套假包；
   - 多处伪造 RTPK 尾部索引，误导自动扫描器；
   - 启动器侧的反调试 / 反沙箱 / 反 Agent 探测，命中后进入慢速迷宫并投放诱饵。
3. 边界：没有口令意味着具备读码能力的人最终仍能还原。本工具抬高 AI 与自动化
   逆向的时间 / token / 算力成本，不承诺不可破解；不联网、不破坏主机、
   不注入第三方进程。

每包格式（沿用旧 RTPK v1，便于误导旧工具）
------------------------------------------
    MAGIC(8)=b"RTPK0001" | VERSION(1)=1 | FLAGS(1)
    MEM(4) | TIME(1) | PARA(1) | SALT(16) | NONCE(12)
    CT_LEN(8) | MAN_LEN(4) | MANIFEST(json) | CIPHERTEXT | TAG(16)

注意：所有包的 MEM/TIME/PARA 都写成高成本档（默认 384MiB/3 或 1GiB/5），
但真实包实际用低成本 Argon2id 派生；假包用随机密钥。按头部参数硬算的人
会在每个假包上付出完整高成本，且永远打不开。

容器格式
--------
    CORE_MAGIC(8)=b"RTPKTRAP" | VERSION(1) | COUNT(2) | FLAGS(1) | RESERVED(4)
    PACK[0..COUNT-1] | NOISE（伪造 footer / MAGIC）
    FOOTER(40)=b"RTPKEND1" | OFFSET(8) | LEN(8) | CRC32(8) | RESERVED(8)
"""

from __future__ import annotations

import argparse
import binascii
import fnmatch
import hashlib
import io
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# 直接运行本文件时确保同目录的 trap_kit 可被导入
sys.path.insert(0, str(Path(__file__).resolve().parent))

MAGIC = b"RTPK0001"
CORE_MAGIC = b"RTPKTRAP"
FOOTER_MAGIC = b"RTPKEND1"
FOOTER_LEN = 40
PACK_VERSION = 1
CORE_VERSION = 4

# 每次构建随机化的密钥派生参数（多态化）。
POLY_FIELDS = ("index", "ct_len", "manifest_len", "salt", "nonce", "manifest")
_DEFAULT_ORDER = list(POLY_FIELDS)

# 真包分片：分片大小与假包接近，避免"最大包就是真包"。
PART_MAGIC = b"RTPKPART"
PART_VERSION = 1
PART_BYTES: dict[str, int] = {
    "标准": 8 * 1024 * 1024,
    "激进": 4 * 1024 * 1024,
}

# 头部对外宣称的 KDF 成本（真实包不按这个算）
TRAP_PROFILES: dict[str, tuple[int, int, int]] = {
    "标准": (384 * 1024, 3, 2),
    "激进": (1024 * 1024, 5, 4),
}

DEFAULT_DECOYS = 12
DEFAULT_FARM_MB = 8
MAX_DECOYS = 64
MAX_FARM_MB = 64
MAX_PACKAGE_BYTES = 512 * 1024 * 1024

# 默认排除：版本库 / 缓存 / 日志 / 本地环境变量。node_modules、plugins 等运行时依赖保留。
DEFAULT_EXCLUDES = (
    ".git", "__pycache__", "*.pyc", "*.pyo", "*.log", "*.tmp", ".env",
)
# 扫描入口时跳过这些目录，避免被 node_modules / venv 里的 exe 淹没
CANDIDATE_SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", "venv", ".venv", "env",
    "site-packages", ".idea", ".vscode",
}
EXEC_SUFFIXES = (".exe", ".bat", ".cmd", ".py")

# 源码里不再保存任何密钥常量：密钥由本次构建随机生成的所有包头 / 清单派生。
# 想还原必须完整跟踪容器解析与派生逻辑，而不是在源码里搜一个 32 字节常量。
_DOMAIN_CORE = b"\x93RTPK-core-derive-v2\x00"
_DOMAIN_FARM = b"\x93RTPK-farm-derive-v2\x00"

Progress = Callable[[int, int, str], None]


def is_protected_exe(path: str | Path) -> bool:
    """判断文件尾部是否带 RTPK footer（即已经加固过的 exe）。"""
    p = Path(path)
    if p.suffix.lower() != ".exe":
        return False
    try:
        size = p.stat().st_size
        if size < FOOTER_LEN:
            return False
        with p.open("rb") as f:
            f.seek(size - FOOTER_LEN)
            return f.read(8) == FOOTER_MAGIC
    except OSError:
        return False


class RuntimePackError(Exception):
    """运行时加固过程中的可预期错误。"""


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


def _notify(cb: Progress | None, done: int, total: int, text: str) -> None:
    if cb:
        cb(done, total, text)


def _make_poly(rng: random.Random) -> dict:
    order = list(POLY_FIELDS)
    rng.shuffle(order)
    return {
        "v": 1,
        "domain": os.urandom(32).hex(),
        "mask": os.urandom(32).hex(),
        "rounds": rng.randint(1, 5),
        "order": order,
        "xor": os.urandom(rng.randint(8, 16)).hex(),
    }


def _core_key_v4(packs: list[dict], poly: dict) -> bytes:
    key = bytearray(_core_key(packs, poly))
    xor = bytes.fromhex(poly.get("xor", ""))
    for i, value in enumerate(xor):
        key[i % len(key)] ^= value
    return bytes(key)


def _core_key(packs: list[dict], poly: dict | None = None) -> bytes:
    """核心密钥：由本次构建所有包头 + 清单派生；v3 每次构建随机化派生参数。"""
    if poly:
        domain = bytes.fromhex(poly["domain"])
        mask = bytes.fromhex(poly["mask"])
        rounds = int(poly.get("rounds", 0))
        order = list(poly.get("order") or _DEFAULT_ORDER)
    else:
        domain = _DOMAIN_CORE
        mask = b""
        rounds = 0
        order = list(_DEFAULT_ORDER)

    h = hashlib.sha256()
    h.update(domain)
    for index, pack in enumerate(packs):
        man = pack["manifest_raw"]
        values = {
            "index": struct.pack("<H", index & 0xFFFF),
            "ct_len": struct.pack("<I", pack["ct_len"] & 0xFFFFFFFF),
            "manifest_len": struct.pack("<I", len(man)),
            "salt": pack["salt"],
            "nonce": pack["nonce"],
            "manifest": man,
        }
        for name in order:
            h.update(values[name])
    digest = h.digest()
    for _ in range(rounds):
        digest = hashlib.sha256(digest + mask).digest()
    return digest


def _farm_key(salt: bytes, nonce: bytes, manifest_raw: bytes) -> bytes:
    h = hashlib.sha256()
    h.update(_DOMAIN_FARM)
    h.update(salt)
    h.update(nonce)
    h.update(manifest_raw)
    return h.digest()


def _try_key(key: bytes, pack: dict) -> bytes | None:
    try:
        return AESGCM(key).decrypt(
            pack["nonce"], pack["ct_blob"], pack["manifest_raw"])
    except (InvalidTag, ValueError):
        return None


def _make_part_payload(index: int, total: int, meta_raw: bytes,
                       chunk: bytes) -> bytes:
    return b"".join((
        PART_MAGIC,
        bytes((PART_VERSION,)),
        struct.pack("<HHI", index, total, len(meta_raw)),
        meta_raw,
        chunk,
    ))


def _parse_part(plain: bytes) -> dict | None:
    """解析核心分片；不是分片格式时返回 None（兼容旧单包）。"""
    if not plain.startswith(PART_MAGIC):
        return None
    p = len(PART_MAGIC)
    if len(plain) < p + 1 + 4 + 4:
        raise RuntimePackError("核心分片头部被截断")
    version = plain[p]
    p += 1
    if version != PART_VERSION:
        raise RuntimePackError(f"不支持的分片版本：{version}")
    index, total, meta_len = struct.unpack("<HHI", plain[p:p + 8])
    p += 8
    if total == 0 or index >= total or len(plain) < p + meta_len:
        raise RuntimePackError("核心分片元数据异常")
    meta_raw = plain[p:p + meta_len]
    p += meta_len
    return {
        "index": index,
        "total": total,
        "meta_raw": meta_raw,
        "chunk": plain[p:],
    }


# ---------------------------------------------------------------- 打包辅助


def _is_excluded(rel: Path, patterns: tuple[str, ...]) -> bool:
    """目录名 / 文件名 / 通配符 / 相对路径 匹配排除规则。"""
    if not patterns:
        return False
    parts = [p.lower() for p in rel.parts]
    name = rel.name.lower()
    posix = rel.as_posix().lower()
    for raw in patterns:
        pat = raw.strip().replace("\\", "/").lower()
        if not pat:
            continue
        if "/" in pat:
            if posix == pat or posix.startswith(pat.rstrip("/") + "/"):
                return True
        elif any(ch in pat for ch in "*?[]"):
            if fnmatch.fnmatch(name, pat):
                return True
            if any(fnmatch.fnmatch(part, pat) for part in parts):
                return True
        else:
            if name == pat or pat in parts:
                return True
    return False


def _collect_files(src: Path, excludes: tuple[str, ...],
                   out_path: Path | None) -> tuple[list[Path], int]:
    """收集待打包文件；返回 (文件列表, 排除项数量)。"""
    if src.is_file():
        return [src], 0
    files: list[Path] = []
    excluded = 0
    out_res = Path(out_path).resolve() if out_path else None
    for root, dirs, names in os.walk(src):
        keep: list[str] = []
        for d in dirs:
            rel_dir = Path(root, d).relative_to(src)
            if _is_excluded(rel_dir, excludes):
                excluded += 1
                continue
            keep.append(d)
        dirs[:] = keep
        for name in names:
            p = Path(root) / name
            rel = p.relative_to(src)
            if out_res is not None and p.resolve() == out_res:
                excluded += 1
                continue
            if p.suffix.lower() == ".exe" and is_protected_exe(p):
                excluded += 1
                continue
            if _is_excluded(rel, excludes):
                excluded += 1
                continue
            files.append(p)
    files.sort(key=lambda p: p.relative_to(src).as_posix())
    return files, excluded


def candidate_entries(src: str | Path, max_depth: int = 2) -> list[str]:
    """扫描入口候选：根目录 + 两级子目录，跳过 node_modules / venv 等。"""
    path = Path(src)
    if not path.exists():
        return []
    if path.is_file():
        return [path.name]
    root = path.resolve()
    found: list[str] = []
    for dirpath, dirs, names in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root)
        depth = 0 if str(rel_dir) == "." else len(rel_dir.parts)
        if depth >= max_depth:
            dirs[:] = []
        else:
            dirs[:] = [d for d in dirs if d.lower() not in CANDIDATE_SKIP_DIRS]
        for name in names:
            suffix = Path(name).suffix.lower()
            if suffix in EXEC_SUFFIXES:
                full = Path(dirpath) / name
                if suffix == ".exe" and is_protected_exe(full):
                    continue
                found.append(full.relative_to(root).as_posix())
    found.sort(key=lambda s: (s.count("/"), s.lower()))
    return found


def validate_entry(src: str | Path, entry: str) -> str:
    path = Path(src)
    rel = entry.replace("\\", "/").lstrip("/")
    if not rel:
        raise RuntimePackError("未选择入口程序")
    if path.is_file():
        if rel != path.name:
            raise RuntimePackError("单文件程序包不能指定其它入口；请直接传文件夹")
        return path.name
    target = path / rel
    if not target.is_file():
        raise RuntimePackError(f"入口文件不存在：{entry}")
    return rel


def _detect_entry(src: Path, explicit: str | None) -> str:
    """确定入口：显式指定 > 根目录唯一 exe/bat/cmd/py > 两级目录唯一候选。"""
    if explicit:
        return validate_entry(src, explicit)
    if src.is_file():
        return src.name

    roots = [p for p in src.iterdir() if p.is_file()]
    for suffix in EXEC_SUFFIXES:
        matches = [p for p in roots if p.suffix.lower() == suffix
                   and not (suffix == ".exe" and is_protected_exe(p))]
        if len(matches) == 1:
            return matches[0].name

    candidates = candidate_entries(src)
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise RuntimePackError("目录里没有找到 exe / bat / cmd / py 入口")
    preview = "、".join(candidates[:8])
    raise RuntimePackError(
        f"入口不唯一，请在 GUI 下拉框或 --entry 指定。候选：{preview}")


def scan_package(src: str | Path, excludes: list[str] | tuple[str, ...] | None = None,
                 out_path: str | Path | None = None) -> dict:
    """打包前预览：统计将被打包 / 排除的文件数与体积。"""
    path = Path(src)
    if not path.exists():
        raise RuntimePackError(f"源不存在：{path}")
    patterns = tuple(DEFAULT_EXCLUDES if excludes is None else excludes)
    files, excluded = _collect_files(
        path, patterns, Path(out_path) if out_path else None)
    return {
        "files": len(files),
        "bytes": sum(p.stat().st_size for p in files),
        "excluded": excluded,
    }


def _zip_package(src: Path, entry: str, profile: str,
                 cb: Progress | None = None, *,
                 excludes: tuple[str, ...] = (),
                 out_path: Path | None = None
                 ) -> tuple[bytes, Manifest, int]:
    """把真实程序包打成 zip（保存在内存），返回 (zip, 清单, 排除项数量)。"""
    buf = io.BytesIO()
    files, excluded = _collect_files(src, excludes, out_path)
    if not files:
        raise RuntimePackError(f"目录为空或全部被排除：{src}")
    if src.is_dir():
        included = {p.relative_to(src).as_posix() for p in files}
        if entry not in included:
            raise RuntimePackError(
                f"入口 {entry} 被排除规则过滤，请调整排除项或换入口")

    total_bytes = sum(p.stat().st_size for p in files)
    if total_bytes > MAX_PACKAGE_BYTES:
        raise RuntimePackError(
            f"程序包 {total_bytes:,} 字节超过上限 {MAX_PACKAGE_BYTES:,} 字节。"
            "请拆分或加固较小的程序包。"
        )

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
    return buf.getvalue(), manifest, excluded


def _zip_files(files: dict[str, bytes], cb: Progress | None = None) -> bytes:
    buf = io.BytesIO()
    items = sorted(files.items())
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:
        for i, (rel, data) in enumerate(items, 1):
            zf.writestr(rel, data)
            if i % 100 == 0 or i == len(items):
                _notify(cb, i, len(items), f"生成诱饵 {i}/{len(items)}")
    return buf.getvalue()


def _pick_entry(files: dict[str, bytes]) -> str:
    names = sorted(files)
    for keyword in ("start", "app", "main", "run", "index", "Program"):
        for name in names:
            if keyword.lower() in Path(name).name.lower() and name.endswith(
                    (".exe", ".bat", ".cmd", ".py", ".ts", ".go", ".cs")):
                return name
    for name in names:
        if name.endswith((".py", ".ts", ".go", ".cs", ".md")):
            return name
    return names[0]


def _fake_manifest(rng: random.Random, payload_size: int) -> Manifest:
    entries = ("start.bat", "app.exe", "main.py", "run.cmd",
               "server.exe", "launcher.exe", "client.exe")
    return Manifest(
        entry=rng.choice(entries),
        files=rng.randint(4, 320),
        unpacked_bytes=int(payload_size * rng.uniform(1.5, 4.5)),
        profile=rng.choice(("轻", "中", "狠")),
        created=time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.localtime(time.time() - rng.randint(0, 730 * 86400)),
        ),
    )


# ---------------------------------------------------------------- 单包编解码


def make_pack_bytes(payload: bytes, manifest: Manifest, kind: str,
                    header_profile: tuple[int, int, int], *,
                    key: bytes | None = None,
                    salt: bytes | None = None,
                    nonce: bytes | None = None) -> bytes:
    """kind: core / farm / decoy。头部成本对所有包都写成同一高成本档。"""
    salt = salt if salt is not None else os.urandom(16)
    nonce = nonce if nonce is not None else os.urandom(12)
    man = manifest.to_bytes()
    if kind == "farm":
        key = _farm_key(salt, nonce, man)
    elif kind == "decoy":
        key = os.urandom(32)
    elif kind == "core":
        if key is None:
            raise RuntimePackError("核心包缺少派生密钥")
    else:
        raise RuntimePackError(f"未知包类型：{kind}")

    ct = AESGCM(key).encrypt(nonce, payload, man)
    mem, time_cost, para = header_profile
    return b"".join((
        MAGIC,
        bytes((PACK_VERSION, 0)),
        struct.pack("<IBB", mem, time_cost, para),
        salt,
        nonce,
        struct.pack("<Q", len(ct) - 16),
        struct.pack("<I", len(man)),
        man,
        ct,
    ))


def parse_pack_at(blob: bytes, pos: int) -> dict:
    if blob[pos:pos + 8] != MAGIC:
        raise RuntimePackError("包 MAGIC 不匹配")
    if len(blob) < pos + 56:
        raise RuntimePackError("包头部被截断")
    p = pos + 8
    version, flags = blob[p], blob[p + 1]
    p += 2
    if version != PACK_VERSION:
        raise RuntimePackError(f"不支持的包版本：{version}")
    mem, time_cost, para = struct.unpack("<IBB", blob[p:p + 6])
    p += 6
    salt = blob[p:p + 16]
    p += 16
    nonce = blob[p:p + 12]
    p += 12
    ct_len = struct.unpack("<Q", blob[p:p + 8])[0]
    p += 8
    man_len = struct.unpack("<I", blob[p:p + 4])[0]
    p += 4
    if man_len > 1024 * 1024:
        raise RuntimePackError("清单长度异常，包已损坏")
    if len(blob) < p + man_len + ct_len + 16:
        raise RuntimePackError("包体长度不足，文件被截断")
    man_raw = blob[p:p + man_len]
    p += man_len
    ct_blob = blob[p:p + ct_len + 16]
    p += ct_len + 16
    try:
        manifest = Manifest.from_bytes(man_raw)
    except Exception as exc:
        raise RuntimePackError("清单解析失败，包已损坏") from exc
    return {
        "offset": pos,
        "end": p,
        "flags": flags,
        "mem": mem,
        "time": time_cost,
        "para": para,
        "salt": salt,
        "nonce": nonce,
        "manifest": manifest,
        "manifest_raw": man_raw,
        "ct_blob": ct_blob,
        "ct_len": ct_len,
    }


# ---------------------------------------------------------------- 容器编解码


def _make_noise(rng: random.Random, packs: list[bytes], start: int = 16) -> bytes:
    """真实数据之后塞入伪造 footer / 假 MAGIC，误导自动扫描器。"""
    starts: list[int] = []
    cur = start
    for pack in packs:
        starts.append(cur)
        cur += len(pack)
    out = bytearray()
    for _ in range(3):
        offset = rng.choice(starts) + rng.randint(0, max(0, len(packs[0]) - 64))
        length = rng.randint(64, 8192)
        out += FOOTER_MAGIC + struct.pack(
            "<QQQ8s", offset, length, rng.getrandbits(32), b"")
        out += os.urandom(rng.randint(128, 1024))
        out += MAGIC + os.urandom(rng.randint(32, 256))
    return bytes(out)


def parse_container(blob: bytes) -> dict:
    if len(blob) < 16 or blob[:8] != CORE_MAGIC:
        raise RuntimePackError("不是 TarpitCrypt 加固容器")
    version = blob[8]
    if version not in (1, 2, 3, CORE_VERSION):
        raise RuntimePackError(f"不支持的容器版本：{version}")
    count = struct.unpack("<H", blob[9:11])[0]
    flags = blob[11]
    if not 1 <= count <= 256:
        raise RuntimePackError(f"包数量异常：{count}")
    pos = 16
    poly = None
    if version == 3:
        if len(blob) < pos + 2:
            raise RuntimePackError("多态参数被截断")
        poly_len = struct.unpack("<H", blob[pos:pos + 2])[0]
        pos += 2
        if len(blob) < pos + poly_len:
            raise RuntimePackError("多态参数被截断")
        try:
            poly = json.loads(blob[pos:pos + poly_len].decode("utf-8"))
        except Exception as exc:
            raise RuntimePackError("多态参数解析失败") from exc
        pos += poly_len
        if sorted(poly.get("order", [])) != sorted(POLY_FIELDS):
            raise RuntimePackError("多态参数字段顺序非法")
    packs: list[dict] = []
    for _ in range(count):
        info = parse_pack_at(blob, pos)
        packs.append(info)
        pos = info["end"]
    return {
        "version": version,
        "count": count,
        "flags": flags,
        "guard": bool(flags & 0x01),
        "poly": poly,
        "packs": packs,
        "trailer": blob[pos:],
    }


def read_embedded(exe_path: str | Path) -> bytes:
    """从自包含 exe 尾部读出容器。"""
    path = Path(exe_path)
    size = path.stat().st_size
    if size < FOOTER_LEN:
        raise RuntimePackError("文件太小，不含嵌入式容器")
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
        blob = f.read(length)
    if (binascii.crc32(blob) & 0xFFFFFFFF) != crc:
        raise RuntimePackError("容器 CRC 校验失败，文件可能被篡改")
    return blob


def embed(runner: str | Path, blob: bytes, out: str | Path) -> Path:
    """把容器追加到 runner.exe 尾部并写 footer，生成单文件 exe。"""
    runner_path = Path(runner)
    if not runner_path.is_file():
        raise RuntimePackError(f"启动器不存在：{runner_path}")
    if runner_path.suffix.lower() != ".exe":
        raise RuntimePackError(f"启动器必须是 .exe：{runner_path}")
    runner_bytes = runner_path.read_bytes()
    offset = len(runner_bytes)
    footer = FOOTER_MAGIC + struct.pack(
        "<QQQ8s", offset, len(blob), binascii.crc32(blob) & 0xFFFFFFFF, b"")
    assert len(footer) == FOOTER_LEN
    out_path = Path(out)
    out_path.write_bytes(runner_bytes + blob + footer)
    return out_path


# ---------------------------------------------------------------- 构建


def build_container(
    src: str | Path,
    *,
    entry: str | None = None,
    decoys: int = DEFAULT_DECOYS,
    farm_mb: int = DEFAULT_FARM_MB,
    trap_profile: str = "标准",
    guard: bool = True,
    excludes: list[str] | tuple[str, ...] | None = None,
    out_path: str | Path | None = None,
    cb: Progress | None = None,
    poly: dict | None = None,
    native: bool = False,
) -> tuple[bytes, dict]:
    """构建陷阱容器（不含启动器），返回 (容器字节, 统计)。

    excludes 为 None 时使用 DEFAULT_EXCLUDES；传空列表表示不排除任何文件。
    """
    if trap_profile not in TRAP_PROFILES:
        raise RuntimePackError(
            f"未知陷阱强度：{trap_profile}（可选 {', '.join(TRAP_PROFILES)}）")
    decoys = max(0, min(MAX_DECOYS, int(decoys)))
    farm_mb = max(0, min(MAX_FARM_MB, int(farm_mb)))
    patterns = tuple(DEFAULT_EXCLUDES if excludes is None else excludes)
    src_path = Path(src)
    if not src_path.exists():
        raise RuntimePackError(f"源不存在：{src_path}")

    header_profile = TRAP_PROFILES[trap_profile]
    entry_rel = _detect_entry(src_path, entry)
    _notify(cb, 0, 1, "正在打包真实程序…")
    real_zip, manifest, excluded_count = _zip_package(
        src_path, entry_rel, trap_profile, cb,
        excludes=patterns,
        out_path=Path(out_path) if out_path else None,
    )

    rng = random.Random(int.from_bytes(os.urandom(8), "big"))
    if native:
        if poly is None:
            raise RuntimePackError("原生多态包缺少构建参数")
    else:
        poly = _make_poly(rng)
    part_bytes = PART_BYTES[trap_profile]
    core_parts = max(1, (len(real_zip) + part_bytes - 1) // part_bytes)
    chunk_size = max(1, (len(real_zip) + core_parts - 1) // core_parts)
    chunks = [real_zip[i:i + chunk_size]
              for i in range(0, len(real_zip), chunk_size)]
    core_parts = len(chunks)
    meta_raw = manifest.to_bytes()
    part_payloads = [
        _make_part_payload(i, core_parts, meta_raw, chunk)
        for i, chunk in enumerate(chunks)
    ]

    decoy_count = decoys
    if core_parts > 2:
        decoy_count = min(decoys, max(4, core_parts))
    _notify(cb, 0, 1, f"正在生成 {decoy_count} 个假包…")
    base = (part_bytes if core_parts > 1
            else max(1024, min(part_bytes, len(real_zip))))
    items: list[dict] = []
    for _ in range(decoy_count):
        size = max(512, rng.randint(int(base * 0.7), int(base * 1.3)))
        items.append({
            "kind": "decoy",
            "payload": os.urandom(size),
            "manifest": _fake_manifest(rng, size),
            "salt": os.urandom(16),
            "nonce": os.urandom(12),
        })

    farm_packs = 0
    if farm_mb > 0:
        import trap_kit  # 仅构建端需要

        parts = 2 if farm_mb >= 4 else 1
        each = max(1, farm_mb // parts)
        for pi in range(parts):
            _notify(cb, pi, parts, f"正在生成诱饵源码农场 {pi + 1}/{parts}…")
            files = trap_kit.generate(each, seed=rng.getrandbits(32))
            for nested_name in ("license_cache", "runtime_core"):
                nested = trap_kit.generate(1, seed=rng.getrandbits(32))
                nested_zip = _zip_files(nested)
                nested_manifest = Manifest(
                    entry=_pick_entry(nested),
                    files=len(nested),
                    unpacked_bytes=sum(len(v) for v in nested.values()),
                    profile=trap_profile,
                    created=time.strftime("%Y-%m-%d %H:%M:%S"),
                )
                files[f"internal/{nested_name}.rpk"] = make_pack_bytes(
                    nested_zip, nested_manifest, "farm", header_profile)
            farm_zip = _zip_files(files)
            items.append({
                "kind": "farm",
                "payload": farm_zip,
                "manifest": _fake_manifest(rng, len(farm_zip)),
                "salt": os.urandom(16),
                "nonce": os.urandom(12),
            })
            farm_packs += 1

    for payload in part_payloads:
        items.append({
            "kind": "core",
            "payload": payload,
            "manifest": _fake_manifest(rng, len(payload)),
            "salt": os.urandom(16),
            "nonce": os.urandom(12),
        })

    # 核心密钥由「最终顺序下所有包」的头部与清单派生；所有明文清单都是伪清单。
    rng.shuffle(items)
    metas: list[dict] = []
    for item in items:
        man_raw = item["manifest"].to_bytes()
        item["manifest_raw"] = man_raw
        metas.append({
            "salt": item["salt"],
            "nonce": item["nonce"],
            "manifest_raw": man_raw,
            "ct_len": len(item["payload"]),
        })
    core_key = (_core_key_v4(metas, poly) if native
                else _core_key(metas, poly))

    packs: list[bytes] = []
    for item in items:
        kind = item["kind"]
        if kind == "core":
            pack = make_pack_bytes(
                item["payload"], item["manifest"], "core", header_profile,
                key=core_key, salt=item["salt"], nonce=item["nonce"])
        elif kind == "farm":
            pack = make_pack_bytes(
                item["payload"], item["manifest"], "farm", header_profile,
                salt=item["salt"], nonce=item["nonce"])
        else:
            pack = make_pack_bytes(
                item["payload"], item["manifest"], "decoy", header_profile,
                salt=item["salt"], nonce=item["nonce"])
        packs.append(pack)

    flags = 0x01 if guard else 0x00
    if native:
        header = b"".join((
            CORE_MAGIC,
            bytes((CORE_VERSION,)),
            struct.pack("<HB4x", len(packs), flags),
        ))
    else:
        poly_raw = json.dumps(poly, ensure_ascii=False,
                             separators=(",", ":")).encode("utf-8")
        header = b"".join((
            CORE_MAGIC,
            bytes((3,)),
            struct.pack("<HB4x", len(packs), flags),
            struct.pack("<H", len(poly_raw)),
            poly_raw,
        ))
    blob = header + b"".join(packs) + _make_noise(rng, packs, len(header))
    mem, time_cost, _ = header_profile
    per_pack = (mem / 1048576.0) * time_cost * 1.2
    stats = {
        "packs": len(packs),
        "decoys": decoy_count,
        "core_parts": core_parts,
        "part_bytes": part_bytes,
        "farm_packs": farm_packs,
        "farm_mb": farm_mb,
        "core_bytes": len(real_zip),
        "container_bytes": len(blob),
        "included_files": manifest.files,
        "included_bytes": manifest.unpacked_bytes,
        "excluded_items": excluded_count,
        "header_mem_kib": mem,
        "header_time": time_cost,
        "attack_seconds_per_pack": per_pack,
        "attack_seconds_full_pass": per_pack * len(packs),
        "guard": bool(guard),
        "trap_profile": trap_profile,
        "entry": entry_rel,
    }
    _notify(cb, 1, 1, "陷阱容器构建完成")
    return blob, stats


def _find_go() -> str | None:
    candidates = [
        os.environ.get("TARPITCRYPT_GO", ""),
        shutil.which("go") or "",
        r"D:\app\go1.27.4\go\bin\go.exe",
        r"C:\Program Files\Go\bin\go.exe",
        r"D:\Go\bin\go.exe",
    ]
    for candidate in candidates:
        if candidate and Path(candidate).is_file():
            return candidate
    return None


def _go_byte_slice(hex_text: str) -> str:
    return "[]byte{" + ", ".join(
        f"0x{b:02x}" for b in bytes.fromhex(hex_text)) + "}"


def _write_poly_go(poly: dict) -> Path:
    native_dir = Path(__file__).resolve().parent / "native"
    native_dir.mkdir(exist_ok=True)
    writes = {
        "index": "h.Write([]byte{byte(idx), byte(idx >> 8)})",
        "ct_len": "h.Write(u32(uint32(p.CtLen)))",
        "manifest_len": "h.Write(u32(uint32(len(p.ManifestRaw))))",
        "salt": "h.Write(p.Salt)",
        "nonce": "h.Write(p.Nonce)",
        "manifest": "h.Write(p.ManifestRaw)",
    }
    body = "\n\t\t".join(writes[name] for name in poly["order"])
    rounds = "\n\t".join("mix()" for _ in range(int(poly["rounds"])))
    xor = "\n\t".join(
        f"sum[{i % 32}] ^= 0x{value:02x}"
        for i, value in enumerate(bytes.fromhex(poly["xor"])))
    source = f'''package main

import "crypto/sha256"

// 由构建器生成：随机派生顺序 / 轮数 / 二进制常量，只存在于机器码里。
func init() {{
	keyFn = func(packs []Pack) []byte {{
		h := sha256.New()
		h.Write({_go_byte_slice(poly["domain"])})
		for idx, p := range packs {{
			_ = idx
			{body}
		}}
		sum := h.Sum(nil)
		mask := {_go_byte_slice(poly["mask"])}
		mix := func() {{
			s := sha256.Sum256(append(append([]byte(nil), sum...), mask...))
			sum = s[:]
		}}
		{rounds}
		{xor}
		return sum
	}}
}}
'''
    path = native_dir / "poly_gen.go"
    path.write_text(source, encoding="utf-8")
    return path


def _compile_native_runner(poly: dict, out_dir: Path) -> Path:
    go = _find_go()
    if not go:
        raise RuntimePackError("未找到 Go 工具链；安装 Go 1.22+ 或使用 PyInstaller 模式")
    native_dir = Path(__file__).resolve().parent / "native"
    poly_path = native_dir / "poly_gen.go"
    original = poly_path.read_text(encoding="utf-8") if poly_path.exists() else None
    _write_poly_go(poly)
    out_dir.mkdir(parents=True, exist_ok=True)
    runner = out_dir / "RTPK_Native_Runner.exe"
    cmd = [
        go, "build", "-trimpath",
        "-ldflags", "-s -w -H=windowsgui",
        "-o", str(runner), ".",
    ]
    try:
        env = os.environ.copy()
        env["PATH"] = str(Path(go).parent) + os.pathsep + env.get("PATH", "")
        env.setdefault("GOROOT", str(Path(go).parent.parent))
        proc = subprocess.run(cmd, cwd=str(native_dir), capture_output=True, env=env)
    finally:
        if original is not None:
            poly_path.write_text(original, encoding="utf-8")
        else:
            poly_path.unlink(missing_ok=True)
    if proc.returncode:
        raise RuntimePackError(
            "原生启动器编译失败：" + proc.stderr.decode("utf-8", "replace")[-800:])
    return runner


def build_native_exe(
    src: str | Path,
    out: str | Path,
    *,
    entry: str | None = None,
    decoys: int = DEFAULT_DECOYS,
    farm_mb: int = DEFAULT_FARM_MB,
    trap_profile: str = "标准",
    guard: bool = True,
    excludes: list[str] | tuple[str, ...] | None = None,
    cb: Progress | None = None,
) -> dict:
    """每次构建生成独立的原生启动器（v4，派生参数编译进机器码）。"""
    rng = random.Random(int.from_bytes(os.urandom(8), "big"))
    poly = _make_poly(rng)
    target = Path(out)
    target.parent.mkdir(parents=True, exist_ok=True)
    build_dir = Path(tempfile.mkdtemp(prefix="rtpk_native_build_"))
    try:
        _notify(cb, 0, 1, "正在编译原生多态启动器…")
        runner = _compile_native_runner(poly, build_dir)
        blob, stats = build_container(
            src, entry=entry, decoys=decoys, farm_mb=farm_mb,
            trap_profile=trap_profile, guard=guard,
            excludes=excludes, out_path=target, cb=cb,
            poly=poly, native=True)
        target = embed(runner, blob, target)
        stats["exe_bytes"] = target.stat().st_size
        stats["native"] = True
        stats["poly_rounds"] = int(poly["rounds"])
        return stats
    finally:
        shutil.rmtree(build_dir, ignore_errors=True)


def build_trap_exe(
    src: str | Path,
    out: str | Path,
    *,
    runner: str | Path,
    entry: str | None = None,
    decoys: int = DEFAULT_DECOYS,
    farm_mb: int = DEFAULT_FARM_MB,
    trap_profile: str = "标准",
    guard: bool = True,
    excludes: list[str] | tuple[str, ...] | None = None,
    cb: Progress | None = None,
) -> dict:
    blob, stats = build_container(
        src, entry=entry, decoys=decoys, farm_mb=farm_mb,
        trap_profile=trap_profile, guard=guard,
        excludes=excludes, out_path=out, cb=cb)
    target = embed(runner, blob, out)
    stats["exe_bytes"] = target.stat().st_size
    return stats


# ---------------------------------------------------------------- 运行侧


def open_core(blob: bytes, poly: dict | None = None) -> tuple[bytes, Manifest, dict]:
    """扫描所有包，解密核心分片并拼回真实 zip；v4 需要构建参数。"""
    info = parse_container(blob)
    if info["version"] == 4:
        if poly is None:
            raise RuntimePackError("这是原生多态包，需要由配套启动器解密")
        key = _core_key_v4(info["packs"], poly)
    else:
        key = _core_key(info["packs"], info.get("poly"))
    parts: list[dict] = []
    legacy: tuple[bytes, Manifest, dict] | None = None
    for pack in info["packs"]:
        plain = _try_key(key, pack)
        if plain is None:
            continue
        parsed = _parse_part(plain)
        if parsed is None:
            legacy = (plain, pack["manifest"], pack)
            break
        parsed["pack"] = pack
        parts.append(parsed)

    if parts:
        total = parts[0]["total"]
        if (len(parts) != total
                or any(p["total"] != total for p in parts)
                or {p["index"] for p in parts} != set(range(total))):
            raise RuntimePackError("核心分片不完整或重复，分发包可能被篡改")
        meta_raw = parts[0]["meta_raw"]
        if any(p["meta_raw"] != meta_raw for p in parts):
            raise RuntimePackError("核心分片元数据不一致")
        ordered = sorted(parts, key=lambda p: p["index"])
        zip_bytes = b"".join(p["chunk"] for p in ordered)
        return zip_bytes, Manifest.from_bytes(meta_raw), ordered[0]["pack"]

    if legacy is not None:
        return legacy
    raise RuntimePackError("核心数据校验失败：分发包可能损坏或被篡改")


def open_farms(blob: bytes) -> list[tuple[bytes, Manifest]]:
    """解出所有诱饵农场（供慢速迷宫 / 中风险降级投放）。"""
    info = parse_container(blob)
    found: list[tuple[bytes, Manifest]] = []
    for pack in info["packs"]:
        key = _farm_key(pack["salt"], pack["nonce"], pack["manifest_raw"])
        plain = _try_key(key, pack)
        if plain is not None:
            found.append((plain, pack["manifest"]))
    return found


def _core_part_count(info: dict, poly: dict | None = None) -> int:
    if info["version"] == 4:
        if poly is None:
            return 0
        key = _core_key_v4(info["packs"], poly)
    else:
        key = _core_key(info["packs"], info.get("poly"))
    count = 0
    for pack in info["packs"]:
        plain = _try_key(key, pack)
        if plain is None:
            continue
        if _parse_part(plain) is None:
            return 1
        count += 1
    return count


def inspect_blob(blob: bytes, poly: dict | None = None) -> dict:
    info = parse_container(blob)
    plain, manifest, core = open_core(blob, poly)
    farms = open_farms(blob)
    core_parts = _core_part_count(info, poly)
    real_index = next(
        (i for i, p in enumerate(info["packs"])
         if p["offset"] == core["offset"]), -1)
    fake_footers = blob.count(FOOTER_MAGIC)
    farm_files = 0
    for zip_bytes, _manifest in farms:
        try:
            farm_files += len(zipfile.ZipFile(io.BytesIO(zip_bytes)).namelist())
        except Exception:
            pass
    return {
        "count": info["count"],
        "guard": info["guard"],
        "real_index": real_index,
        "core_entry": manifest.entry,
        "core_files": manifest.files,
        "core_bytes": len(plain),
        "core_parts": core_parts,
        "decoys": info["count"] - core_parts - len(farms),
        "farm_packs": len(farms),
        "farm_files": farm_files,
        "header_mem_kib": core["mem"],
        "header_time": core["time"],
        "header_para": core["para"],
        "fake_footers": fake_footers,
        "container_bytes": len(blob),
    }


def safe_extract(zip_bytes: bytes, out_dir: Path) -> list[Path]:
    """解压并拒绝 Zip Slip / 绝对路径，返回解出的文件列表。

    先逐项校验，再交给 extractall：文件数上千时比逐文件读写快一倍左右。
    """
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
        zf.extractall(out)
        for info in zf.infolist():
            if not info.is_dir():
                written.append((out / info.filename.replace("\\", "/")).resolve())
    return written


def wipe_dir(path: Path, budget: float = 3.0) -> None:
    """退出后擦除临时目录：优先覆写大文件，随后用系统命令快速删除。

    上千个小文件逐个覆写 / 删除会被杀软逐文件扫描拖到几十秒。这里给覆写设
    3 秒预算（按体积从大到小），然后用 `rd /s /q` 一次性删除；删除失败时
    回退到逐个 unlink。安全边界：这不是抗物理取证方案，SSD 磨损均衡也不
    保证不可恢复；目标是让同机普通恢复工具读不到主要明文。
    """
    path = Path(path)
    if not path.exists():
        return
    chunk = os.urandom(1024 * 1024)
    files: list[Path] = []
    for root, _dirs, names in os.walk(path):
        for name in names:
            files.append(Path(root) / name)
    try:
        files.sort(key=lambda p: p.stat().st_size, reverse=True)
    except OSError:
        pass

    deadline = time.monotonic() + max(0.0, budget)
    for p in files:
        if time.monotonic() >= deadline:
            break
        try:
            size = p.stat().st_size
            if size:
                with p.open("r+b", buffering=0) as fh:
                    remaining = size
                    while remaining > 0:
                        take = min(remaining, len(chunk))
                        fh.write(chunk[:take])
                        remaining -= take
        except OSError:
            pass

    removed = False
    if os.name == "nt":
        try:
            subprocess.run(
                ["cmd", "/c", "rd", "/s", "/q", str(path)],
                capture_output=True,
                creationflags=0x08000000,  # CREATE_NO_WINDOW
            )
            removed = not path.exists()
        except OSError:
            removed = False
    if not removed:
        for p in files:
            try:
                p.unlink()
            except OSError:
                pass
        for root, dirs, _names in os.walk(path, topdown=False):
            for name in dirs:
                try:
                    (Path(root) / name).rmdir()
                except OSError:
                    pass
    try:
        path.rmdir()
    except OSError:
        pass


# ---------------------------------------------------------------- CLI


def _print_stats(stats: dict, out: Path) -> None:
    size = stats.get("exe_bytes", stats["container_bytes"])
    print(f"已生成 {out}（{size:,} 字节）")
    print(f"  包总数        : {stats['packs']}（真包分片 {stats.get('core_parts', 1)} / "
          f"假包 {stats['decoys']} / 农场包 {stats['farm_packs']}）")
    print(f"  入口          : {stats['entry']}")
    print(f"  打包文件      : {stats.get('included_files', '?')} 个 / "
          f"{stats.get('included_bytes', 0):,} 字节；排除 {stats.get('excluded_items', 0)} 项")
    print(f"  假包宣称 KDF  : {stats['header_mem_kib']} KiB × {stats['header_time']}")
    print(f"  攻击者单包    : ≈ {stats['attack_seconds_per_pack']:.1f} 秒")
    print(f"  全量尝试估算  : ≈ {stats['attack_seconds_full_pass']:.0f} 秒（不含读诱饵源码的 token 成本）")


def _cli(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="TarpitCrypt：正常双击即用，反 AI 逆向成本陷阱")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_build = sub.add_parser("build", help="生成加固 exe")
    p_build.add_argument("src", help="源文件或文件夹")
    p_build.add_argument("-o", "--out", required=True, help="输出 exe / .rtpk")
    p_build.add_argument("--runner", help="通用启动器 exe；提供则生成单文件 exe")
    p_build.add_argument("--native", action="store_true",
                         help="生成原生多态启动器（每次构建独立编译，推荐）")
    p_build.add_argument("--entry", help="入口程序相对路径；默认自动识别")
    p_build.add_argument("--decoys", type=int, default=DEFAULT_DECOYS,
                         help=f"假包数量 0-{MAX_DECOYS}（默认 {DEFAULT_DECOYS}）")
    p_build.add_argument("--farm-mb", type=int, default=DEFAULT_FARM_MB,
                         help=f"诱饵源码体积 0-{MAX_FARM_MB} MB（默认 {DEFAULT_FARM_MB}）")
    p_build.add_argument("--trap-profile", choices=list(TRAP_PROFILES),
                         default="标准", help="假包宣称的 KDF 成本档")
    p_build.add_argument("--no-guard", action="store_true",
                         help="关闭启动器侧反调试 / 反沙箱探测")
    p_build.add_argument("--exclude", action="append", default=None,
                         help="追加排除规则（目录名 / 文件名 / 通配符），可重复")
    p_build.add_argument("--no-default-excludes", action="store_true",
                         help="不使用默认排除规则（.git / 缓存 / 日志 / .env）")

    p_inspect = sub.add_parser("inspect", help="查看真实包信息（会付出一次核心解密）")
    p_inspect.add_argument("file", help=".rtpk 或加固后的 exe")

    p_run = sub.add_parser("run", help="直接运行加固包（调试用）")
    p_run.add_argument("file")
    p_run.add_argument("--keep-temp", action="store_true", help="调试：保留临时目录")

    args = ap.parse_args(argv)

    if args.cmd == "build":
        out = Path(args.out)
        excludes = list(args.exclude or [])
        if not args.no_default_excludes:
            excludes = list(DEFAULT_EXCLUDES) + excludes
        stats = build_native_exe(
            args.src, out, entry=args.entry,
            decoys=args.decoys, farm_mb=args.farm_mb,
            trap_profile=args.trap_profile, guard=not args.no_guard,
            excludes=excludes,
        ) if args.native else (
            build_trap_exe(
                args.src, out,
                runner=args.runner, entry=args.entry,
                decoys=args.decoys, farm_mb=args.farm_mb,
                trap_profile=args.trap_profile, guard=not args.no_guard,
                excludes=excludes,
            ) if args.runner else None
        )
        if stats is None:
            blob, stats = build_container(
                args.src, entry=args.entry, decoys=args.decoys,
                farm_mb=args.farm_mb, trap_profile=args.trap_profile,
                guard=not args.no_guard, excludes=excludes)
            out.write_bytes(blob)
        _print_stats(stats, out)
        return 0

    if args.cmd == "inspect":
        path = Path(args.file)
        blob = read_embedded(path) if path.suffix.lower() == ".exe" else path.read_bytes()
        data = inspect_blob(blob)
        print(f"包总数        : {data['count']}")
        print(f"核心分片      : {data.get('core_parts', 1)}")
        print(f"首个真包序号  : {data['real_index']}")
        print(f"假包 / 农场包 : {data['decoys']} / {data['farm_packs']}")
        print(f"农场文件数    : {data['farm_files']}")
        print(f"核心入口      : {data['core_entry']}")
        print(f"核心文件数    : {data['core_files']}")
        print(f"宣称 KDF      : mem={data['header_mem_kib']}KiB, time={data['header_time']}, para={data['header_para']}")
        print(f"伪造 footer   : {data['fake_footers']} 处")
        print(f"容器字节      : {data['container_bytes']:,}")
        print(f"陷阱开关      : {'开' if data['guard'] else '关'}")
        return 0

    if args.cmd == "run":
        path = Path(args.file)
        blob = read_embedded(path) if path.suffix.lower() == ".exe" else path.read_bytes()
        plain, manifest, _ = open_core(blob)
        tmp = Path(tempfile.mkdtemp(prefix="rtpk_"))
        safe_extract(plain, tmp)
        entry = tmp / manifest.entry
        print(f"临时目录：{tmp}")
        print(f"启动：{entry}")
        proc = __import__("subprocess").Popen([str(entry)], cwd=str(entry.parent))
        try:
            return proc.wait()
        finally:
            if args.keep_temp:
                print(f"调试：保留 {tmp}")
            else:
                wipe_dir(tmp)
    return 0


def cli_main() -> int:
    try:
        return _cli()
    except RuntimePackError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(cli_main())
