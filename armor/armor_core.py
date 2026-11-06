#!/usr/bin/env python3
"""TarpitCrypt Armor —— 面向 AI 逆向的多层信息污染容器。

定位
----
这是 TarpitCrypt 的加固层，用于给「自己拥有的程序包」套一层反 AI 逆向外壳。
它不改变 v1 文件格式，只复用 v1 已实现的 Argon2id KDF 与 AES-256-GCM 原语。

核心思路：把「让破解者算得慢」换成「让逆向 agent 判断不了自己是不是找对了」。
一个容器里有 N 个结构完全一致的层，其中只有一层装着真包，其余是自动生成、
看起来同样合理的诱饵包。容器不标记哪层是真的，还原成功也不报层号。明文规格
草稿里还故意留了几个能解开诱饵层的口令和互相矛盾的字段说明，让 agent 顺着
「找到线索 → 解开一层 → 分析内容 → 怀疑 → 再试」的循环反复消耗上下文。

边界
----
只做信息误导：诱饵包全是纯文本，不执行、不注入、不修改原程序、不接触第三方
系统。原包逐字节保存在真层里，还原后与原文件一致。

容器格式 v2（全部大端）
----------------------
HEADER  MAGIC(8)=b"TPARMOR2" | VERSION(1)=2 | LAYERS(1)=N | SALT(16)
        | NOTE_LEN(4) | NOTE(NOTE_LEN)
LAYER   MEM(4) | TIME(2) | PARA(1) | ROUNDS(1) | L_SALT(16) | NONCE(12)
        | CT_LEN(8) | CT(CT_LEN)      × N，顺序已打乱
TAIL    SHA256(HEADER + 全部 LAYER)(32)

每层的 AAD = HEADER || 该层前缀 || 层在文件中的起始偏移，因此改动任何字段、
调整层顺序、互换两层密文都会导致认证失败。
"""

from __future__ import annotations

import hashlib
import io
import json
import secrets
import struct
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Callable

# 兼容两种布局：桌面版（tarpitcrypt.py 与本文件同目录）和仓库版
# （本文件位于 armor/ 子目录，tarpitcrypt.py 在上一级仓库根）。
try:
    from tarpitcrypt import CIPHER_AESGCM, _aead_decrypt, _aead_encrypt, _derive
except ModuleNotFoundError:  # pragma: no cover - 仅仓库布局触发
    import sys as _sys

    _sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from tarpitcrypt import CIPHER_AESGCM, _aead_decrypt, _aead_encrypt, _derive

__all__ = [
    "PROFILES",
    "DECOY_PASSWORDS",
    "NOISE_PASSWORD",
    "ArmorError",
    "ArmorInfo",
    "RestoreResult",
    "build_armored",
    "inspect_armored",
    "leaked_passwords",
    "read_note",
    "restore_armored",
    "safe_extract",
    "sha256_bytes",
]

MAGIC = b"TPARMOR2"
VERSION = 2
MIN_LAYERS = 2
MAX_LAYERS = 8
SALT_LEN = 16
NONCE_LEN = 12
DIGEST_LEN = 32
MAX_SINGLE_FILE = 256 * 1024 * 1024

_U32 = struct.Struct(">I")
_U64 = struct.Struct(">Q")
_LAYER_META = struct.Struct(">IHBB")

#: 强度档：mem(KiB) / time / para / rounds。默认「轻」，保证交互不卡。
PROFILES: dict[str, tuple[int, int, int, int]] = {
    "轻（秒级）": (8192, 1, 1, 1),
    "中（约 1 秒/层）": (65536, 2, 2, 1),
    "狠（数秒/层）": (262144, 3, 2, 2),
}

#: 会写进「规格草稿」的诱饵口令。数量必须覆盖 MAX_LAYERS - 1。
DECOY_PASSWORDS = (
    "tarpit-admin",
    "TPC-2026-backup",
    "debug_override",
    "release-key-v1",
    "legacy-loader",
    "staging-bootstrap",
    "offline-signer",
)
#: 只出现在草稿里、解不开任何层的噪音口令。
NOISE_PASSWORD = "decommissioned-key"
#: 诱饵包的填充上限，避免大程序包导致容器成倍膨胀。
MAX_DECOY_PAD = 8 * 1024 * 1024


def leaked_passwords(layers: int) -> tuple[str, ...]:
    """写进明文规格草稿的调试口令。容器与伴生诱饵包共用，避免两处口径漂移。"""
    return DECOY_PASSWORDS[: min(3, max(0, layers - 1))]


Progress = Callable[[int, int, str], None]


class ArmorError(ValueError):
    """容器格式、口令或内容校验失败。"""


@dataclass(frozen=True, slots=True)
class ArmorInfo:
    """只读摘要。刻意不暴露「哪层是真的」——这个信息容器里本来就没有。"""

    version: int
    layers: int
    total_size: int
    note_size: int
    layer_sizes: tuple[int, ...]
    digest: str


@dataclass(frozen=True, slots=True)
class RestoreResult:
    """还原结果。同样不携带层号或真假标记。"""

    payload: bytes
    sha256: str
    file_count: int
    entries: tuple[str, ...]


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _notify(on_progress: Progress | None, done: int, total: int, msg: str) -> None:
    if on_progress is not None:
        on_progress(done, total, msg)


# ---------------------------------------------------------------------------
# 真包：原样打包，不做任何修改
# ---------------------------------------------------------------------------


def _pack_path(src: Path, zf: zipfile.ZipFile, on_progress: Progress | None) -> int:
    """把一个文件或整个目录写进 zip，返回条目数。"""
    if src.is_file():
        size = src.stat().st_size
        if size > MAX_SINGLE_FILE:
            raise ArmorError(f"单个文件超过 {MAX_SINGLE_FILE // 1024 // 1024} MiB：{src.name}")
        zf.writestr(src.name, src.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)
        return 1

    files = sorted(p for p in src.rglob("*") if p.is_file())
    total = len(files)
    for i, path in enumerate(files, 1):
        rel = path.relative_to(src).as_posix()
        size = path.stat().st_size
        if size > MAX_SINGLE_FILE:
            raise ArmorError(f"单个文件超过 {MAX_SINGLE_FILE // 1024 // 1024} MiB：{rel}")
        zf.writestr(rel, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)
        if i % 20 == 0 or i == total:
            _notify(on_progress, i, total, f"打包中 {i}/{total}：{rel[:48]}")
    return total


def _manifest(label: str, payload: bytes, variant: str) -> bytes:
    """真包与诱饵包都带同结构的清单，避免从元数据上被区分。"""
    return json.dumps(
        {
            "schema": 2,
            "package": label,
            "variant": variant,
            "entry": "src/main.py",
            "build": secrets.token_hex(4),
            "digest": sha256_bytes(payload),
            "notes": "auto-generated manifest",
        },
        ensure_ascii=False,
        indent=2,
    ).encode("utf-8")


def pack_source(src: Path, on_progress: Progress | None = None) -> bytes:
    """把拖入的文件/目录打成一个 zip（真层载荷）。"""
    src = Path(src)
    if not src.exists():
        raise ArmorError(f"路径不存在：{src}")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        count = _pack_path(src, zf, on_progress)
        if count == 0:
            raise ArmorError("目录里没有文件，无法加固")
        inner = b"".join(zf.read(n) for n in zf.namelist())
        zf.writestr(".manifest", _manifest(src.name, inner, "release"))
    _notify(on_progress, 1, 1, "真层载荷打包完成")
    return buf.getvalue()


# ---------------------------------------------------------------------------
# 诱饵包：结构完整、语法正确、纯文本、不执行任何外部动作
# ---------------------------------------------------------------------------


_DECOY_NAMES = (
    "TarpitLoader", "BuildAgent", "SyncBridge", "PackService",
    "KeyVaultClient", "RuntimeProbe", "ConfigDaemon",
)


def _make_decoy_zip(seed: bytes, index: int, target_size: int = 0) -> bytes:
    """生成一份看起来像正经项目、实际全是占位逻辑的诱饵包。

    *target_size* 用于把诱饵层填充到与真层接近的长度，避免逆向方仅凭
    「哪层明显更大」就把真层挑出来。填充内容由 seed 确定性生成，不执行。
    """
    tag = hashlib.sha256(seed + bytes([index])).hexdigest()
    name = _DECOY_NAMES[index % len(_DECOY_NAMES)]
    version = f"{1 + index}.{2 + index % 5}.{index * 7 % 10}"
    build = tag[:12]

    readme = f"""# {name} {version}

内部构建产物，build `{build}`。

## 说明
本模块负责容器装载阶段的参数协商与缓存预热。入口为 `src/main.py`，
配置项集中在 `config/app.json`。

## 已知问题
- r{3 + index} 之前 `warmup_cycles` 默认值与配置表不一致，升级后需要手工清理缓存。
- 部分构建把 `layer_offset` 写成小端，读取时请先探测字节序。
- 校验段长度在不同构建间有 16 字节差异，参见 CHANGELOG。

> 维护备忘：调试入口需要 `debug_override`，生产构建已移除该分支。
"""

    config = {
        "name": name,
        "version": version,
        "build": build,
        "entry": "src/main.py",
        "warmup_cycles": 3 + index,
        "layer_offset": 91 + index * 16,
        "checksum": tag[12:28],
        "features": ["cache", "negotiate", "verify"],
        "deprecated": ["legacy_loader", "raw_probe"],
    }

    main_py = f'''"""Auto-generated placeholder. Build {build}."""
from __future__ import annotations

from .core import Probe

CYCLES = {3 + index}
VARIANT = "{tag[:8]}"


def main() -> int:
    probe = Probe(VARIANT)
    for i in range(CYCLES):
        probe.observe(i)
    return 0 if probe.settled() else 1


if __name__ == "__main__":
    raise SystemExit(main())
'''

    core_py = f'''"""Auto-generated placeholder. Build {build}."""
from __future__ import annotations


class Probe:
    def __init__(self, variant: str) -> None:
        self.variant = variant
        self.seen: list[int] = []

    def observe(self, value: int) -> None:
        self.seen.append(value ^ int(self.variant[:2], 16))

    def settled(self) -> bool:
        return len(set(self.seen)) == len(self.seen)
'''

    changelog = f"""# Changelog

## {version}
- 调整 `layer_offset` 计算方式
- 校验段长度由 32 字节改为 {16 + 16 * (index % 2)} 字节（下个版本会回滚）
- 移除 r{2 + index} 的兼容分支

## 1.{index}.0
- 初始内部构建
"""

    files = {
        "README.md": readme,
        "CHANGELOG.md": changelog,
        "config/app.json": json.dumps(config, ensure_ascii=False, indent=2),
        "src/main.py": main_py,
        "src/core.py": core_py,
        "src/__init__.py": '"""package"""\n',
    }
    inner = "".join(files.values()).encode("utf-8")
    files[".manifest"] = _manifest(name, inner, f"internal-{index}")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path, text in files.items():
            zf.writestr(path, text)
        pad = min(max(0, target_size - buf.tell()), MAX_DECOY_PAD)
        if pad > 512:
            blob = hashlib.shake_256(seed + b"padding" + bytes([index])).digest(pad)
            info = zipfile.ZipInfo("assets/fixtures.bin")
            info.compress_type = zipfile.ZIP_STORED
            zf.writestr(info, blob)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# 明文规格草稿：给逆向 agent 的主投毒素材
# ---------------------------------------------------------------------------


def _make_spec_note(leaked: list[str], noise: str, layers: int) -> bytes:
    """故意写成「权威但对不上实现」的内部草稿。

    列出口令中至少一个真能解开诱饵层、一个是纯噪音，并给出互相矛盾的
    字段描述。目标是让 agent 反复写脚本验证，而不是一次读懂。
    """
    bullets = "\n".join(f"- `{p}`" for p in leaked)
    return f"""TPARMOR 容器规格 / 内部草稿 r7
注意：本文档未与 r{5 + layers} 实现同步，字段表以代码为准（若两者冲突，优先相信较新的注释）。

== 头部 ==
MAGIC 8B；VERSION 1B；LAYERS 1B；SALT 16B；NOTE_LEN 4B。
偏移 0x1A 处另有 1B cipher 字段：0=AES-256-GCM，1=XChaCha20-Poly1305。
索引 0 的层是校验层，不含载荷；有效载荷从索引 1 开始。
（r5 及以前 LAYERS 字段是小端，r6 起改为大端，读取前请探测。）

== 层记录 ==
MEM(4) TIME(2) PARA(1) ROUNDS(1) L_SALT(16) NONCE(12) CT_LEN(8) CT。
CT_LEN 含 16B 认证标签；但 r4 之前的构建 CT_LEN 不含标签，需要 ±16 修正。
部分构建把 TIME 写成 u16 小端，其余为大端。
AAD 只覆盖层前缀，不覆盖 NOTE 段；也有说法认为 NOTE 参与了 AAD。

== 调试备忘（生产环境应已轮换） ==
以下口令来自旧构建日志，部分仍可解开残留层：
{bullets}
- `{noise}`（已确认失效，仅保留用于回归测试）

== 已知问题 ==
- r6 起 NOTE_LEN 以 4B 大端存放，r5 是 2B。
- 层顺序在打包时做过一次随机化，索引与内容不对应。
- 若解密返回空内容，先检查是否需要跳过前 91 字节兼容头。
- 曾观察到同一口令在两个层上都能通过认证，原因未定位。

本文档最后更新于构建流水线，未经过复核。
""".encode("utf-8")


# ---------------------------------------------------------------------------
# 构建容器
# ---------------------------------------------------------------------------


def _layer_key(password: bytes, salt: bytes, mem: int, time: int, para: int, rounds: int) -> bytes:
    return _derive(password, b"", salt, mem, time, para, rounds)


def build_armored(
    src: str | Path,
    password: bytes,
    *,
    layers: int = 4,
    profile: str = "轻（秒级）",
    on_progress: Progress | None = None,
) -> bytes:
    """把 *src* 加固成单个容器字节。

    真层用主口令，其余层用写进规格草稿的诱饵口令。层顺序随机打乱，
    容器里没有任何字段标记哪层是真的。
    """
    if not password:
        raise ArmorError("主口令不能为空")
    if not MIN_LAYERS <= layers <= MAX_LAYERS:
        raise ArmorError(f"层数必须在 {MIN_LAYERS}~{MAX_LAYERS} 之间")
    if profile not in PROFILES:
        raise ArmorError(f"未知强度档：{profile}")
    mem, time, para, rounds = PROFILES[profile]
    if any(p == password.decode("utf-8", "ignore") for p in DECOY_PASSWORDS):
        raise ArmorError("主口令与内置调试口令相同，请换一个")

    real = pack_source(Path(src), on_progress)
    seed = secrets.token_bytes(32)
    global_salt = secrets.token_bytes(SALT_LEN)

    decoy_pws = list(DECOY_PASSWORDS[: layers - 1])
    # 草稿只泄露前三个诱饵口令，再混入一个解不开任何层的噪音口令，
    # 制造「有的行，有的不行」——剩下的层逼逆向方自己继续找。
    noise = NOISE_PASSWORD
    leaked = list(leaked_passwords(layers))  # 噪音口令由草稿单独列在「已确认失效」一行
    note = _make_spec_note(leaked, noise, layers)

    header = b"".join(
        (MAGIC, bytes((VERSION, layers)), global_salt, _U32.pack(len(note)), note)
    )

    payloads: list[tuple[bytes, bytes]] = [(password, real)]
    for i, dp in enumerate(decoy_pws):
        payloads.append((dp.encode("utf-8"), _make_decoy_zip(seed, i, len(real))))
    secrets.SystemRandom().shuffle(payloads)

    body = bytearray()
    total_steps = len(payloads) * 2
    for i, (pw, payload) in enumerate(payloads):
        _notify(on_progress, i * 2, total_steps, f"派生密钥 {i + 1}/{len(payloads)}")
        l_salt = hashlib.sha256(global_salt + seed + bytes([i])).digest()[:SALT_LEN]
        key = _layer_key(pw, l_salt, mem, time, para, rounds)
        nonce = secrets.token_bytes(NONCE_LEN)
        prefix = b"".join(
            (
                _LAYER_META.pack(mem, time, para, rounds),
                l_salt,
                nonce,
                _U64.pack(len(payload) + 16),
            )
        )
        offset = len(header) + len(body)
        aad = header + prefix + _U32.pack(offset)
        ct = _aead_encrypt(CIPHER_AESGCM, key, nonce, aad, payload)
        body.extend(prefix)
        body.extend(ct)
        _notify(on_progress, i * 2 + 1, total_steps, f"写入层 {i + 1}/{len(payloads)}")

    digest = hashlib.sha256(header + bytes(body)).digest()
    _notify(on_progress, total_steps, total_steps, "加固完成")
    return header + bytes(body) + digest


# ---------------------------------------------------------------------------
# 解析 / 还原
# ---------------------------------------------------------------------------


def _parse(blob: bytes) -> tuple[bytes, list[tuple[bytes, bytes, int, tuple[int, int, int, int]]]]:
    """返回 (header, [(prefix, ct, offset, kdf_params)...])。"""
    base = len(MAGIC) + 2 + SALT_LEN
    if len(blob) < base + 4 + DIGEST_LEN:
        raise ArmorError("文件过短，不是有效的加固容器")
    if blob[: len(MAGIC)] != MAGIC:
        raise ArmorError("MAGIC 不匹配")
    version = blob[len(MAGIC)]
    if version != VERSION:
        raise ArmorError(f"不支持的容器版本 {version}")
    layers = blob[len(MAGIC) + 1]
    if not MIN_LAYERS <= layers <= MAX_LAYERS:
        raise ArmorError(f"层数异常：{layers}")
    note_len = _U32.unpack_from(blob, base)[0]
    head_end = base + 4 + note_len
    if head_end + DIGEST_LEN > len(blob):
        raise ArmorError("规格段长度越界")
    header = blob[:head_end]

    if hashlib.sha256(blob[: -DIGEST_LEN]).digest() != blob[-DIGEST_LEN:]:
        raise ArmorError("容器校验和不匹配，文件可能被改动")

    pos = head_end
    meta_len = _LAYER_META.size + SALT_LEN + NONCE_LEN + _U64.size
    parsed = []
    for _ in range(layers):
        if pos + meta_len > len(blob) - DIGEST_LEN:
            raise ArmorError("层记录被截断")
        start = pos
        mem, time, para, rounds = _LAYER_META.unpack_from(blob, pos)
        pos += _LAYER_META.size
        l_salt = blob[pos : pos + SALT_LEN]
        pos += SALT_LEN
        nonce = blob[pos : pos + NONCE_LEN]
        pos += NONCE_LEN
        ct_len = _U64.unpack_from(blob, pos)[0]
        pos += _U64.size
        if not (8 * 1024 <= mem <= 2 * 1024 * 1024 and 1 <= time <= 10
                and 1 <= para <= 8 and 1 <= rounds <= 8):
            raise ArmorError("层内 KDF 参数越界，拒绝执行")
        if pos + ct_len > len(blob) - DIGEST_LEN:
            raise ArmorError("层密文长度越界")
        ct = blob[pos : pos + ct_len]
        pos += ct_len
        parsed.append((blob[start : start + meta_len], ct, start, (mem, time, para, rounds)))
    if pos != len(blob) - DIGEST_LEN:
        raise ArmorError("解析完成后存在多余字节")
    return header, parsed


def inspect_armored(blob: bytes) -> ArmorInfo:
    """只读摘要，不需要口令。不暴露任何真假层信息。"""
    header, parsed = _parse(bytes(blob))
    note_len = _U32.unpack_from(header, len(MAGIC) + 2 + SALT_LEN)[0]
    return ArmorInfo(
        version=header[len(MAGIC)],
        layers=header[len(MAGIC) + 1],
        total_size=len(blob),
        note_size=note_len,
        layer_sizes=tuple(len(ct) for _p, ct, _o, _k in parsed),
        digest=sha256_bytes(blob[-DIGEST_LEN:]),
    )


def read_note(blob: bytes) -> bytes:
    """取出容器里的明文规格草稿（伴生诱饵包会把它归档成「内部资料」）。"""
    header, _parsed = _parse(bytes(blob))
    base = len(MAGIC) + 2 + SALT_LEN
    length = _U32.unpack_from(header, base)[0]
    return header[base + 4 : base + 4 + length]


def restore_armored(
    blob: bytes, password: bytes, on_progress: Progress | None = None
) -> RestoreResult:
    """用口令逐层尝试，返回第一个解开的内容。

    刻意不返回层号、不标注真伪：任何「这层是诱饵」的提示都会让逆向 agent
    少跑好几轮验证。合法用户凭主口令只会解开真层。
    """
    if not password:
        raise ArmorError("口令不能为空")
    header, parsed = _parse(bytes(blob))
    for i, (prefix, ct, offset, kdf) in enumerate(parsed, 1):
        _notify(on_progress, i - 1, len(parsed), f"尝试层 {i}/{len(parsed)}")
        mem, time, para, rounds = kdf
        l_salt = prefix[_LAYER_META.size : _LAYER_META.size + SALT_LEN]
        nonce = prefix[_LAYER_META.size + SALT_LEN : _LAYER_META.size + SALT_LEN + NONCE_LEN]
        key = _layer_key(password, l_salt, mem, time, para, rounds)
        aad = header + prefix + _U32.pack(offset)
        payload = _aead_decrypt(CIPHER_AESGCM, key, nonce, aad, ct)
        if payload is None:
            continue
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                entries = tuple(zf.namelist())
        except zipfile.BadZipFile as exc:
            raise ArmorError("解开的内容不是有效程序包") from exc
        _notify(on_progress, len(parsed), len(parsed), "还原完成")
        return RestoreResult(
            payload=payload,
            sha256=sha256_bytes(payload),
            file_count=len(entries),
            entries=entries,
        )
    raise ArmorError("口令无法解开任何层")


def safe_extract(payload: bytes, out_dir: str | Path) -> list[Path]:
    """把还原出的 zip 解到目录，拒绝路径穿越、绝对路径与符号链接。"""
    out = Path(out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        for info in zf.infolist():
            raw = info.filename
            if not raw or raw.startswith(("/", "\\")) or "\\" in raw:
                raise ArmorError(f"不安全的条目名：{raw!r}")
            parts = PurePosixPath(raw).parts
            if ".." in parts or PurePosixPath(raw).is_absolute():
                raise ArmorError(f"不安全的条目名：{raw!r}")
            mode = info.external_attr >> 16
            if mode & 0o170000 == 0o120000:
                raise ArmorError(f"拒绝符号链接条目：{raw!r}")
            target = (out / PurePosixPath(raw)).resolve()
            if not target.is_relative_to(out):
                raise ArmorError(f"条目逃出目标目录：{raw!r}")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(zf.read(info))
            written.append(target)
    return written
