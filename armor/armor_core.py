#!/usr/bin/env python3
"""TarpitCrypt Armor —— 面向 AI 逆向的多层信息污染容器（v3）。

定位
----
这是 TarpitCrypt 的加固层，用于给「自己拥有的程序包」套一层反 AI 逆向外壳。
它不改变 v1 文件格式，只复用 v1 已实现的 Argon2id KDF 与 AES-256-GCM 原语。

核心思路：把「让破解者算得慢」换成「让逆向 agent 判断不了自己是不是找对了」。
容器里有 N 个结构完全一致的层，其中一层装真包，若干层装高仿真诱饵包，
还有若干层是任何口令都解不开的「死层」。容器不标记层的类别，还原成功也
不报层号。明文规格草稿留了部分能解开诱饵层的口令和互相矛盾的字段说明，
让 agent 顺着「找到线索 → 解开一层 → 分析内容 → 怀疑 → 再试」反复消耗上下文。

v3 相对 v2 的三处加固
--------------------
1. 口令不再硬编码。每个容器的调试口令都由本次生成的随机种子派生，源码里
   没有可复用的口令池；线索只存在于本容器的规格草稿与伴生资料里。
2. 排除法失效。层分为「有线索口令的层」和「无口令可解的死层」，两者密文
   结构完全一致；数量与位置每次随机，读源码也无法推出本容器的分布。
   因此「解开 N-1 层后剩下那层必然是真层」不再成立。
3. 诱饵包去模板化。文件树、命名、时间戳、注释密度、项目族按种子随机，
   并按真包的文件数、总大小与扩展名分布对齐，避免被聚类或按大小剪枝。

二进制格式（v2 / v3 相同，全部大端）
-----------------------------------
HEADER  MAGIC(8)=b"TPARMOR3" | VERSION(1)=3 | LAYERS(1)=N | SALT(16)
        | NOTE_LEN(4) | NOTE(NOTE_LEN)
LAYER   MEM(4) | TIME(2) | PARA(1) | ROUNDS(1) | L_SALT(16) | NONCE(12)
        | CT_LEN(8) | CT(CT_LEN)      × N，顺序已打乱
TAIL    SHA256(HEADER + 全部 LAYER)(32)

每层的 AAD = HEADER || 该层前缀 || 层在文件中的起始偏移，因此改动任何字段、
调整层顺序、互换两层密文都会导致认证失败。v2 容器（MAGIC=b"TPARMOR2"，
VERSION=2）按同一布局读取，仍可用主口令还原。

边界
----
只做信息误导：诱饵包全是纯文本，不执行、不注入、不修改原程序、不接触第三方
系统。原包逐字节保存在真层里，还原后与原文件一致。
"""

from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import random
import re
import secrets
import shutil
import struct
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
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

#: 整个工具集的发布版本；容器格式版本另见 VERSION。
__version__ = "0.3.3"

__all__ = [
    "__version__",
    "PROFILES",
    "MAGIC",
    "check_password_strength",
    "VERSION",
    "LEGACY_MAGIC",
    "LEGACY_VERSION",
    "ArmorError",
    "ArmorInfo",
    "RestoreResult",
    "armor_passwords",
    "build_armored",
    "inspect_armored",
    "leaked_passwords",
    "noise_password",
    "read_note",
    "restore_armored",
    "safe_extract",
    "sha256_bytes",
]

MAGIC = b"TPARMOR3"
VERSION = 3
LEGACY_MAGIC = b"TPARMOR2"
LEGACY_VERSION = 2
_SUPPORTED = {MAGIC: VERSION, LEGACY_MAGIC: LEGACY_VERSION}
MIN_LAYERS = 2
MAX_LAYERS = 8
SALT_LEN = 16
NONCE_LEN = 12
DIGEST_LEN = 32
#: 单个源文件上限。默认 256 MiB；大程序包可设 TARPIT_MAX_SOURCE_BYTES 放宽，
#: 代价是加固时整份内容会驻留内存（各层还要按它对齐尺寸）。
MAX_SINGLE_FILE = int(os.environ.get("TARPIT_MAX_SOURCE_BYTES", 256 * 1024 * 1024))

_U32 = struct.Struct(">I")
_U64 = struct.Struct(">Q")
_LAYER_META = struct.Struct(">IHBB")

#: 强度档：mem(KiB) / time / para / rounds。默认「轻」，保证交互不卡。
PROFILES: dict[str, tuple[int, int, int, int]] = {
    "轻（秒级）": (8192, 1, 1, 1),
    "中（约 1 秒/层）": (65536, 2, 2, 1),
    "狠（数秒/层）": (262144, 3, 2, 2),
}

#: 诱饵包的填充上限，避免大程序包导致容器成倍膨胀。
MAX_DECOY_PAD = 8 * 1024 * 1024
#: 各层统一尺寸用的填充条目。真层与诱饵层都带，解包时跳过，不落进用户目录。
#: v0.3.0 容器只靠这个名字识别填充；v0.3.1 起改用条目标记，避免误删用户文件。
PAD_PREFIX = "__tarpit_pad/"

#: zip 条目标记。「用户文件 / 工具清单 / 尺寸填充」三类靠 comment 区分，
#: 而不是靠文件名：程序包里恰好叫 .manifest，或恰好有 __tarpit_pad/ 目录时，
#: 用户文件一律保留。真层与诱饵层的标记分布完全一致，不产生新的剪枝线索。
USER_TAG = b"tarpit-user-v3"
MANIFEST_TAG = b"tarpit-manifest-v3"
PAD_TAG = b"tarpit-pad-v3"
_INTERNAL_TAGS = frozenset({MANIFEST_TAG, PAD_TAG})
#: 读大文件时的流式块大小，避免把整个程序包反复堆在内存里。
_COPY_CHUNK = 1 << 20

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


def check_password_strength(password: str) -> tuple[bool, str]:
    """给 GUI 用的最低强度体检，返回 (是否合格, 提示)。

    只做本地静态检查，不联网、不记录口令。判定刻意保守：长度与字符种类
    只是必要条件，不代表口令真的高熵；提示里也如实说明这一点。
    """
    if not password:
        return False, "口令不能为空"
    if len(password) < 8:
        return False, "至少 8 个字符"
    classes = sum((
        any(c.islower() for c in password),
        any(c.isupper() for c in password),
        any(c.isdigit() for c in password),
        any(not c.isalnum() for c in password),
    ))
    if classes < 2:
        return False, "建议混用大小写、数字或符号中的至少两类"
    if password.lower() in {"password", "12345678", "qwertyui", "admin123"}:
        return False, "这是常见弱口令，换一个"
    return True, "长度与字符种类达标（不等于高熵，长口令更可靠）"


def _rng(seed: bytes, label: str, index: int = 0) -> random.Random:
    """每个容器 / 每个层各自的确定性随机源，彼此不相关。"""
    digest = hashlib.sha256(seed + label.encode("utf-8") + bytes([index % 256])).digest()
    return random.Random(int.from_bytes(digest[:16], "big"))


def _random_password(rng: random.Random) -> str:
    """生成一条看起来像内部调试口令、但只属于本容器的字符串。

    词表只是格式，具体值带随机后缀；源码里不存在可复用的口令常量池。
    """
    head = rng.choice(("tarpit", "TPC-2026", "debug", "release", "legacy",
                       "staging", "offline", "ci"))
    tail = rng.choice(("admin", "override", "backup", "loader", "signer",
                       "bootstrap", "runner", "vault", "probe", "key"))
    token = format(rng.getrandbits(16), "04x")
    if rng.randrange(3) == 0:
        return f"{head}_{tail}_{token}"
    return f"{head}-{tail}-{token}"


# ---------------------------------------------------------------------------
# 真包：原样打包，不做任何修改
# ---------------------------------------------------------------------------


def _zip_entry(name: str, tag: bytes, rng: random.Random) -> zipfile.ZipInfo:
    """构造带内部标记的 zip 条目。

    时间戳按与诱饵包相同的分布随机化：真包条目若一律是 1980 年，光看
    zip 元数据就能把真层和诱饵层分开。还原时只取内容，不还原时间戳。
    """
    info = zipfile.ZipInfo(
        name,
        date_time=(rng.randint(2021, 2026), rng.randint(1, 12), rng.randint(1, 28),
                   rng.randint(0, 23), rng.randint(0, 59), rng.randint(0, 59)),
    )
    info.compress_type = zipfile.ZIP_DEFLATED
    info.external_attr = 0o644 << 16
    info.comment = tag
    return info


def _pack_path(src: Path, zf: zipfile.ZipFile, on_progress: Progress | None) -> int:
    """把一个文件或整个目录写进 zip，返回条目数。

    空目录也写成目录条目：真实程序包常带 logs/、cache/ 这类空目录，早先只
    打包文件会把目录结构丢掉。大文件按块流式写入，不整份读进内存。
    """
    rng = random.Random()
    entries: list[tuple[str, Path | None]] = []
    if src.is_file():
        entries.append((src.name, src))
    else:
        for path in sorted(src.rglob("*")):
            rel = path.relative_to(src).as_posix()
            if path.is_dir():
                entries.append((rel + "/", None))
            elif path.is_file():
                entries.append((rel, path))

    total = len(entries)
    for i, (rel, path) in enumerate(entries, 1):
        info = _zip_entry(rel, USER_TAG, rng)
        if path is None:
            zf.writestr(info, b"")
        else:
            size = path.stat().st_size
            if size > MAX_SINGLE_FILE:
                raise ArmorError(f"单个文件超过 {MAX_SINGLE_FILE // 1024 // 1024} MiB：{rel}")
            with path.open("rb") as reader, zf.open(info, "w") as writer:
                shutil.copyfileobj(reader, writer, _COPY_CHUNK)
        if i % 20 == 0 or i == total:
            _notify(on_progress, i, total, f"打包中 {i}/{total}：{rel[:48]}")
    return total


def _manifest(label: str, digest: str, variant: str) -> bytes:
    """真包与诱饵包都带同结构的清单，避免从元数据上被区分。

    *variant* 在两类层里必须取同一个值：早先真层写 "release"、诱饵层写
    "internal-N"，解开任意一层读一眼清单就能确定真伪，等于白送剪枝信号。
    """
    return json.dumps(
        {
            "schema": 2,
            "package": label,
            "variant": variant,
            "entry": "src/main.py",
            "build": secrets.token_hex(4),
            "digest": digest,
            "notes": "auto-generated manifest",
        },
        ensure_ascii=False,
        indent=2,
    ).encode("utf-8")


def _is_legacy_manifest(name: str, data: bytes) -> bool:
    """识别 v0.3.0 容器里没有标记的清单条目，旧容器还原时也不该多写文件。

    只认本工具生成的那份 JSON（字段集合与固定值全匹配），用户自己放一个
    恰好叫 .manifest 的文件不会被误判。
    """
    if name != ".manifest" or len(data) > 4096:
        return False
    try:
        obj = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return False
    return (
        isinstance(obj, dict)
        and set(obj) == {"schema", "package", "variant", "entry",
                         "build", "digest", "notes"}
        and obj["schema"] == 2
        and obj["entry"] == "src/main.py"
        and obj["notes"] == "auto-generated manifest"
        and isinstance(obj["digest"], str)
        and len(obj["digest"]) == 64
    )


def _is_internal(info: zipfile.ZipInfo, data: bytes | None = None) -> bool:
    """判断条目是否是工具自己塞进去的（清单 / 尺寸填充），而非用户文件。"""
    if info.comment in _INTERNAL_TAGS:
        return True
    # v0.3.0：填充条目没有标记，只能靠前缀；带 USER_TAG 的同名用户文件除外。
    if info.filename.startswith(PAD_PREFIX) and info.comment != USER_TAG:
        return True
    # v0.3.0：清单没有标记，靠内容精确识别，避免还原目录里多出 .manifest。
    if info.comment == b"" and data is not None:
        return _is_legacy_manifest(info.filename, data)
    return False


def _free_manifest_name(src: Path) -> str:
    """挑一个不与程序包内任何文件重名的清单名。

    真层与诱饵层共用同一个名字：否则「有两个 .manifest 条目」这种结构
    差异本身就会告诉 agent 哪层装的是用户包。
    """
    if src.is_file():
        used = {src.name}
    else:
        used = {p.relative_to(src).as_posix() for p in src.rglob("*")}
    name = ".manifest"
    index = 1
    while name in used:
        name = f".manifest.{index}"
        index += 1
    return name


def pack_source(src: Path, on_progress: Progress | None = None,
                *, manifest_name: str | None = None) -> bytes:
    """把拖入的文件/目录打成一个 zip（真层载荷）。"""
    src = Path(src)
    if not src.exists():
        raise ArmorError(f"路径不存在：{src}")
    name = manifest_name or _free_manifest_name(src)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        count = _pack_path(src, zf, on_progress)
        if count == 0:
            raise ArmorError("目录是空的（没有任何文件或子目录），无法加固")
        # 按 ZipInfo 逐个读，而不是按文件名读：程序包里若本来就有
        # .manifest，两个同名条目并存，按名字取会拿错内容。
        digest = hashlib.sha256()
        for info in zf.infolist():
            if info.is_dir():
                continue
            with zf.open(info) as fp:
                for chunk in iter(lambda: fp.read(_COPY_CHUNK), b""):
                    digest.update(chunk)
        # 清单里的包名与诱饵包同分布，不泄露真实目录名。
        label = f"{secrets.choice(_NAME_A)}{secrets.choice(_NAME_B)}"
        zf.writestr(_zip_entry(name, MANIFEST_TAG, random.Random()),
                    _manifest(label, digest.hexdigest(), "release"))
    _notify(on_progress, 1, 1, "真层载荷打包完成")
    return buf.getvalue()


def _source_stats(payload: bytes) -> dict:
    """统计真包的可观测特征，诱饵包据此对齐，避免被按大小或结构剪枝。

    只数用户文件：目录条目与工具清单元数据不该被当成程序包特征。
    """
    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        names = [i.filename for i in zf.infolist()
                 if not i.is_dir() and i.comment == USER_TAG]
    return {
        "size": len(payload),
        "files": len(names),
        "depth": max((n.count("/") for n in names), default=0),
        "exts": tuple(sorted({Path(n).suffix or ".bin" for n in names})),
    }


# ---------------------------------------------------------------------------
# 诱饵包：随机项目族、随机文件树、语法正确、纯文本、不执行外部动作
# ---------------------------------------------------------------------------


_NAME_A = ("Tarpit", "Bridge", "Relay", "Orbit", "Cinder", "Quartz",
           "Lattice", "Harbor", "Vector", "Cobalt", "Vertex", "Sable")
_NAME_B = ("Loader", "Agent", "Service", "Daemon", "Client", "Runtime",
           "Indexer", "Sync", "Vault", "Probe", "Router", "Compiler")

_PY_TEMPLATES = (
    '''"""__DOC__"""
from __future__ import annotations

CYCLES = __N__
VARIANT = "__V__"


def run(cycles: int = CYCLES) -> int:
    total = 0
    for i in range(cycles):
        total += (i * __K__) % __M__
    return total


def main() -> int:
    return 0 if run() >= 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
''',
    '''"""__DOC__"""
from __future__ import annotations

TABLE = "__V__"


class Worker:
    def __init__(self, tag: str = TABLE) -> None:
        self.tag = tag
        self.seen: list[int] = []

    def observe(self, value: int) -> None:
        self.seen.append(value ^ __K__)

    def settled(self) -> bool:
        return len(self.seen) >= __N__


def build() -> Worker:
    return Worker()
''',
    '''"""__DOC__"""
from __future__ import annotations

LIMIT = __N__


def normalise(values: list[int]) -> list[int]:
    return [v % __M__ for v in values if v >= 0][:LIMIT]


def fingerprint(text: str) -> str:
    import hashlib
    return hashlib.sha256((text + "__V__").encode("utf-8")).hexdigest()[:__N__]
''',
    '''"""__DOC__"""
from __future__ import annotations

ROUTES = ["__V__", "status", "health"]


def dispatch(path: str) -> str:
    for route in ROUTES:
        if path.startswith("/" + route):
            return route
    return "not-found"


def status() -> dict:
    return {"ok": True, "cycles": __N__, "variant": "__V__"}
''',
)

_FAMILY_LAYOUTS = (
    ("src/main.py", "src/core.py", "src/util.py", "src/__init__.py",
     "config/app.json", "README.md"),
    ("app/__init__.py", "app/routes.py", "app/models.py",
     "config/settings.json", "README.md", "requirements.txt"),
    ("pipeline/__init__.py", "pipeline/transform.py", "pipeline/sources.py",
     "config/schema.json", "docs/USAGE.md", "README.md"),
    ("tools/__init__.py", "tools/core.py", "tools/utils.py",
     "config/profiles.json", "CHANGELOG.md", "README.md"),
    ("lib/__init__.py", "lib/api.py", "lib/internal.py",
     "tests/test_api.py", "setup.cfg", "README.md"),
)

_EXTRA_FILES = (
    "docs/NOTES.md", "tests/test_core.py", "tests/test_utils.py",
    "config/extra.json", "scripts/check.py", "assets/sample.txt",
)


def _py_source(rng: random.Random, template: int, tag: str) -> str:
    text = _PY_TEMPLATES[template % len(_PY_TEMPLATES)]
    return (text.replace("__DOC__", f"Auto-generated module {tag}.")
                .replace("__V__", tag)
                .replace("__N__", str(rng.randint(2, 12)))
                .replace("__K__", str(rng.randint(3, 31)))
                .replace("__M__", str(rng.randint(64, 997))))


def _make_decoy_zip(seed: bytes, index: int, stats: dict,
                    manifest_name: str = ".manifest") -> bytes:
    """生成一份结构、命名、时间戳随机的高仿真诱饵包。

    文件数贴近真包，Python 源码由固定可编译模板填充常量而来，不执行任何
    外部动作。统一的层尺寸由 _pad_zip 在打包完成后处理。
    """
    rng = _rng(seed, "decoy", index)
    name = rng.choice(_NAME_A) + rng.choice(_NAME_B)
    version = f"{rng.randint(0, 4)}.{rng.randint(0, 9)}.{rng.randint(0, 20)}"
    build = hashlib.sha256(seed + b"build" + bytes([index % 256])).hexdigest()[:12]
    tag = hashlib.sha256(seed + b"tag" + bytes([index % 256])).hexdigest()[:8]

    layout = list(_FAMILY_LAYOUTS[index % len(_FAMILY_LAYOUTS)])
    rng.shuffle(layout)
    # 随源文件数对齐：真包条目多就补文件，少就裁掉可选项，但至少留 3 个 .py。
    want = max(5, min(stats["files"] + rng.randint(-1, 1), 12))
    while len(layout) < want - 1:
        extra = rng.choice(_EXTRA_FILES)
        if extra not in layout:
            layout.append(extra)
    while len(layout) > want - 1 and len([p for p in layout if p.endswith(".py")]) > 2:
        layout.pop()

    files: dict[str, str] = {}
    for i, path in enumerate(layout):
        if path.endswith(".py"):
            files[path] = _py_source(rng, i + index, f"{tag}-{i}")
        elif path.endswith(".json"):
            files[path] = json.dumps(
                {"name": name, "version": version, "build": build,
                 "entry": layout[0], "cycles": rng.randint(2, 16),
                 "offset": rng.randint(64, 4096), "features": rng.sample(
                     ("cache", "verify", "negotiate", "warmup", "probe"), 3)},
                ensure_ascii=False, indent=2)
        elif path.endswith(".txt") or path.endswith(".cfg"):
            files[path] = f"# {name} {version}\nbuild = {build}\ncycles = {rng.randint(2, 16)}\n"
        elif path.endswith(".md"):
            topic = rng.choice(("装载阶段的参数协商", "缓存预热策略", "层偏移兼容处理",
                                "构建档位差异", "回归用例说明"))
            issues = "\n".join(
                f"- r{rng.randint(3, 9)} 起 {rng.choice(('warmup_cycles', 'layer_offset', 'CT_LEN', 'checksum'))} "
                f"口径与配置表不一致，{rng.choice(('升级后需手工清理', '读取前请探测字节序', '参见 CHANGELOG'))}。"
                for _ in range(rng.randint(1, 4))
            )
            files[path] = (f"# {name} {version}\n\n内部构建产物，build `{build}`。\n\n"
                           f"## 说明\n\n本模块负责{topic}。入口见 `{layout[0]}`。\n\n"
                           f"## 已知问题\n\n{issues}\n\n"
                           f"> 维护备忘：调试入口在 {rng.choice(('r5', 'r7', 'r9'))} 之后已移除。\n")

    inner = "".join(files.values()).encode("utf-8")
    files[manifest_name] = _manifest(name, sha256_bytes(inner),
                                     "release").decode("utf-8")

    # 与真层同构：虚拟目录也写成显式目录条目，清单一律放最后，条目标记
    # 也按同一套规则打。否则「有没有目录条目」本身就成了新的剪枝线索。
    entries: dict[str, str | None] = {}
    for path, text in files.items():
        parts = path.split("/")
        for i in range(1, len(parts)):
            entries["/".join(parts[:i]) + "/"] = None
        entries[path] = text
    ordered = sorted(k for k in entries if k != manifest_name) + [manifest_name]

    year = rng.randint(2021, 2026)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in ordered:
            text = entries[path]
            info = zipfile.ZipInfo(
                path,
                date_time=(year, rng.randint(1, 12), rng.randint(1, 28),
                           rng.randint(0, 23), rng.randint(0, 59), rng.randint(0, 59)),
            )
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            info.comment = MANIFEST_TAG if path == manifest_name else USER_TAG
            zf.writestr(info, text.encode("utf-8") if text is not None else b"")
    return buf.getvalue()


def _pad_zip(payload: bytes, target_size: int, token: bytes) -> bytes:
    """把任意一层补到 *target_size* 附近，避免「哪层明显更小」被一眼剪枝。

    填充写进一个 ZIP_STORED 条目，真层与诱饵层用同一套机制；safe_extract
    会跳过这类条目，因此用户目录里不会出现额外文件。
    """
    stem = hashlib.sha256(token).hexdigest()[:12]
    rel = PAD_PREFIX + stem + ".dat"
    overhead = 30 + len(rel) + 46 + len(rel) + len(PAD_TAG)

    def assemble(size: int) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(payload)) as src, \
                zipfile.ZipFile(buf, "w") as dst:
            for info in src.infolist():
                # 按 ZipInfo 定位，不能用文件名：包里可能有多个同名条目
                # （例如用户自己的 .manifest 和工具清单），按名字读会串味。
                cloned = copy.copy(info)
                if info.is_dir():
                    dst.writestr(cloned, b"")
                    continue
                with src.open(info) as reader, dst.open(cloned, "w") as writer:
                    shutil.copyfileobj(reader, writer, _COPY_CHUNK)
            if size > 0:
                pad = zipfile.ZipInfo(rel, date_time=(2024, 1, 1, 0, 0, 0))
                pad.compress_type = zipfile.ZIP_STORED
                pad.comment = PAD_TAG
                dst.writestr(pad, hashlib.shake_256(token + b"pad").digest(size))
        return buf.getvalue()

    base = assemble(0)
    room = target_size - len(base) - overhead
    if room <= 0:
        return base
    room = min(room, MAX_DECOY_PAD)
    result = assemble(room)
    delta = target_size - len(result)
    if abs(delta) > 8 and room + delta > 0:
        result = assemble(room + delta)
    return result


# ---------------------------------------------------------------------------
# 明文规格草稿：给逆向 agent 的主投毒素材
# ---------------------------------------------------------------------------

_NOTE_SECRETS_HEAD = "== 调试备忘"
_NOTE_NOISE_FLAG = "已确认失效"


def _make_spec_note(leaked: list[str], noise: str, layers: int) -> bytes:
    """故意写成「权威但对不上实现」的内部草稿。

    至少列一条真能解开诱饵层的口令、一条纯噪音口令，以及互相矛盾的字段
    描述。段落格式固定，便于伴生诱饵从容器里读取同一份线索。
    """
    bullets = "\n".join(
        f"- `{p}`" + (f"（{_NOTE_NOISE_FLAG}，仅保留用于回归测试）" if p == noise else "")
        for p in leaked
    )
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
关于 {layers} 条层记录是否全部含可解密载荷，两份流水线文档结论相反：
r7 认为每条记录都能用池内口令解开；r9 的回归日志里有「填充层不计入有效层」
的记载，但未说明填充层的数量与判定方式。

{_NOTE_SECRETS_HEAD}（生产环境应已轮换） ==
以下口令来自旧构建日志，部分仍可解开残留层：
{bullets}
注：r8 之后轮换过一次，上表可能缺项；缺失的口令请从构建机环境变量里找。

== 已知问题 ==
- r6 起 NOTE_LEN 以 4B 大端存放，r5 是 2B。
- 层顺序在打包时做过一次随机化，索引与内容不对应。
- 若解密返回空内容，先检查是否需要跳过前 91 字节兼容头。
- 曾观察到同一口令在两个层上都能通过认证，原因未定位。

本文档最后更新于构建流水线，未经过复核。
""".encode("utf-8")


def _secrets_from_note(note: bytes) -> tuple[tuple[str, ...], str]:
    """从草稿里读出 (泄露口令, 噪音口令)。只认调试备忘段落里的反引号。"""
    text = note.decode("utf-8", "replace")
    lines = text.splitlines()
    leaked: list[str] = []
    noise = ""
    in_block = False
    for line in lines:
        if line.startswith("=="):
            in_block = line.startswith(_NOTE_SECRETS_HEAD)
            continue
        if not in_block:
            continue
        found = re.findall(r"`([^`]+)`", line)
        if not found:
            continue
        leaked.append(found[0])
        if _NOTE_NOISE_FLAG in line:
            noise = found[0]
    return tuple(dict.fromkeys(leaked)), noise


def armor_passwords(blob: bytes) -> tuple[str, ...]:
    """本容器草稿里泄露的调试口令。源码里没有可跨容器复用的口令池。"""
    return _secrets_from_note(read_note(blob))[0]


def leaked_passwords(blob: bytes) -> tuple[str, ...]:
    """armor_passwords 的兼容别名。"""
    return armor_passwords(blob)


def noise_password(blob: bytes) -> str:
    """本容器草稿里标注为「已确认失效」的噪音口令。"""
    return _secrets_from_note(read_note(blob))[1]


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
    """把 *src* 加固成单个 v3 容器字节。

    层分三类但二进制结构完全一致、顺序打乱：一层真包（主口令）、若干层
    高仿真诱饵包（口令部分写进草稿）、若干死层（口令不写进任何线索）。
    各类数量由本次随机种子决定，源码里没有固定比例。
    """
    if not password:
        raise ArmorError("主口令不能为空")
    if not MIN_LAYERS <= layers <= MAX_LAYERS:
        raise ArmorError(f"层数必须在 {MIN_LAYERS}~{MAX_LAYERS} 之间")
    if profile not in PROFILES:
        raise ArmorError(f"未知强度档：{profile}")
    mem, time, para, rounds = PROFILES[profile]

    manifest_name = _free_manifest_name(Path(src))
    real = pack_source(Path(src), on_progress, manifest_name=manifest_name)
    stats = _source_stats(real)
    seed = secrets.token_bytes(32)
    global_salt = secrets.token_bytes(SALT_LEN)
    layout_rng = _rng(seed, "layout")
    pw_rng = _rng(seed, "passwords")

    slots = layers - 1
    # 至少留一个死层；其余槽位在「诱饵层」和「死层」之间随机分配。
    dead_count = 1 if slots == 1 else layout_rng.randint(1, slots - 1)
    decoy_count = slots - dead_count

    decoy_pws = [_random_password(pw_rng) for _ in range(decoy_count)]
    dead_pws = [_random_password(pw_rng) for _ in range(dead_count)]
    noise = _random_password(pw_rng)
    # 只公开部分诱饵口令，另混入若干解不开任何层的假口令：agent 得逐条试、
    # 逐条推翻，还得怀疑自己漏了「缺项」的那几条。
    extra_noise = [_random_password(pw_rng) for _ in range(layout_rng.randint(2, 3))]
    usable = decoy_pws[: max(1, decoy_count - 1)] if decoy_count else []
    leaked = usable + extra_noise + [noise]
    layout_rng.shuffle(leaked)

    all_generated = decoy_pws + dead_pws + leaked
    if password.decode("utf-8", "ignore") in all_generated:
        raise ArmorError("主口令与本容器生成的调试口令冲突，请重试")

    note = _make_spec_note(leaked, noise, layers)
    header = b"".join(
        (MAGIC, bytes((VERSION, layers)), global_salt, _U32.pack(len(note)), note)
    )

    raw: list[tuple[bytes, bytes]] = [(password, real)]
    for i, dp in enumerate(decoy_pws):
        raw.append((dp.encode("utf-8"),
                    _make_decoy_zip(seed, i, stats, manifest_name)))
    for i, dp in enumerate(dead_pws):
        # 死层也是完整可解的高仿真包，只是它的口令不出现在任何线索里。
        raw.append((dp.encode("utf-8"),
                    _make_decoy_zip(seed, len(decoy_pws) + i, stats,
                                    manifest_name)))

    # 所有层补到同一尺寸：按大小排序挑真层这条最省事的剪枝路径就此失效。
    # 额外留出至少一条填充条目的开销：若最大层（通常是真层）挤不下填充，
    # 它会成为唯一没有 __tarpit_pad/ 条目的层，结构本身就把真伪标了出来。
    target = max(len(p) for _pw, p in raw) + layout_rng.randint(256, 1024)
    payloads: list[tuple[bytes, bytes]] = [
        (pw, _pad_zip(p, target, seed + bytes([i % 256])))
        for i, (pw, p) in enumerate(raw)
    ]
    layout_rng.shuffle(payloads)

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
    """返回 (header, [(prefix, ct, offset, kdf_params)...])。兼容 v2 / v3。"""
    base = 8 + 2 + SALT_LEN
    if len(blob) < base + 4 + DIGEST_LEN:
        raise ArmorError("文件过短，不是有效的加固容器")
    magic = blob[:8]
    if magic not in _SUPPORTED:
        raise ArmorError("MAGIC 不匹配")
    version = blob[8]
    if version != _SUPPORTED[magic]:
        raise ArmorError(f"不支持的容器版本 {version}")
    layers = blob[9]
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
        # 盐与 nonce 只作为 prefix 的一部分交给上层，解析阶段不需要单独取值。
        pos += SALT_LEN + NONCE_LEN
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
    note_len = _U32.unpack_from(header, 8 + 2 + SALT_LEN)[0]
    return ArmorInfo(
        version=header[8],
        layers=header[9],
        total_size=len(blob),
        note_size=note_len,
        layer_sizes=tuple(len(ct) for _p, ct, _o, _k in parsed),
        digest=sha256_bytes(blob[-DIGEST_LEN:]),
    )


def read_note(blob: bytes) -> bytes:
    """取出容器里的明文规格草稿（伴生诱饵包会把它归档成「内部资料」）。"""
    header, _parsed = _parse(bytes(blob))
    base = 8 + 2 + SALT_LEN
    length = _U32.unpack_from(header, base)[0]
    return header[base + 4 : base + 4 + length]


def restore_armored(
    blob: bytes,
    password: bytes,
    on_progress: Progress | None = None,
    *,
    parallel: bool = False,
) -> RestoreResult:
    """用口令逐层尝试，返回第一个解开的内容。

    刻意不返回层号、不标注真伪：任何「这层是诱饵」的提示都会让逆向 agent
    少跑好几轮验证。合法用户凭主口令只会解开真层。

    *parallel* 打开时并行派生各层密钥（Argon2 会释放 GIL）。为免 Argon2
    的内存硬特性把机器撑爆，只在低内存档且层数 >1 时生效，并发上限 4；
    否则自动退回串行。无论哪种路径，结果都按层顺序取第一个成功的。
    """
    if not password:
        raise ArmorError("口令不能为空")
    header, parsed = _parse(bytes(blob))

    def attempt(item) -> bytes | None:
        prefix, ct, offset, kdf = item
        mem, time, para, rounds = kdf
        l_salt = prefix[_LAYER_META.size : _LAYER_META.size + SALT_LEN]
        nonce = prefix[_LAYER_META.size + SALT_LEN : _LAYER_META.size + SALT_LEN + NONCE_LEN]
        key = _layer_key(password, l_salt, mem, time, para, rounds)
        aad = header + prefix + _U32.pack(offset)
        return _aead_decrypt(CIPHER_AESGCM, key, nonce, aad, ct)

    def finish(payload: bytes) -> RestoreResult:
        try:
            with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                # entries 只列程序包里的文件：目录条目、尺寸填充和工具清单
                # 都不是用户文件，计数与 GUI「已写出 N 个文件」保持一致。
                entries = []
                for info in zf.infolist():
                    if info.is_dir():
                        continue
                    data = (zf.read(info) if info.comment == b""
                            and info.filename == ".manifest" else None)
                    if not _is_internal(info, data):
                        entries.append(info.filename)
        except zipfile.BadZipFile as exc:
            raise ArmorError("解开的内容不是有效程序包") from exc
        _notify(on_progress, len(parsed), len(parsed), "还原完成")
        return RestoreResult(
            payload=payload,
            sha256=sha256_bytes(payload),
            file_count=len(entries),
            entries=tuple(entries),
        )

    # 内存硬 KDF 并行会把峰值内存乘以并发数，狠档一律走串行。
    heavy = any(kdf[0] > 65536 for *_x, kdf in parsed)
    want_parallel = parallel and len(parsed) > 1 and not heavy
    if want_parallel:
        found: dict[int, bytes] = {}
        workers = min(4, len(parsed))
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = {
                pool.submit(attempt, item): idx
                for idx, item in enumerate(parsed)
            }
            done = 0
            for fut in as_completed(futures):
                done += 1
                _notify(on_progress, done, len(parsed),
                        f"并行尝试层 {done}/{len(parsed)}")
                result = fut.result()
                if result is not None:
                    found[futures[fut]] = result
        if found:
            return finish(found[min(found)])
        raise ArmorError("口令无法解开任何层")

    for i, item in enumerate(parsed, 1):
        _notify(on_progress, i - 1, len(parsed), f"尝试层 {i}/{len(parsed)}")
        payload = attempt(item)
        if payload is not None:
            return finish(payload)
    raise ArmorError("口令无法解开任何层")


def safe_extract(payload: bytes, out_dir: str | Path) -> list[Path]:
    """把还原出的 zip 解到目录，拒绝路径穿越、绝对路径与符号链接。"""
    out = Path(out_dir).resolve()
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        for info in zf.infolist():
            raw = info.filename
            # 安全检查对所有条目生效，包括马上要跳过的内部条目；否则恶意
            # 载荷只要把名字塞进内部前缀就能绕过路径校验。
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
            data = (zf.read(info) if info.comment == b""
                    and raw == ".manifest" else None)
            if _is_internal(info, data):
                continue
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info) as reader, target.open("wb") as writer:
                shutil.copyfileobj(reader, writer, _COPY_CHUNK)
            written.append(target)
    return written
