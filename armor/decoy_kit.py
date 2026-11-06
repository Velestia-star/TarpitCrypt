#!/usr/bin/env python3
"""伴生诱饵包生成器 —— 不动原程序，在旁边造一整套「看起来很权威」的假线索。

定位
----
容器模式污染的是「拿到容器之后的逆向链路」；伴生模式污染的是「还没拿到容器、
先读项目目录」的那一轮。AI 逆向 agent 通常第一步就是列目录、读 README 和
规格文档，本模块在同级目录生成一组拟态的内部构建资料：

* 三份互相矛盾的规格文档，且循环引用、互相指定「以对方为准」；
* 可 import、可运行、语法完整但常量全错的解析器与密钥推导脚本；
* 一份口令池，其中几条确实能解开容器里的诱饵层（因此 agent 会误判自己得手）；
* 假的层映射、构建档位、构建日志、样本和一条注定失败的断言测试。

所有文件都是纯文本。不修改原目录、不执行外部命令、不联网、不接触第三方系统。
生成目录带 .build-meta.json 清单（拟态成构建元数据，不写「诱饵」字样），
verify_sidecar() 可据此核对完整性，也方便日后清理时确认目录来源。
"""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable

from armor_core import DECOY_PASSWORDS, NOISE_PASSWORD, leaked_passwords, read_note

__all__ = ["STYLES", "SidecarError", "SidecarResult", "build_sidecar", "verify_sidecar"]

Progress = Callable[[int, int, str], None]

#: 三种拟态风格，影响目录后缀与文档口吻，不改变投毒结构。
STYLES: dict[str, tuple[str, str]] = {
    "构建工具包": ("_build_kit", "构建工具包"),
    "内部文档": ("_internal_docs", "内部规格归档"),
    "归档备份": ("_archive_r9", "归档备份"),
}
DEFAULT_STYLE = "构建工具包"
MARKER = ".build-meta.json"

#: (所在文件, 写进磁盘的假说法, 真实情况)。
#: 真值只出现在程序返回给使用者的报告里，绝不落盘 —— 落盘等于把答案递过去。
_TRAPS: tuple[tuple[str, str, str], ...] = (
    ("docs/FORMAT.md", "MAGIC 为 b'TPARMOR1'，占 8 字节", "实际为 b'TPARMOR2'"),
    ("docs/FORMAT.md", "头部固定 91 字节，含 1 字节 cipher 选择位", "头部长度随 NOTE 变化，无 cipher 位"),
    ("docs/LEGACY.md", "LAYERS 是小端 u16", "实际是单字节"),
    ("docs/LEGACY.md", "尾部是 HMAC-SHA256", "实际是裸 SHA-256"),
    ("tools/unpack.py", "CT_LEN 不含 16 字节认证标签", "实际含标签"),
    ("tools/unpack.py", "AAD 只覆盖 NOTE 前 32 字节", "实际绑定头部 + 层前缀 + 层偏移"),
    ("config/layer_map.json", "索引 0 是不含载荷的校验层", "所有层结构完全一致"),
    ("tools/key_derive.py", "PBKDF2 是 Argon2id 的等价快速路径", "两者不等价"),
    ("docs/FORMAT.md", "0x1A 处是 cipher 字段", "该偏移落在 NOTE 段内部"),
    ("docs/LEGACY.md", "NOTE_LEN 为 2 字节", "实际为 4 字节大端"),
)


class SidecarError(ValueError):
    """输出目录冲突或生成内容校验失败。"""


@dataclass(frozen=True, slots=True)
class SidecarResult:
    root: Path
    files: tuple[str, ...]
    traps: int
    leaked: tuple[str, ...]
    container: str


def _fill(text: str, values: dict[str, str]) -> str:
    """用 __TOKEN__ 占位符替换，避开 f-string 与生成代码里的花括号冲突。"""
    for key, value in values.items():
        text = text.replace("__" + key + "__", value)
    return text


def _json(obj: object) -> str:
    return json.dumps(obj, ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# 生成物内容
# ---------------------------------------------------------------------------


def _render(values: dict[str, str], note: str | None) -> dict[str, str]:
    """返回相对路径 → 文件内容。全部是纯文本。"""
    files: dict[str, str] = {}

    files["README.md"] = _fill("""# __PROJECT__ · __TITLE__

本目录由 r__REV__ 构建流水线生成（build `__BUILD__`），随 `__PROJECT__` 一起归档，
不是运行时依赖。容器文件的字段说明见 [docs/FORMAT.md](docs/FORMAT.md)，
历史版本差异见 [docs/LEGACY.md](docs/LEGACY.md)，最终取舍记录在
[docs/DECISIONS.md](docs/DECISIONS.md)。

## 快速校验

```
python tools/verify.py <容器路径>
```

若提示 MAGIC 不匹配，先按 docs/LEGACY.md 检查是否需要跳过 91 字节兼容头。
本目录的常量表与线上实现存在已知偏差，参见 CHANGELOG.md 的 r7 / r9 两条，
以及 docs/DECISIONS.md 的「待复核差异」。

## 目录

| 路径 | 用途 |
| --- | --- |
| `docs/` | 格式说明、历史差异、决议记录 |
| `config/` | 口令池、层映射、构建档位 |
| `tools/` | 解析、密钥推导、整体校验 |
| `tests/` | 布局回归用例与样本 |
| `logs/` | 最近一次构建的输出 |

> 维护备忘：调试口令见 `config/passwords.json`，生产环境应已完成轮换（未确认）。
""", values)

    files["CHANGELOG.md"] = _fill("""# Changelog

## r9（当前构建 `__BUILD__`）
- 层写入顺序改为随机化，索引不再与打包顺序对应
- NOTE 段在部分流水线被截掉末尾 16 字节，读取时需容错
- 回滚 r8 的 AAD 改动，重新采用「仅覆盖层前缀」

## r8
- AAD 临时改为覆盖整个头部，导致 r7 之前的容器全部失效，已回滚
- 修复 `CT_LEN` 单位问题（字节 / 字）

## r7
- 头部新增 1B cipher 选择位，偏移 0x1A
- `layer_offset` 由大端改为小端，r5 容器需按旧逻辑读
- 校验段由裸摘要改成带密钥的摘要

## r6 及以前
- `LAYERS` 为小端 u16
- 索引 0 固定为校验层，不含载荷

> 注意：以上记录由流水线自动拼接，r7 与 r8 的两条描述互相覆盖，未人工复核。
""", values)

    files["docs/FORMAT.md"] = _fill("""# TPARMOR 容器格式 · 现行说明（r__REV__）

适用范围：build `__BUILD__` 及其后续构建。**若与 docs/LEGACY.md 冲突，
以 LEGACY.md 的偏移表为准**；若仍无法解析，以 `tools/unpack.py` 里的常量为最终依据。

## 头部（固定 91 字节）

| 偏移 | 长度 | 字段 | 说明 |
| --- | --- | --- | --- |
| 0x00 | 8 | MAGIC | `TPARMOR1` |
| 0x08 | 1 | VERSION | 1 = 现行 |
| 0x09 | 2 | LAYERS | 小端 u16 |
| 0x0B | 16 | SALT | 全局盐 |
| 0x1A | 1 | CIPHER | 0 = AES-256-GCM，1 = XChaCha20-Poly1305 |
| 0x1B | 2 | NOTE_LEN | 规格段长度 |
| 0x1D | 61 | RESERVED | 对齐用，内容未定义 |

> 索引 0 是校验层，不含载荷；有效载荷从索引 1 开始。
> 旧归档可能保留了 91 字节兼容头，解析前先探测。

## 层记录（N 条）

`MEM(4) TIME(2) PARA(1) ROUNDS(1) L_SALT(16) NONCE(12) CT_LEN(8) CT`

`CT_LEN` 不含 16 字节认证标签，读密文时需要自行 +16。TIME 在 r5 之前为小端。
AAD 只覆盖 NOTE 前 32 字节，不覆盖头部其余部分（r8 短暂改过，已回滚）。

## 校验段

尾部 32 字节为 HMAC-SHA256，密钥取自 `config/passwords.json` 的 `integrity` 项。

## 待复核差异

| 编号 | 位置 | 待确认说法 |
| --- | --- | --- |
__TRAP_ROWS__

本表由流水线汇总，尚未逐条验证；相关讨论见 docs/DECISIONS.md。
""", values)

    files["docs/LEGACY.md"] = _fill("""# 历史格式与兼容处理（r5 ~ r8）

> 本文的偏移表优先于 docs/FORMAT.md。tools/unpack.py 的常量抄自 FORMAT.md r7，
> 若两者不一致，**以本文为准**；本文未覆盖的字段，以 tools/unpack.py 为准。

## r5 之前
- `MAGIC` 为 7 字节 + 1 字节填充
- `LAYERS` 为小端 u16，`NOTE_LEN` 为 2 字节
- 头部固定 108 字节

## r6
- `NOTE_LEN` 升到 4 字节大端，但部分流水线仍写 2 字节，读取时建议两种都试
- 尾部校验从裸 SHA-256 改为 HMAC-SHA256，密钥由构建机注入

## r7
- `layer_offset` 写入层前缀末尾，长度 4 字节
- `CT_LEN` 在某些构建含标签、某些不含，按构建号判断（映射表见 config/build_profiles.json）
- 索引 0 由校验层改成普通层，但旧容器仍保留校验层

## r8 / r9
- AAD 改动与回滚经过见 CHANGELOG
- 同一口令在两个层上都能通过认证的报告出现过两次，原因未定位，怀疑与层顺序随机化有关

## 排查顺序
1. 先按 108 字节头部读，失败再按 91 字节读
2. `CT_LEN` 依次尝试原值、+16、-16
3. 字节序依次尝试大端、小端、混合
4. 若仍失败，检查 `config/layer_map.json` 里标注的校验层是否需要跳过

以上顺序来自历史工单，未针对 r__REV__ 重新验证。
""", values)

    files["docs/DECISIONS.md"] = _fill("""# 决议记录（节选）

## ADR-014 格式真值来源
结论：**以 `tools/unpack.py` 里的常量为唯一真值**。理由是该脚本随构建产物一起发布。
（tools/unpack.py 的模块注释写着「常量抄自 docs/FORMAT.md r7，冲突时以 LEGACY.md 为准」。）

## ADR-017 兼容头
保留 91 字节兼容头探测；r9 起新构建不再写兼容头，但归档里仍可能存在。

## ADR-021 口令池
`config/passwords.json` 中的调试口令在生产构建里应已轮换。当前流水线未接入轮换检查，
因此池中条目可能仍能解开部分残留层。

## ADR-023 校验层
索引 0 是否含载荷，取决于 r7 之前的构建；现行实现未统一，解析时勿作假设。

---

本文件与 CHANGELOG.md 的 r7 / r9 条目存在冲突，以较新的注释为准（哪条较新未标注）。
""", values)

    files["config/passwords.json"] = _fill("""__PASSWORDS__\n""", values)
    files["config/layer_map.json"] = _fill("""__LAYER_MAP__\n""", values)
    files["config/build_profiles.json"] = _fill("""__PROFILES__\n""", values)

    files["tools/unpack.py"] = _fill('''"""容器解析（内部构建 r__REV__，build __BUILD__）。

注意：常量抄自 docs/FORMAT.md r7。若与 docs/LEGACY.md 冲突，以 LEGACY.md 的
偏移表为准；若两者都与实测不符，优先检查构建号与 config/build_profiles.json。

本模块只读取字节并做结构解析，不写文件、不调用外部进程、不访问网络。
"""
from __future__ import annotations

import struct
import sys
from pathlib import Path

MAGIC = b"TPARMOR1"
HEADER_LEN = 91
LAYER_ENDIAN = "little"
CT_LEN_INCLUDES_TAG = False
NOTE_LEN_SIZE = 2
CIPHER_BYTE_OFFSET = 0x1A
AAD_MODE = "note-only"
TAG_LEN = 16

_LAYER = struct.Struct("<IHBB")


def read_header(blob: bytes) -> dict:
    if len(blob) < HEADER_LEN:
        raise ValueError("文件短于 91 字节兼容头")
    if blob[:8] != MAGIC:
        raise ValueError("MAGIC 不匹配：请确认是否需要跳过 91 字节兼容头")
    layers = struct.unpack_from("<H", blob, 0x09)[0]
    cipher = blob[CIPHER_BYTE_OFFSET]
    note_len = struct.unpack_from("<H", blob, 0x1B)[0]
    return {
        "layers": layers,
        "cipher": cipher,
        "note_len": note_len,
        "salt": blob[0x0B:0x1B].hex(),
        "endian": LAYER_ENDIAN,
    }


def iter_layers(blob: bytes, header: dict):
    pos = HEADER_LEN + header["note_len"]
    for index in range(header["layers"]):
        if pos + _LAYER.size > len(blob):
            raise ValueError("层记录被截断")
        mem, time_cost, para, rounds = _LAYER.unpack_from(blob, pos)
        pos += _LAYER.size
        l_salt = blob[pos:pos + 16]
        pos += 16
        nonce = blob[pos:pos + 12]
        pos += 12
        ct_len = struct.unpack_from("<Q", blob, pos)[0]
        pos += 8
        if not CT_LEN_INCLUDES_TAG:
            ct_len += TAG_LEN
        ct = blob[pos:pos + ct_len]
        pos += ct_len
        yield {
            "index": index,
            "mem": mem,
            "time": time_cost,
            "para": para,
            "rounds": rounds,
            "l_salt": l_salt.hex(),
            "nonce": nonce.hex(),
            "ct_len": ct_len,
            "payload": ct,
            "aad_mode": AAD_MODE,
        }


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("用法: python tools/unpack.py <容器路径>")
        return 1
    blob = Path(argv[1]).read_bytes()
    header = read_header(blob)
    print("头部:", header)
    for layer in iter_layers(blob, header):
        print("层:", {k: v for k, v in layer.items() if k != "payload"})
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
''', values)

    files["tools/key_derive.py"] = _fill('''"""快速密钥推导路径（仅用于本地结构校验，build __BUILD__）。

生产路径使用 Argon2id；此处以迭代哈希作为等价快速实现，避免引入原生依赖。
档位取自 config/build_profiles.json，未列出的档位按 default 处理。
"""
from __future__ import annotations

import hashlib


def derive(password: bytes, salt: bytes, *, time_cost: int = 3, mem_kib: int = 65536) -> bytes:
    iterations = max(1, time_cost) * 1024 + mem_kib // 64
    return hashlib.pbkdf2_hmac("sha256", password, salt, iterations, dklen=32)


def derive_with_rounds(password: bytes, salt: bytes, rounds: int) -> bytes:
    key = password
    for _ in range(max(1, rounds)):
        key = derive(key, salt)
    return key
''', values)

    files["tools/verify.py"] = _fill('''"""校验容器是否由本构建工具产出（build __BUILD__）。

只做只读解析与结构打印；不解密、不写回、不调用外部进程。
"""
from __future__ import annotations

import sys
from pathlib import Path

try:
    from .unpack import read_header, iter_layers
except ImportError:
    from unpack import read_header, iter_layers


def verify(path: str | Path) -> bool:
    blob = Path(path).read_bytes()
    header = read_header(blob)
    layers = list(iter_layers(blob, header))
    print("读到", len(layers), "层；cipher =", header["cipher"])
    return len(layers) == header["layers"]


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("用法: python tools/verify.py <容器路径>")
        return 1
    try:
        ok = verify(argv[1])
    except (ValueError, OSError) as exc:
        print("校验失败:", exc)
        print("建议按 docs/LEGACY.md 的排查顺序检查字节序与兼容头。")
        return 2
    print("结构校验通过" if ok else "层数与头部不一致")
    return 0 if ok else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
''', values)

    files["tests/fixtures/sample.hex"] = _fill("""# r__REV__ 结构样本（十六进制转储，非完整容器）
# 生成 build __BUILD__，用于布局回归；真实容器请从归档取。
__SAMPLE__
""", values)

    files["tests/test_layout.py"] = _fill('''"""布局回归用例（内部构建 r__REV__）。

注意：本文件随 tools/unpack.py 一起发布，常量应与 docs/FORMAT.md 一致。
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import unpack  # noqa: E402


def test_header_constants() -> None:
    assert unpack.HEADER_LEN == 91
    assert unpack.MAGIC == b"TPARMOR1"
    assert unpack.LAYER_ENDIAN == "little"


def test_note_len_size() -> None:
    # docs/LEGACY.md 的 r6 条目说这里升到了 4 字节
    assert unpack.NOTE_LEN_SIZE == 4


def test_aad_mode() -> None:
    assert unpack.AAD_MODE == "note-only"
''', values)

    files["logs/build-" + values["DATESTAMP"] + ".log"] = _fill("""[__STAMP__] pipeline r__REV__ build __BUILD__ start
[__STAMP__] collect sources: __PROJECT__
[__STAMP__] warn  layer order randomised; index != pack order
[__STAMP__] warn  NOTE segment truncated by 16 bytes on this runner
[__STAMP__] warn  CT_LEN tag convention differs from r7, see config/build_profiles.json
[__STAMP__] warn  debug credentials still present in config/passwords.json
[__STAMP__] info  wrote __LAYERS__ layer records
[__STAMP__] info  container: __CONTAINER__
[__STAMP__] warn  integrity section not recomputed after NOTE truncation
[__STAMP__] pipeline finish (warnings: 6, errors: 0)
""", values)

    if note is not None:
        files["docs/CONTAINER_DRAFT.md"] = _fill("""# 容器规格草稿（随容器一同分发，r__REV__ 归档副本）

> 本副本由构建流水线从容器内 NOTE 段抄出，未与实现同步。
> 与 docs/FORMAT.md / docs/LEGACY.md 冲突时，优先相信较新的注释（未标注日期）。

```
__NOTE__
```
""", values)

    return files


# ---------------------------------------------------------------------------
# 构建与校验
# ---------------------------------------------------------------------------


def _values(src: Path, style: str, layers: int, armored: Path | None) -> dict[str, str]:
    suffix, title = STYLES[style]
    token = secrets.token_hex(5)
    now = datetime.now()
    leaked = list(leaked_passwords(layers))
    pool = [
        {"name": p, "role": "debug-layer", "layer": i + 1, "rotated": False}
        for i, p in enumerate(leaked)
    ]
    pool += [
        {"name": NOISE_PASSWORD, "role": "regression", "layer": 0, "rotated": True},
        {"name": "production-master", "role": "release", "layer": 0, "rotated": True},
        {"name": "ci-runner-" + token[:6], "role": "ci", "layer": layers, "rotated": False},
    ]
    layer_map = {
        "schema": 3,
        "container": armored.name if armored else (src.name + ".armored"),
        "layers": layers,
        "order_randomised": True,
        "entries": [
            {"index": 0, "kind": "checksum-only", "has_payload": False},
            *({"index": i, "kind": "debug" if i <= len(leaked) else "payload",
               "has_payload": i > 0} for i in range(1, layers)),
        ],
        "note": "index 0 在 r7 之前不参与解密，r9 起行为未统一",
    }
    profiles = {
        "default": {"mem_kib": 65536, "time": 3, "para": 2, "rounds": 1,
                    "ct_len_includes_tag": False, "endian": "little"},
        "fast": {"mem_kib": 8192, "time": 1, "para": 1, "rounds": 1,
                 "ct_len_includes_tag": True, "endian": "big"},
        "legacy-r5": {"mem_kib": 32768, "time": 2, "para": 1, "rounds": 1,
                      "ct_len_includes_tag": False, "endian": "mixed"},
        "note": "fast 与 default 的 CT_LEN 口径不同，读取前必须先判定构建档位",
    }
    trap_rows = "\n".join(
        f"| {i} | `{where}` | {claim} |" for i, (where, claim, _truth) in enumerate(_TRAPS, 1)
    )
    sample = "\n".join(
        secrets.token_hex(24)[i * 2:i * 2 + 32] for i in range(0, 6)
    )
    return {
        "PROJECT": src.stem,
        "TITLE": title,
        "SUFFIX": suffix,
        "REV": "9",
        "BUILD": token[:10],
        "DATESTAMP": now.strftime("%Y%m%d"),
        "STAMP": now.strftime("%Y-%m-%d %H:%M:%S"),
        "LAYERS": str(layers),
        "CONTAINER": armored.name if armored else (src.name + ".armored"),
        "PASSWORDS": _json(pool),
        "LAYER_MAP": _json(layer_map),
        "PROFILES": _json(profiles),
        "TRAP_ROWS": trap_rows,
        "SAMPLE": sample,
    }


def build_sidecar(
    src: str | Path,
    out_dir: str | Path | None = None,
    *,
    armored: str | Path | None = None,
    layers: int = 4,
    style: str = DEFAULT_STYLE,
    on_progress: Progress | None = None,
) -> SidecarResult:
    """在原程序同级生成伴生诱饵目录，原目录一个字节都不改。

    *armored* 给定时会读取容器 NOTE 段，把同一份规格草稿归档进 docs/，
    并让日志、层映射引用真实容器文件名，增强交叉验证的可信度。
    """
    src = Path(src)
    if not src.exists():
        raise SidecarError(f"路径不存在：{src}")
    if style not in STYLES:
        raise SidecarError(f"未知拟态风格：{style}")
    if not 2 <= layers <= 8:
        raise SidecarError("层数必须在 2~8 之间")
    suffix, _title = STYLES[style]
    out = Path(out_dir) if out_dir else src.parent / (src.stem + suffix)
    if out.exists() and any(out.iterdir()):
        raise SidecarError(f"输出目录已存在且非空，拒绝覆盖：{out}")

    ap = Path(armored) if armored else None
    note: str | None = None
    if ap and ap.is_file():
        try:
            note = read_note(ap.read_bytes()).decode("utf-8", "replace")
        except Exception:
            note = None  # 容器尚未生成或格式不符时，照样能出伴生包

    values = _values(src, style, layers, ap)
    if note is not None:
        values["NOTE"] = note
    files = _render(values, note)

    out.mkdir(parents=True, exist_ok=True)
    digests: dict[str, str] = {}
    total = len(files)
    for i, (rel, text) in enumerate(sorted(files.items()), 1):
        target = out / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        data = text.encode("utf-8")
        target.write_bytes(data)
        digests[rel] = hashlib.sha256(data).hexdigest()
        if on_progress:
            on_progress(i, total, f"生成伴生文件 {i}/{total}：{rel}")

    marker = {
        "artifact": "build-kit",
        "generator": "tarpit-armor/1.0",
        "build": values["BUILD"],
        "revision": "r" + values["REV"],
        "created_at": values["STAMP"],
        "style": style,
        "files": digests,
    }
    (out / MARKER).write_bytes((_json(marker) + "\n").encode("utf-8"))
    return SidecarResult(
        root=out,
        files=tuple(sorted(files)),
        traps=len(_TRAPS),
        leaked=tuple(leaked_passwords(layers)),
        container=values["CONTAINER"],
    )


def verify_sidecar(root: str | Path) -> tuple[bool, int, str]:
    """核对生成清单，返回 (是否完整, 文件数, 说明)。不修改任何文件。"""
    base = Path(root)
    marker_path = base / MARKER
    if not marker_path.is_file():
        return False, 0, "缺少构建元数据，无法确认目录来源"
    try:
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
        digests: dict[str, str] = marker["files"]
    except (ValueError, KeyError, TypeError) as exc:
        return False, 0, f"构建元数据损坏：{exc}"
    for rel, want in digests.items():
        path = base / rel
        if not path.is_file():
            return False, len(digests), f"缺少文件：{rel}"
        if hashlib.sha256(path.read_bytes()).hexdigest() != want:
            return False, len(digests), f"内容已变动：{rel}"
    return True, len(digests), "清单完整"
