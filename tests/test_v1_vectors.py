"""v1 文件格式兼容回归：只读固定样本，绝不用当前代码重新加密。

这些样本由 tests/generate_vectors.py 事先生成并入库，代表「已经发出去的
旧 .tarpit 文件」。本文件只调用 decrypt，不调用 encrypt —— 这样一旦有人
改动 AAD 组成、头部布局或诱饵段顺序，测试就会红，而不是跟着一起改、全绿。

刻意不在本文件里生成样本：那会退化成「当前代码解当前代码」的自洽测试。
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(ROOT))

import tarpitcrypt as tc  # noqa: E402

MANIFEST = json.loads((FIX / "vectors.json").read_text(encoding="utf-8"))
NAMES = list(MANIFEST["vectors"])


def _load(name: str) -> tuple[bytes, dict]:
    entry = MANIFEST["vectors"][name]
    blob = (FIX / entry["file"]).read_bytes()
    return blob, entry


def test_manifest_format_version_is_frozen() -> None:
    """格式版本若升到 2，必须提供迁移脚本，而不是悄悄改样本。"""
    assert MANIFEST["format_version"] == 1
    assert tc.VERSION == 1
    assert len(NAMES) >= 4


@pytest.mark.parametrize("name", NAMES)
def test_fixed_vector_bytes_unchanged(name: str) -> None:
    blob, entry = _load(name)
    assert len(blob) == entry["size"]
    assert hashlib.sha256(blob).hexdigest() == entry["sha256"]


@pytest.mark.parametrize("name", NAMES)
def test_fixed_vector_decrypts(name: str) -> None:
    blob, entry = _load(name)
    keyfile = bytes.fromhex(entry["keyfile_hex"]) if "keyfile_hex" in entry else None
    plaintext, is_decoy = tc.decrypt(blob, entry["password"].encode("utf-8"),
                                     keyfile=keyfile)
    assert plaintext == bytes.fromhex(entry["expected_plaintext_hex"])
    assert is_decoy is False


@pytest.mark.parametrize("name", NAMES)
def test_wrong_password_rejected(name: str) -> None:
    blob, entry = _load(name)
    keyfile = bytes.fromhex(entry["keyfile_hex"]) if "keyfile_hex" in entry else None
    with pytest.raises(ValueError):
        tc.decrypt(blob, b"definitely-not-the-password", keyfile=keyfile)


def test_keyfile_is_required_when_flagged() -> None:
    """少了 keyfile 不能靠主口令蒙混过关。"""
    blob, entry = _load("v1_keyfile")
    with pytest.raises(ValueError):
        tc.decrypt(blob, entry["password"].encode("utf-8"), keyfile=None)


def test_decoy_layer_layout_still_matches() -> None:
    blob, entry = _load("v1_decoy")
    plaintext, is_decoy = tc.decrypt(blob, entry["decoy_password"].encode("utf-8"))
    assert is_decoy is True
    assert plaintext == bytes.fromhex(entry["decoy_plaintext_hex"])


@pytest.mark.parametrize("name", NAMES)
def test_header_still_parses(name: str) -> None:
    """固定样本的 91 字节头部必须仍能按 v1 布局读出来。"""
    blob, _entry = _load(name)
    header = tc._parse_header(blob)
    assert blob[:8] == tc.MAGIC
    assert blob[8] == tc.VERSION == 1
    assert len(header.raw) == tc.HEADER_LEN
    assert header.raw == blob[:tc.HEADER_LEN]
