"""回归：keygen 不能静默覆盖已有 keyfile。

早期版本用 Path.write_bytes，连跑两次就会换掉旧文件；而 README 又反复强调
「keyfile 丢了数据永久没了」，工具自己提供了最省事的丢法。现在改为
os.open(O_CREAT | O_EXCL)，第二次应报错且原文件字节不变。
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import tarpitcrypt as tc  # noqa: E402


def test_keygen_refuses_to_overwrite(tmp_path: Path) -> None:
    target = tmp_path / "once.key"
    assert tc.main(["keygen", str(target)]) == tc.EXIT_OK
    first = target.read_bytes()
    assert len(first) == tc.KEYFILE_HINT_LEN

    code = tc.main(["keygen", str(target)])
    assert code == tc.EXIT_USAGE
    assert target.read_bytes() == first, "旧 keyfile 被改动了"


def test_keygen_creates_new_file(tmp_path: Path) -> None:
    target = tmp_path / "fresh.key"
    assert tc.main(["keygen", str(target)]) == tc.EXIT_OK
    assert target.is_file()
    assert target.read_bytes() != bytes(tc.KEYFILE_HINT_LEN)


@pytest.mark.parametrize("name", ["a.key", "b.key"])
def test_keygen_outputs_are_independent(tmp_path: Path, name: str) -> None:
    assert tc.main(["keygen", str(tmp_path / name)]) == tc.EXIT_OK
