"""控制台编码回归测试。

背景：GitHub 的英文 Windows runner 控制台是 cp1252，脚本里一句中文 ``print``
就会抛 ``UnicodeEncodeError``。Python 3.15 起默认 UTF-8 模式（PEP 686），
本地开发机上永远复现不了，所以必须用子进程强制降级编码来验证。

这两条测试保证：即使在非 UTF-8 控制台上，CLI 也能正常输出中文、正常返回退出码。
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
SCRIPT = REPO / "tarpitcrypt.py"


def _run(args: list[str], env: dict[str, str], stdin: str = "") -> subprocess.CompletedProcess[str]:
    """用指定编码环境跑一次 CLI，统一按 UTF-8 解码输出。"""
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        input=stdin,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=180,
    )


@pytest.mark.parametrize("encoding", ["cp1252", "cp936", "ascii"])
def test_cli_survives_non_utf8_console(tmp_path: Path, encoding: str) -> None:
    """非 UTF-8 控制台下，加密仍然成功且中文提示不炸。"""
    env = {**os.environ, "PYTHONUTF8": "0", "PYTHONIOENCODING": encoding}
    source = tmp_path / "note.txt"
    source.write_bytes("中文样例 payload".encode("utf-8"))
    target = tmp_path / "note.tarpit"

    result = _run(
        ["encrypt", str(source), str(target), "--password-stdin",
         "--mem", "8192", "--time", "1", "--para", "1", "--rounds", "1"],
        env,
        stdin="pw\n",
    )

    assert result.returncode == 0, f"stderr={result.stderr[-600:]}"
    assert target.exists() and target.read_bytes()[:8] == b"TARPITCR"
    assert "已加密" in result.stdout


@pytest.mark.parametrize("encoding", ["cp1252", "cp936"])
def test_cli_error_messages_survive_non_utf8_console(tmp_path: Path, encoding: str) -> None:
    """错误路径同样不能因为编码崩掉：文件不存在要干净地返回退出码 4。"""
    env = {**os.environ, "PYTHONUTF8": "0", "PYTHONIOENCODING": encoding}
    result = _run(
        ["decrypt", str(tmp_path / "missing.tarpit"), str(tmp_path / "out.bin"), "--password-stdin"],
        env,
        stdin="pw\n",
    )

    assert result.returncode == 4
    assert "环境错误" in result.stderr
