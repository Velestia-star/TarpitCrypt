#!/usr/bin/env python3
"""构建通用运行时启动器 RTPK_Runner.exe（只需构建一次）。

用法：
    python build_runner.py

产物： armor/dist/RTPK_Runner.exe
之后在 GUI「运行时加固」页选中它，即可秒级生成任意多个加密 exe
（每个程序包只是把加密数据追加到这个 runner 尾部，不需要重新 PyInstaller）。
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAME = "RTPK_Runner"


def main() -> int:
    if importlib.util.find_spec("PyInstaller") is None:
        print("缺少 PyInstaller。请先执行：")
        print("    python -m pip install pyinstaller")
        return 2
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--clean", "--windowed", "--onefile",
        "--name", NAME,
        "--distpath", str(HERE / "dist"),
        "--workpath", str(HERE / "build_rtpk"),
        "--specpath", str(HERE),
        "--paths", str(HERE),
        "--hidden-import", "runtime_pack",
        "--hidden-import", "argon2.low_level",
        "--hidden-import", "cryptography.hazmat.primitives.ciphers.aead",
        str(HERE / "runtime_runner.py"),
    ]
    print("执行：", " ".join(cmd))
    result = subprocess.run(cmd, cwd=str(HERE), check=False)
    if result.returncode:
        print(f"启动器构建失败，退出码 {result.returncode}")
        return result.returncode
    # 清掉中间产物，只保留 exe
    shutil.rmtree(HERE / "build_rtpk", ignore_errors=True)
    (HERE / (NAME + ".spec")).unlink(missing_ok=True)
    target = HERE / "dist" / (NAME + ".exe")
    print(f"完成：{target}（{target.stat().st_size:,} 字节）")
    print("在 GUI「运行时加固」页的“启动器”一栏选中它。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
