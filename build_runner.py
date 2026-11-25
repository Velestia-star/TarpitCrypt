#!/usr/bin/env python3
"""构建通用运行时启动器 RTPK_Runner.exe（只需构建一次）。

优先构建原生 Go 启动器（无 Python 依赖、启动更快、无 .pyc 可读）；
找不到 Go 工具链时回退到 PyInstaller。

用法：
    python build_runner.py

产物： dist/RTPK_Runner.exe
之后在 GUI「陷阱设置」的“通用启动器”一栏选中它，即可秒级生成任意多个
加固 exe（每个程序包只是把陷阱容器追加到这个 runner 尾部，不需要重新构建）。
"""

from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
NAME = "RTPK_Runner"


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


def _build_native() -> int | None:
    go = _find_go()
    if not go:
        return None
    native_dir = HERE / "native"
    if not native_dir.is_dir():
        return None
    target = HERE / "dist" / (NAME + ".exe")
    target.parent.mkdir(parents=True, exist_ok=True)
    cmd = [
        go, "build", "-trimpath",
        "-ldflags", "-s -w -H=windowsgui",
        "-o", str(target), ".",
    ]
    print("执行：", " ".join(cmd))
    result = subprocess.run(cmd, cwd=str(native_dir), check=False)
    if result.returncode:
        print(f"原生启动器构建失败，退出码 {result.returncode}，回退 PyInstaller")
        return result.returncode
    print(f"完成（原生）：{target}（{target.stat().st_size:,} 字节）")
    return 0


def main() -> int:
    native = _build_native()
    if native == 0:
        print("在 GUI「陷阱设置」的“通用启动器”一栏选中它。")
        return 0

    if importlib.util.find_spec("PyInstaller") is None:
        print("缺少 Go 工具链，且缺少 PyInstaller。请安装 Go，或执行：")
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
        "--hidden-import", "trap_guard",
        "--hidden-import", "argon2.low_level",
        "--hidden-import", "cryptography.hazmat.primitives.ciphers.aead",
        "--hidden-import", "cryptography.hazmat.primitives.kdf.hkdf",
        "--hidden-import", "cryptography.hazmat.primitives.hashes",
        "--exclude-module", "tkinter",
        "--exclude-module", "_tkinter",
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
    print(f"完成（PyInstaller 回退）：{target}（{target.stat().st_size:,} 字节）")
    print("在 GUI「陷阱设置」的“通用启动器”一栏选中它。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
