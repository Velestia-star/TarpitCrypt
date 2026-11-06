#!/usr/bin/env python3
"""把 GUI 打成免装 Python 的 Windows 可执行文件（可选能力）。

本机没预装 PyInstaller 也能看这份脚本；真正打包前先：

    pip install pyinstaller argon2-cffi cryptography
    python build_exe.py            # 单文件，dist/TarpitCryptArmor.exe
    python build_exe.py --onedir   # 目录版，启动更快、便于排查

要点
----
* ``tarpitcrypt.py`` 在仓库根目录，冻结后 ``armor_core`` 的「回上级找模块」
  逻辑不再适用，因此用 ``--paths`` 把根目录加进搜索路径，并显式声明
  ``--hidden-import``，让 PyInstaller 把 v1 核心一起打进去。
* ``--windowed`` 用 pythonw，不弹控制台；调试时可去掉该参数看 traceback。
* 打包产物不会包含任何容器、口令或样例程序包。

注意：打出来的 exe 仍只做「信息误导」，不注入、不联网、不改动原程序。
"""

from __future__ import annotations

import argparse
import importlib.util
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
APP_NAME = "TarpitCryptArmor"

HIDDEN = (
    "tarpitcrypt", "armor_core", "armor_metrics", "decoy_kit",
    "argon2.low_level", "cryptography.hazmat.primitives.ciphers.aead",
)


def build(onedir: bool = False, clean: bool = False) -> int:
    if importlib.util.find_spec("PyInstaller") is None:
        print("缺少 PyInstaller。请先执行：")
        print("    pip install pyinstaller argon2-cffi cryptography")
        return 2
    if not (ROOT / "tarpitcrypt.py").is_file():
        print(f"未在仓库根目录找到 tarpitcrypt.py：{ROOT}")
        print("若在桌面独立副本里打包，请把 tarpitcrypt.py 放在本脚本的上级目录，")
        print("或改用与 armor_core.py 同目录的布局。")
        return 2

    if clean:
        for name in ("build", "dist"):
            shutil.rmtree(HERE / name, ignore_errors=True)

    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--noconfirm", "--windowed", "--clean",
        "--name", APP_NAME,
        "--distpath", str(HERE / "dist"),
        "--workpath", str(HERE / "build"),
        "--specpath", str(HERE),
        "--paths", str(ROOT),
        "--paths", str(HERE),
    ]
    cmd += ["--onedir" if onedir else "--onefile"]
    for mod in HIDDEN:
        cmd += ["--hidden-import", mod]
    cmd.append(str(HERE / "armor_gui.py"))

    print("执行：", " ".join(cmd))
    result = subprocess.run(cmd, cwd=str(HERE), check=False)
    if result.returncode:
        print(f"打包失败，退出码 {result.returncode}")
        return result.returncode
    target = HERE / "dist" / (APP_NAME if onedir else APP_NAME + ".exe")
    print(f"完成：{target}")
    print("首次运行若被安全软件拦截，请改用「运行自测.bat」走源码方式。")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="打包 TarpitCrypt Armor GUI")
    ap.add_argument("--onedir", action="store_true", help="产出目录版而非单文件")
    ap.add_argument("--clean", action="store_true", help="先清掉 build/ 与 dist/")
    args = ap.parse_args(argv)
    return build(onedir=args.onedir, clean=args.clean)


if __name__ == "__main__":
    raise SystemExit(main())
