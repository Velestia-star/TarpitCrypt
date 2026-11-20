#!/usr/bin/env python3
"""RTPK 单文件启动器：被 PyInstaller 打包后，尾部注入加密程序包即可分发。

双击运行流程
------------
1. 从自身尾部读出 RTPK 包（runtime_pack.read_embedded）
2. 口令模式弹 tkinter 输入框；免密模式直接进入
3. Argon2id 派生 + AES-GCM 解密到内存
4. 安全解压到临时目录
5. 启动清单指定的入口程序，等待其退出
6. 覆写擦除临时目录

安全边界见 runtime_pack.py 模块文档。调试时可设 RTPK_DEBUG=1 保留临时目录，
或 RTPK_PASSWORD 预填口令（仅供自动化测试，不写入分发包）。
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, simpledialog

# 冻结后模块随包打入；源码直跑时把同目录加进路径
sys.path.insert(0, str(Path(__file__).resolve().parent))
import runtime_pack as rp  # noqa: E402


def _ask_password(title: str = "运行时加固 · 请输入口令") -> str | None:
    env = os.environ.get("RTPK_PASSWORD")
    if env:
        return env
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    try:
        pw = simpledialog.askstring(title, "口令：", show="*", parent=root)
    finally:
        root.destroy()
    return pw


def _fatal(text: str) -> None:
    try:
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        messagebox.showerror("无法启动", text, parent=root)
        root.destroy()
    except Exception:
        print(f"无法启动：{text}", file=sys.stderr)


def main() -> int:
    try:
        exe = Path(sys.executable if getattr(sys, "frozen", False) else __file__)
        blob = rp.read_embedded(exe)
        info = rp.parse_pack(blob)
        pw = None
        if info["password_required"]:
            pw = _ask_password()
            if not pw:
                return 1
        plain, manifest = rp.decrypt_pack(blob, pw)
    except rp.RuntimePackError as exc:
        _fatal(str(exc))
        return 2
    except Exception as exc:  # 依赖缺失等意外
        _fatal(f"启动器异常：{exc}")
        return 3

    tmp = Path(tempfile.mkdtemp(prefix="rtpk_"))
    try:
        rp.safe_extract(plain, tmp)
        entry = tmp / manifest.entry
        if not entry.exists():
            raise rp.RuntimePackError(f"入口文件缺失：{manifest.entry}")
        proc = subprocess.Popen([str(entry)], cwd=str(entry.parent))
        return proc.wait()
    except Exception as exc:
        _fatal(f"运行失败：{exc}")
        return 4
    finally:
        if os.environ.get("RTPK_DEBUG") == "1":
            print(f"[RTPK_DEBUG] 保留临时目录：{tmp}")
        else:
            rp.wipe_dir(tmp)


if __name__ == "__main__":
    raise SystemExit(main())
