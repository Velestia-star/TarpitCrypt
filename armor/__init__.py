#!/usr/bin/env python3
"""TarpitCrypt Armor · 程序包加固工具集（Python 子包）。

目录内模块历史上以顶层名互相导入（``import armor_core``、
``from armor_metrics import ...``），并在各自文件开头用 ``sys.path.insert``
把本目录登记进搜索路径，以便 ``python armor/selftest.py`` 这类脚本直跑。

这里统一补一次路径登记，让包式导入同样能解析同目录模块：
``import armor.armor_gui``、``python -m armor.runtime_check``，以及
pip 安装后的控制台入口。目录内模块的导入语句因此无需改写。

刻意不在导入时加载任何子模块：加固逻辑会读文件、起线程、做加密，
导入包本身不应该带这些副作用。
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

# 与 armor/armor_core.py 的 __version__ 保持一致；发版时两处同步修改。
__version__ = "0.3.17"

_HERE = str(_Path(__file__).resolve().parent)
if _HERE not in _sys.path:
    _sys.path.insert(0, _HERE)

__all__ = ["__version__"]
