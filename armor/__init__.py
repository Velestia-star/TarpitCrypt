#!/usr/bin/env python3
"""TarpitCrypt Armor · 运行时加固包。

把程序包加密成单文件 exe，双击输口令即可运行原程序，明文不长期留盘。

模块以顶层名互相导入（``import runtime_pack``），便于
``python armor/selftest.py`` 直跑。这里补一次路径登记，让包式导入
``import armor.armor_gui`` 同样能解析同目录模块。
"""

from __future__ import annotations

import sys as _sys
from pathlib import Path as _Path

__version__ = "0.4.0"

_HERE = str(_Path(__file__).resolve().parent)
if _HERE not in _sys.path:
    _sys.path.insert(0, _HERE)

__all__ = ["__version__"]
