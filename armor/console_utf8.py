"""控制台编码兜底：英文版 Windows 的 stdout 常是 cp1252，中文日志会炸。

CLI 脚本在入口调用一次 ensure()；当前编码写不出中文时才切到 UTF-8，
中文 Windows（GBK）与 macOS / Linux（UTF-8）不受影响。GUI 用 pythonw，
stdout 可能为 None，直接跳过。
"""

from __future__ import annotations

import sys

_PROBE = "通过测试中文"


def ensure() -> bool:
    """必要时把 stdout / stderr 切成 UTF-8，返回是否做了切换。"""
    out = sys.stdout
    if out is None or not hasattr(out, "reconfigure"):
        return False
    enc = getattr(out, "encoding", None) or "ascii"
    try:
        _PROBE.encode(enc)
        return False
    except (LookupError, UnicodeEncodeError):
        pass
    for stream in (sys.stdout, sys.stderr):
        try:
            if stream is not None and hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):  # pragma: no cover - 极老的解释器
            return False
    return True
