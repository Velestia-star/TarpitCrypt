#!/usr/bin/env python3
"""Windows 原生拖放（WM_DROPFILES），给任意 Tk 窗口挂整棵 HWND 树。

Tk 在 Windows 上给几乎每个控件建一个 TkChild HWND（实测 99+）。
Explorer 拖放只投递到鼠标正下方那个 HWND，不冒泡。必须给窗口树里每个
HWND 都注册 DragAcceptFiles + 子类化 wndproc，否则拖到输入框/日志框会丢。

消息只入纯 Python 队列，由外部按空闲时机消费；绝不在 wndproc 内碰 Tcl
（否则 Python 3.12 + tkinter 会因 GIL 重入致命崩溃）。
"""

from __future__ import annotations

import ctypes
import queue
import sys
from ctypes import wintypes
from typing import Callable

HDROP = ctypes.c_void_p
WM_DROPFILES = 0x0233
WM_COPYDATA = 0x004A
WM_COPYGLOBALDATA = 0x0049
GWL_WNDPROC = -4
MSGFLT_ALLOW = 1
MAX_PATH = 32768


class NativeDrop:
    """把 *root* 的整棵 HWND 树注册为系统拖放目标。"""

    def __init__(self, root, on_files: Callable[[list[str]], None]):
        self.root = root
        self.on_files = on_files
        self._queue: queue.Queue[list[str]] = queue.Queue()
        self.ok = False
        self.error = ""
        self._old: dict[int, int] = {}
        self._proc_ref = None
        if sys.platform != "win32":
            self.error = "仅 Windows 支持原生拖放"
            return
        try:
            self._user32 = ctypes.windll.user32
            self._shell32 = ctypes.windll.shell32
            self._kernel32 = ctypes.windll.kernel32
            self._setup_ctypes()
            root.update_idletasks()
            self._WNDPROC = ctypes.WINFUNCTYPE(
                wintypes.LPARAM, wintypes.HWND, wintypes.UINT,
                wintypes.WPARAM, wintypes.LPARAM)
            self._proc_ref = self._WNDPROC(self._wndproc)
            self.refresh()
            if not self._old:
                raise OSError("窗口树为空")
            self.ok = True
        except Exception as exc:
            self.error = str(exc)

    def _setup_ctypes(self) -> None:
        u, s, k = self._user32, self._shell32, self._kernel32
        u.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
        u.SendMessageTimeoutW.argtypes = [
            wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM,
            wintypes.UINT, wintypes.UINT, ctypes.POINTER(wintypes.LPARAM)]
        u.SendMessageTimeoutW.restype = wintypes.LPARAM
        self._getwndlong = (getattr(u, "GetWindowLongPtrW", None)
                            or u.GetWindowLongW)
        self._getwndlong.argtypes = [wintypes.HWND, ctypes.c_int]
        self._getwndlong.restype = ctypes.c_ssize_t
        self._setwndlong = (getattr(u, "SetWindowLongPtrW", None)
                            or u.SetWindowLongW)
        self._setwndlong.argtypes = [wintypes.HWND, ctypes.c_int, ctypes.c_ssize_t]
        self._setwndlong.restype = ctypes.c_ssize_t
        u.CallWindowProcW.argtypes = [ctypes.c_ssize_t, wintypes.HWND,
                                      wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
        u.CallWindowProcW.restype = wintypes.LPARAM
        s.DragQueryFileW.argtypes = [HDROP, wintypes.UINT, wintypes.LPWSTR, wintypes.UINT]
        s.DragQueryFileW.restype = wintypes.UINT
        s.DragFinish.argtypes = [HDROP]
        k.GlobalFree.argtypes = [wintypes.HGLOBAL]
        k.GlobalFree.restype = wintypes.HGLOBAL

    def _all_hwnds(self) -> list[int]:
        u = self._user32
        top = int(self.root.frame(), 16)
        found: list[int] = [top, self.root.winfo_id()]
        CB = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        def cb(hwnd, _lparam):
            if hwnd:
                found.append(int(hwnd))
            return True

        u.EnumChildWindows.argtypes = [wintypes.HWND, CB, wintypes.LPARAM]
        u.EnumChildWindows.restype = wintypes.BOOL
        cb_ref = CB(cb)  # 防 GC
        u.EnumChildWindows(top, cb_ref, 0)
        return list(dict.fromkeys(found))

    def refresh(self) -> None:
        """给新出现的 HWND 补挂拖放。"""
        for hwnd in self._all_hwnds():
            if hwnd in self._old:
                continue
            old = self._setwndlong(hwnd, GWL_WNDPROC, self._proc_ref)
            if not old:
                continue
            self._old[hwnd] = old
            self._shell32.DragAcceptFiles(hwnd, True)
            for msg in (WM_DROPFILES, WM_COPYGLOBALDATA, WM_COPYDATA):
                try:
                    self._user32.ChangeWindowMessageFilterEx(
                        hwnd, msg, MSGFLT_ALLOW, None)
                except Exception:
                    pass

    def _wndproc(self, hwnd, msg, wparam, lparam):
        if msg == WM_DROPFILES:
            try:
                self._queue.put(self._paths(wparam))
            except Exception as exc:
                print(f"[drop] 解析失败: {exc}", file=sys.stderr)
            try:
                self._shell32.DragFinish(HDROP(wparam))
            except Exception:
                pass
            return 0
        old = self._old.get(hwnd)
        if old:
            return self._user32.CallWindowProcW(old, hwnd, msg, wparam, lparam)
        return 0

    def _paths(self, hdrop: int) -> list[str]:
        s = self._shell32
        count = s.DragQueryFileW(HDROP(hdrop), 0xFFFFFFFF, None, 0)
        out: list[str] = []
        for i in range(count):
            buf = ctypes.create_unicode_buffer(MAX_PATH)
            n = s.DragQueryFileW(HDROP(hdrop), i, buf, MAX_PATH)
            if n:
                out.append(buf.value)
        return out

    def consume(self) -> None:
        """主线程空闲时调用；把队列里的路径交给回调。"""
        while True:
            try:
                paths = self._queue.get_nowait()
            except queue.Empty:
                return
            if paths:
                try:
                    self.on_files(paths)
                except Exception as exc:
                    print(f"[drop] 回调异常: {exc}", file=sys.stderr)
