#!/usr/bin/env python3
"""TarpitCrypt 桌面 WebView 壳（P5）。

用 pywebview 把本地 Web 装进一个原生窗口：不显示浏览器地址栏，随机
loopback 端口只在本机可用；同时给页面开放三个原生能力：

* 原生文件 / 文件夹选择对话框；
* 原生输出目录选择；
* 用系统文件管理器打开路径。

本机路径直读只在这个壳里开启（``ts._ALLOW_PATHS = True``），并且页面会
拿到一个随机会话令牌；普通 ``tarpitcrypt_server.py`` 永远不开启路径模式。

用法::

    pip install pywebview
    python desktop_web.py

不想用 WebView 时，原来的 ``python armor/armor_gui.py`` 仍然可用。
"""

from __future__ import annotations

import argparse
import secrets
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any

try:
    import webview
except ImportError:  # pragma: no cover - 只在没装桌面依赖时触发
    webview = None  # type: ignore[assignment]

import tarpitcrypt_server as ts

__all__ = ["NativeApi", "start_local_server", "main"]


class NativeApi:
    """暴露给页面的 ``window.pywebview.api``。"""

    def __init__(self) -> None:
        self._window: Any = None

    def _bind_window(self, window: Any) -> None:
        self._window = window

    def _dialog(self, kind: str) -> str:
        if webview is None or self._window is None:
            return ""
        dialog_type = webview.OPEN_DIALOG if kind == "open" else webview.FOLDER_DIALOG
        try:
            result = self._window.create_file_dialog(dialog_type, allow_multiple=False)
        except Exception:
            return ""
        if not result:
            return ""
        if isinstance(result, (list, tuple)):
            return str(result[0]) if result else ""
        return str(result)

    def pick_file(self) -> str:
        return self._dialog("open")

    def pick_folder(self) -> str:
        return self._dialog("folder")

    def pick_armored(self) -> str:
        return self._dialog("open")

    def pick_output_dir(self) -> str:
        return self._dialog("folder")

    def open_path(self, raw: str) -> str:
        if not raw:
            return ""
        target = Path(raw).expanduser().resolve()
        if not target.exists():
            return ""
        if target.is_file():
            ts.open_in_file_manager(target)
        elif sys.platform.startswith("win"):
            subprocess.Popen(["explorer", str(target)])
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(target)])
        else:
            subprocess.Popen(["xdg-open", str(target)])
        return str(target)


def start_local_server(
    out_dir: str | Path | None = None,
) -> tuple[Any, str, str]:
    """启动随机端口的本地服务，并打开桌面壳专用的路径模式。

    返回 ``(server, url, token)``。调用方负责 ``shutdown()`` / ``server_close()``。
    """
    if out_dir is not None:
        ts._OUT_DIR = Path(out_dir).expanduser().resolve()
    ts._OUT_DIR.mkdir(parents=True, exist_ok=True)
    if not (ts.DOCS_DIR / "index.html").is_file():
        raise FileNotFoundError(
            f"找不到桌面前端：{ts.DOCS_DIR / 'index.html'}；请从仓库目录运行"
        )
    ts._ALLOW_PATHS = True
    ts._PATH_TOKEN = secrets.token_hex(16)
    server = ts.TarpitWebServer(("127.0.0.1", 0), ts.TarpitRequestHandler)
    thread = threading.Thread(target=server.serve_forever, name="tarpit-web", daemon=True)
    thread.start()
    port = int(server.server_address[1])
    return server, f"http://127.0.0.1:{port}/", ts._PATH_TOKEN


def _stop_server(server: Any) -> None:
    try:
        server.shutdown()
    finally:
        server.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="TarpitCrypt 桌面 WebView 壳（P5）")
    parser.add_argument("--out-dir", default=None, help="输出目录，默认 存放文件/")
    parser.add_argument("--debug", action="store_true", help="打开 WebView 调试工具")
    args = parser.parse_args(argv)

    if webview is None:
        print(
            "没有找到 pywebview。请先安装桌面依赖：\n"
            "  python -m pip install pywebview\n"
            "然后重新运行 python desktop_web.py。",
            file=sys.stderr,
        )
        return 2

    try:
        server, url, _token = start_local_server(args.out_dir)
    except FileNotFoundError as exc:
        print(exc, file=sys.stderr)
        return 2
    api = NativeApi()
    window = webview.create_window(
        "TarpitCrypt",
        url,
        js_api=api,
        width=1280,
        height=860,
        min_size=(1000, 640),
    )
    if window is None:
        _stop_server(server)
        print("WebView 窗口创建失败。", file=sys.stderr)
        return 2
    api._bind_window(window)
    stopped = threading.Event()

    def on_closed() -> None:
        if not stopped.is_set():
            stopped.set()
            _stop_server(server)

    window.events.closed += on_closed
    try:
        webview.start(debug=args.debug)
    finally:
        if not stopped.is_set():
            stopped.set()
            _stop_server(server)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
