#!/usr/bin/env python3
"""TarpitCrypt 桌面 WebView 壳（P5）。

用 pywebview 把本地 Web 装进一个原生窗口：不显示浏览器地址栏，固定
loopback 端口（默认 8766）只在本机可用；同时给页面开放三个原生能力：

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
import os
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
    port: int = 0,
) -> tuple[Any, str, str]:
    """启动本地服务，并打开桌面壳专用的路径模式。

    ``port=0`` 时由系统分配随机端口（测试用）；桌面主程序使用固定端口，
    这样 IndexedDB / localStorage 的 origin 不变，工作区和历史才能跨启动保留。
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
    server = ts.TarpitWebServer(("127.0.0.1", port), ts.TarpitRequestHandler)
    thread = threading.Thread(target=server.serve_forever, name="tarpit-web", daemon=True)
    thread.start()
    actual_port = int(server.server_address[1])
    return server, f"http://127.0.0.1:{actual_port}/", ts._PATH_TOKEN


def _stop_server(server: Any) -> None:
    try:
        server.shutdown()
    finally:
        server.server_close()


def _storage_dir() -> Path:
    """给 WebView 一个稳定的用户数据目录，避免 private mode 每次清空。"""
    if sys.platform.startswith("win"):
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        root = Path(base) if base else Path.home() / "AppData" / "Local"
    else:
        root = Path.home() / ".local" / "share"
    path = root / "TarpitCrypt" / "webview"
    path.mkdir(parents=True, exist_ok=True)
    return path


_WEBVIEW2_CLIENT = "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
_WEBVIEW2_URL = "https://developer.microsoft.com/microsoft-edge/webview2/"


def _webview2_version() -> str:
    """返回已安装的 WebView2 Runtime 版本；空字符串表示没找到。"""
    if not sys.platform.startswith("win"):
        return ""
    try:
        import winreg
    except ImportError:
        return ""

    keys = (
        (winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{_WEBVIEW2_CLIENT}"),
        (winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\Microsoft\EdgeUpdate\Clients\{_WEBVIEW2_CLIENT}"),
        (winreg.HKEY_CURRENT_USER, rf"Software\Microsoft\EdgeUpdate\Clients\{_WEBVIEW2_CLIENT}"),
    )
    for hive, subkey in keys:
        try:
            with winreg.OpenKey(hive, subkey) as key:
                value, _kind = winreg.QueryValueEx(key, "pv")
                if value:
                    return str(value)
        except OSError:
            continue

    for env in ("ProgramFiles(x86)", "ProgramFiles", "LOCALAPPDATA"):
        base = os.environ.get(env)
        if not base:
            continue
        root = Path(base) / "Microsoft" / "EdgeWebView" / "Application"
        if not root.is_dir():
            continue
        versions = [
            item.name
            for item in root.iterdir()
            if item.is_dir() and (item / "msedgewebview2.exe").is_file()
        ]
        if versions:
            return sorted(versions)[-1]
    return ""


def _find_webview2_bootstrapper() -> Path | None:
    names = ("MicrosoftEdgeWebview2Setup.exe", "MicrosoftEdgeWebView2Setup.exe")
    roots: list[Path] = []
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        roots.append(Path(meipass))
    roots.append(Path(sys.executable).resolve().parent)
    roots.append(Path(__file__).resolve().parent)
    for root in roots:
        for name in names:
            candidate = root / name
            if candidate.is_file():
                return candidate
    return None


def _show_error(text: str) -> None:
    if sys.platform.startswith("win"):
        import ctypes

        ctypes.windll.user32.MessageBoxW(0, text, "TarpitCrypt", 0x10)
    else:
        print(text, file=sys.stderr)


def _ensure_webview2() -> bool:
    """检测 WebView2；优先运行随 exe 附带的 Evergreen Bootstrapper。"""
    if not sys.platform.startswith("win"):
        return True
    if _webview2_version():
        return True

    bootstrapper = _find_webview2_bootstrapper()
    if bootstrapper is not None:
        try:
            subprocess.run(
                [str(bootstrapper), "/silent", "/install"],
                check=False,
                timeout=300,
            )
        except (OSError, subprocess.TimeoutExpired):
            pass
        if _webview2_version():
            return True

    _show_error(
        "缺少 Microsoft Edge WebView2 Runtime，桌面窗口无法启动。\n\n"
        f"请安装后重试：{_WEBVIEW2_URL}\n\n"
        "也可以把 MicrosoftEdgeWebview2Setup.exe 放到 TarpitCrypt.exe 旁边，"
        "程序会在启动时自动安装。"
    )
    return False


def _run_self_test() -> int:
    """验证冻结环境里的 tarpitcrypt / armor 原生依赖都能跑。"""
    import io
    import tempfile
    import zipfile

    armor_core, decoy_kit = ts._armor_modules()
    import armor_metrics  # noqa: F401 - 验证它能被冻结收集
    import tarpitcrypt as tc

    params = tc.CryptoParams(mem=8192, time=1, para=1, rounds=1, pow=0)
    password = b"SelftestPass1!"
    blob = tc.encrypt(b"tarpitcrypt-selftest", password, params=params)
    plain, is_decoy = tc.decrypt(blob, password)
    if plain != b"tarpitcrypt-selftest" or is_decoy:
        raise RuntimeError("v1 自测失败")

    with tempfile.TemporaryDirectory(prefix="tc-exe-selftest-") as tmp:
        source = Path(tmp) / "selftest.txt"
        source.write_text("armor selftest", encoding="utf-8")
        armored = armor_core.build_armored(
            source,
            password,
            layers=2,
            profile=next(iter(armor_core.PROFILES)),
        )
        restored = armor_core.restore_armored(armored, password)
        with zipfile.ZipFile(io.BytesIO(restored.payload)) as archive:
            data = archive.read("selftest.txt")
        if data != b"armor selftest":
            raise RuntimeError("armor 自测失败")
    print("self-test OK")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="TarpitCrypt 桌面 WebView 壳（P5）")
    parser.add_argument("--out-dir", default=None, help="输出目录，默认 存放文件/")
    parser.add_argument("--debug", action="store_true", help="打开 WebView 调试工具")
    parser.add_argument(
        "--port",
        type=int,
        default=8766,
        help="固定本地端口（默认 8766）；换端口会换持久化空间",
    )
    parser.add_argument("--self-test", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    if args.self_test:
        try:
            return _run_self_test()
        except Exception as exc:
            print(f"self-test failed: {type(exc).__name__}: {exc}", file=sys.stderr)
            return 1

    if webview is None:
        _show_error(
            "没有找到 pywebview。请先安装桌面依赖：\n"
            "  python -m pip install pywebview\n"
            "然后重新运行 python desktop_web.py。"
        )
        return 2

    if not _ensure_webview2():
        return 3

    try:
        server, url, _token = start_local_server(args.out_dir, port=args.port)
    except FileNotFoundError as exc:
        _show_error(str(exc))
        return 2
    except OSError as exc:
        _show_error(
            f"端口 {args.port} 启动失败：{exc}\n"
            "请关掉占用它的程序，或用 --port 换一个固定端口"
            "（注意：换端口会换一套持久化空间）。"
        )
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
        _show_error("WebView 窗口创建失败。")
        return 2
    api._bind_window(window)
    stopped = threading.Event()

    def on_closed() -> None:
        if not stopped.is_set():
            stopped.set()
            _stop_server(server)

    window.events.closed += on_closed
    storage_path = _storage_dir()
    try:
        webview.start(
            debug=args.debug,
            private_mode=False,
            storage_path=str(storage_path),
        )
    finally:
        if not stopped.is_set():
            stopped.set()
            _stop_server(server)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
