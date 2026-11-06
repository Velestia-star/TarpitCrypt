#!/usr/bin/env python3
"""TarpitCrypt 的本地 Web 入口。

一个零额外依赖的小服务：标准库 ``http.server`` 起在 ``127.0.0.1``，浏览器
拖进去文件或整个文件夹，服务端调用 :mod:`tarpitcrypt` 加密后直接把
``.tarpit`` 文件回吐给浏览器下载。

设计取舍
--------
- **只监听回环地址**，不做远程访问；口令只在这台机器的内存里过一遍，
  不落盘、不写日志。
- **校验 Origin**：拒绝来自其他站点的跨源 POST，防止你聊天时随手打开的
  某个网页偷偷往本机端口提交请求。
- **加密串行化**：Argon2id 按 GiB 级别吃内存，多个请求并发放大会直接把机器
  OOM，所以用一把全局锁把派生过程串起来。
- WEB 层只做搬运：口令规范化、KDF、AEAD 全部复用 :mod:`tarpitcrypt` 的实现，
  不在这里重写任何密码学逻辑。

用法::

    python tarpitcrypt_server.py --open
    # → http://127.0.0.1:8765
"""

from __future__ import annotations

import argparse
import io
import json
import mimetypes
import os
import sys
import threading
import time
import unicodedata
import webbrowser
import zipfile
from email.parser import BytesParser
from email.policy import HTTP as HTTP_POLICY
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Final
from urllib.parse import quote

import tarpitcrypt as tc

__all__ = ["TarpitWebServer", "build_handler", "main", "parse_form"]

HOST: Final[str] = "127.0.0.1"
PORT: Final[int] = 8765
MAX_BODY_BYTES: Final[int] = 512 * 1024 * 1024  # 512 MB

#: Argon2id 是 GiB 级内存硬函数，并发跑两个大参数会直接把机器拖死。
_CRYPTO_LOCK: Final[threading.Lock] = threading.Lock()

#: 界面上的三档预设。耗时来自 README 的实测数据。
PRESETS: Final[dict[str, dict[str, Any]]] = {
    "fast": {"mem": 262_144, "time": 3, "para": 2, "rounds": 2},
    "standard": {"mem": 1_048_576, "time": 3, "para": 4, "rounds": 2},
    "hard": {"mem": 1_048_576, "time": 4, "para": 4, "rounds": 3},
}

_PARAM_KEYS: Final[tuple[str, ...]] = ("mem", "time", "para", "rounds", "pow", "cipher")


# ---------------------------------------------------------------------------
# HTTP 无关的纯函数（好测）
# ---------------------------------------------------------------------------


def normalize_password(raw: str) -> bytes:
    """口令 → NFC 规范化后的 UTF-8 字节。

    与 CLI 保持完全一致，否则同一个口令在网页和命令行里会派生出不同密钥。
    """
    return unicodedata.normalize("NFC", raw).encode("utf-8")


def sanitize_member_path(name: str) -> str:
    """清洗 zip 内条目路径，挡住 ``../`` 逃逸（zip-slip）。

    Args:
        name: 浏览器提交的相对路径，可能含 ``\\``、``..``。

    Returns:
        以 ``/`` 分隔、不含以上级目录开头的安全路径。
    """
    raw = name.replace("\\", "/")
    parts = [p for p in raw.split("/") if p not in ("", ".", "..")]
    if not parts:
        return "unnamed"
    return "/".join(parts)


def bundle_files(files: list[tuple[str, bytes]]) -> bytes:
    """把若干个文件打成 zip，保留目录结构。

    路径先净化（挡 zip-slip），重名自动加序号，最后按路径排序写入，
    保证同一批输入产出结构稳定、便于排查。

    Args:
        files: ``(相对路径, 内容)`` 列表。

    Returns:
        zip 文件的字节。
    """
    taken: set[str] = set()
    entries: list[tuple[str, bytes]] = []
    for name, data in files:
        path = sanitize_member_path(name)
        if path in taken:
            stem, dot, ext = path.rpartition(".")
            counter = 1
            while True:
                candidate = f"{stem}({counter}).{ext}" if dot else f"{path}({counter})"
                if candidate not in taken:
                    path = candidate
                    break
                counter += 1
        taken.add(path)
        entries.append((path, data))

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, data in sorted(entries, key=lambda item: item[0]):
            archive.writestr(path, data)
    return buffer.getvalue()


def parse_form(
    content_type: str, body: bytes
) -> tuple[dict[str, str], list[tuple[str, str, bytes]]]:
    """解析 ``multipart/form-data``，返回普通字段与文件列表。

    用标准库 ``email`` 解析，而不是手写 ``\\r\\n--boundary`` 切分：二进制
    正文里出现与边界相同的字节序列时，手写切分会静默截断数据。

    Args:
        content_type: 请求的 ``Content-Type`` 头，必须含 boundary。
        body: 原始请求体。

    Returns:
        ``(字段字典, [(表单字段名, 原始文件名, 内容), ...])``。
        表单字段名与文件名分开保留，避免「用户恰好传了个叫 keyfile 的文件」
        被误当成 keyfile。

    Raises:
        ValueError: ``Content-Type`` 不是 multipart。
    """
    if "multipart/form-data" not in content_type.lower():
        raise ValueError("请求必须是 multipart/form-data")
    header = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("latin-1", "replace")
    message = BytesParser(policy=HTTP_POLICY).parsebytes(header + body)
    if not message.is_multipart():
        raise ValueError("请求体不是合法的 multipart")

    fields: dict[str, str] = {}
    files: list[tuple[str, str, bytes]] = []
    for part in message.iter_parts():
        name = part.get_param("name", header="content-disposition") or ""
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if filename is not None:
            files.append((name, filename, payload))
        else:
            fields[name] = payload.decode("utf-8", "replace")
    return fields, files


def params_from_form(fields: dict[str, str]) -> tc.CryptoParams:
    """把表单字段合并成 :class:`tarpitcrypt.CryptoParams`。

    预设打底，显式字段覆盖。任何越界值都会在 :meth:`CryptoParams.validate`
    里被拦下，不会带着恶意参数进 Argon2。

    Raises:
        ValueError: 参数越界。
    """
    preset = fields.get("preset", "fast")
    merged: dict[str, Any] = dict(PRESETS.get(preset, PRESETS["fast"]))
    for key in _PARAM_KEYS:
        raw = fields.get(key, "").strip()
        if not raw:
            continue
        merged[key] = raw if key == "cipher" else int(raw)
    params = tc.CryptoParams(**merged)
    params.validate()
    return params


def _content_disposition(filename: str) -> str:
    """生成兼容中文文件名的 ``Content-Disposition``。"""
    ascii_name = filename.encode("ascii", "ignore").decode("ascii") or "download"
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(filename)}"


def _safe_output_name(name: str, suffix: str) -> str:
    """从上传的文件名推出下载文件名，去掉路径分隔符。"""
    base = Path(sanitize_member_path(name)).name or "file"
    if suffix and not base.endswith(suffix):
        return base + suffix
    return base


# ---------------------------------------------------------------------------
# HTTP 处理器
# ---------------------------------------------------------------------------


class TarpitRequestHandler(BaseHTTPRequestHandler):
    """处理页面与两个 JSON/二进制接口。"""

    server_version = "TarpitCryptWeb/1.0"
    protocol_version = "HTTP/1.1"

    # -- 基础设施 ---------------------------------------------------------

    def log_message(self, fmt: str, *args: Any) -> None:
        """只记录方法与状态，绝不记录求体（口令就在里面）。"""
        sys.stderr.write(f"[web] {self.address_string()} {fmt % args}\n")

    def _origin_allowed(self) -> bool:
        """只放行本机来源的跨源请求。"""
        origin = self.headers.get("Origin")
        if not origin:
            return True  # curl / 同源导航
        host = origin.split("://", 1)[-1].split(":", 1)[0]
        return host in {"127.0.0.1", "localhost", "::1"}

    def _read_body(self) -> bytes:
        """读取请求体，超过上限直接拒绝。"""
        length_raw = self.headers.get("Content-Length")
        if not length_raw:
            raise ValueError("缺少 Content-Length")
        length = int(length_raw)
        if length > MAX_BODY_BYTES:
            raise ValueError(f"请求体超过上限 {MAX_BODY_BYTES // (1024 * 1024)} MB")
        return self.rfile.read(length)

    def _send_bytes(
        self, status: HTTPStatus, payload: bytes, content_type: str, filename: str | None = None
    ) -> None:
        """回吐一段二进制（文件下载）。"""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        if filename is not None:
            self.send_header("Content-Disposition", _content_disposition(filename))
        self.end_headers()
        self.wfile.write(payload)

    def _send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        """回吐一段 JSON。"""
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send_bytes(status, body, "application/json; charset=utf-8")

    def _fail(self, status: HTTPStatus, message: str) -> None:
        """统一的错误响应。"""
        self._send_json(status, {"ok": False, "error": message})

    # -- 路由 -------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler 约定
        """只提供首页与 favicon。"""
        if self.path in ("/", "/index.html"):
            self._send_bytes(HTTPStatus.OK, INDEX_HTML.encode("utf-8"), "text/html; charset=utf-8")
            return
        if self.path == "/favicon.ico":
            self._send_bytes(HTTPStatus.OK, b"", "image/gif")
            return
        self._fail(HTTPStatus.NOT_FOUND, "没有这个地址")

    def do_POST(self) -> None:  # noqa: N802
        """加密 / 解密两个接口。"""
        if not self._origin_allowed():
            self._fail(HTTPStatus.FORBIDDEN, "拒绝非本机来源的请求")
            return
        route = self.path.rstrip("/")
        if route not in ("/api/encrypt", "/api/decrypt"):
            self._fail(HTTPStatus.NOT_FOUND, "没有这个接口")
            return
        try:
            body = self._read_body()
            fields, files = parse_form(self.headers.get("Content-Type", ""), body)
        except ValueError as exc:
            self._fail(HTTPStatus.BAD_REQUEST, str(exc))
            return

        handler = self._handle_encrypt if route == "/api/encrypt" else self._handle_decrypt
        try:
            handler(fields, files)
        except tc.DecryptError as exc:
            self._fail(HTTPStatus.UNPROCESSABLE_ENTITY, str(exc))
        except (ValueError, tc.TarpitError) as exc:
            self._fail(HTTPStatus.BAD_REQUEST, str(exc))
        except MemoryError:
            self._fail(HTTPStatus.INSUFFICIENT_STORAGE, "内存不足，请调低 mem 预设")
        except OSError as exc:
            self._fail(HTTPStatus.INTERNAL_SERVER_ERROR, f"服务端错误：{exc}")

    # -- 业务 -------------------------------------------------------------

    def _handle_encrypt(
        self, fields: dict[str, str], files: list[tuple[str, str, bytes]]
    ) -> None:
        """加密上传的文件或文件夹。"""
        data_files = [(filename, data) for name, filename, data in files if name == "files"]
        password_raw = fields.get("password", "")
        if not password_raw:
            raise ValueError("缺少口令")
        if not data_files:
            raise ValueError("没有收到任何文件")

        params = params_from_form(fields)
        keyfile = self._pick_file(files, "keyfile")

        is_bundle = fields.get("bundle") == "1" or len(data_files) > 1
        payload = bundle_files(data_files) if is_bundle else data_files[0][1]

        decoy_password_raw = fields.get("decoy_password", "")
        decoy_file = self._pick_file(files, "decoy")
        if decoy_file is not None and not decoy_password_raw:
            raise ValueError("启用了诱饵文件却没给诱饵口令")
        if decoy_file is None and decoy_password_raw:
            raise ValueError("给了诱饵口令但没有诱饵文件")

        started = time.perf_counter()
        with _CRYPTO_LOCK:
            blob = tc.encrypt(
                payload,
                normalize_password(password_raw),
                params=params,
                keyfile=keyfile,
                decoy_plaintext=decoy_file,
                decoy_password=normalize_password(decoy_password_raw) if decoy_file else None,
            )
        elapsed = time.perf_counter() - started

        first_name = data_files[0][0]
        source_name = (
            Path(sanitize_member_path(first_name)).parts[0] if is_bundle else first_name
        )
        out_name = _safe_output_name(source_name, "") + ".tarpit"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(blob)))
        self.send_header("Content-Disposition", _content_disposition(out_name))
        self.send_header("X-Tarpit-Elapsed", f"{elapsed:.2f}")
        self.send_header("X-Tarpit-Params", json.dumps(
            {"mem": params.mem, "time": params.time, "para": params.para,
             "rounds": params.rounds, "pow": params.pow, "cipher": params.cipher}
        ))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(blob)

    def _handle_decrypt(
        self, fields: dict[str, str], files: list[tuple[str, str, bytes]]
    ) -> None:
        """解密上传的 ``.tarpit`` 文件。"""
        data_files = [(filename, data) for name, filename, data in files if name == "files"]
        password_raw = fields.get("password", "")
        if not password_raw:
            raise ValueError("缺少口令")
        if len(data_files) != 1:
            raise ValueError("解密一次只能上传一个 .tarpit 文件")

        keyfile = self._pick_file(files, "keyfile")
        name, blob = data_files[0]

        started = time.perf_counter()
        with _CRYPTO_LOCK:
            plaintext, is_decoy = tc.decrypt(blob, normalize_password(password_raw), keyfile=keyfile)
        elapsed = time.perf_counter() - started

        out_name = _safe_output_name(name, "")
        if out_name.endswith(".tarpit"):
            out_name = out_name[: -len(".tarpit")]
        if zipfile.is_zipfile(io.BytesIO(plaintext)):
            out_name = out_name if out_name.endswith(".zip") else out_name + ".zip"

        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(plaintext)))
        self.send_header("Content-Disposition", _content_disposition(out_name or "plain.bin"))
        self.send_header("X-Tarpit-Elapsed", f"{elapsed:.2f}")
        self.send_header("X-Tarpit-Decoy", "1" if is_decoy else "0")
        self.send_header("Access-Control-Expose-Headers", "X-Tarpit-Elapsed, X-Tarpit-Decoy")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(plaintext)

    @staticmethod
    def _pick_file(files: list[tuple[str, str, bytes]], field: str) -> bytes | None:
        """按表单字段名挑出一个文件的内容。"""
        for name, _filename, data in files:
            if name == field:
                return data
        return None


# ---------------------------------------------------------------------------
# 页面
# ---------------------------------------------------------------------------


def build_handler() -> type[TarpitRequestHandler]:
    """返回绑定了页面内容的处理器类（方便测试替换）。"""
    return TarpitRequestHandler


class TarpitWebServer(ThreadingHTTPServer):
    """带 ``daemon_threads`` 的 HTTP 服务，关闭时不阻塞。"""

    daemon_threads = True
    allow_reuse_address = True


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    """启动本地 Web 服务。"""
    parser = argparse.ArgumentParser(
        prog="tarpitcrypt-web",
        description="TarpitCrypt 本地 Web 入口：拖文件进来，加密文件出去。",
    )
    parser.add_argument("--host", default=HOST, help=f"监听地址，默认 {HOST}")
    parser.add_argument("--port", type=int, default=PORT, help=f"端口，默认 {PORT}")
    parser.add_argument("--open", action="store_true", help="启动后自动打开浏览器")
    args = parser.parse_args(argv)

    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print(
            "警告：正在监听非回环地址。口令会以明文 HTTP 经过网络，只应绑定 127.0.0.1。",
            file=sys.stderr,
        )

    server = TarpitWebServer((args.host, args.port), TarpitRequestHandler)
    url = f"http://{args.host}:{server.server_address[1]}"
    print(f"TarpitCrypt Web 已启动：{url}")
    print("Ctrl+C 退出。口令只在本机内存里过一遍，不落盘、不进日志。")
    if args.open:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        server.server_close()
    return 0


INDEX_HTML = """<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>TarpitCrypt · 焦油坑加密</title>
<style>
  :root {
    --bg: #12100e; --panel: #1b1815; --line: #2e2a25;
    --fg: #e8e2d8; --dim: #9a9188; --accent: #d9a25f; --ok: #7fb069; --bad: #d96f5f;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; background:
      radial-gradient(1200px 600px at 15% -10%, #241d16 0%, transparent 60%), var(--bg);
    color: var(--fg); font: 15px/1.6 "Segoe UI", system-ui, -apple-system, sans-serif;
  }
  main { max-width: 780px; margin: 0 auto; padding: 40px 20px 80px; }
  h1 { font-size: 26px; margin: 0 0 6px; letter-spacing: .5px; }
  h1 span { color: var(--accent); }
  .sub { color: var(--dim); margin: 0 0 26px; font-size: 14px; }
  code { background: #000; padding: 1px 5px; border-radius: 4px; font-size: .92em; }
  .tabs { display: flex; gap: 8px; margin-bottom: 16px; }
  .tab {
    flex: 1; padding: 10px; background: var(--panel); color: var(--dim);
    border: 1px solid var(--line); border-radius: 10px; cursor: pointer; font-size: 15px;
  }
  .tab.active { color: var(--fg); border-color: var(--accent); background: #241d16; }
  .drop {
    border: 2px dashed var(--line); border-radius: 14px; padding: 34px 20px;
    text-align: center; background: var(--panel); transition: .15s; cursor: pointer;
  }
  .drop.over { border-color: var(--accent); background: #241d16; transform: scale(1.005); }
  .drop p { margin: 6px 0; }
  .hint { color: var(--dim); font-size: 13px; }
  .link { color: var(--accent); cursor: pointer; text-decoration: underline dotted; }
  .files { list-style: none; padding: 0; margin: 12px 0 0; max-height: 190px; overflow: auto; }
  .files li {
    display: flex; justify-content: space-between; gap: 12px; padding: 6px 12px;
    background: var(--panel); border: 1px solid var(--line); border-radius: 8px; margin-bottom: 6px;
    font-size: 13px;
  }
  .files li span:last-child { color: var(--dim); flex: none; }
  .grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-top: 18px; }
  label { display: flex; flex-direction: column; gap: 6px; font-size: 13px; color: var(--dim); }
  input[type=password], input[type=text], select {
    width: 100%; padding: 10px 12px; background: #0e0c0a; color: var(--fg);
    border: 1px solid var(--line); border-radius: 9px; font-size: 15px;
  }
  input[type=file] { color: var(--dim); font-size: 12px; }
  details { margin-top: 16px; background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 10px 14px; }
  summary { cursor: pointer; color: var(--dim); font-size: 13px; }
  button.go {
    width: 100%; margin-top: 22px; padding: 13px; border: 0; border-radius: 11px;
    background: var(--accent); color: #1a1207; font-size: 16px; font-weight: 700; cursor: pointer;
  }
  button.go:disabled { opacity: .55; cursor: progress; }
  .status { margin-top: 16px; font-size: 14px; min-height: 22px; }
  .status.ok { color: var(--ok); } .status.bad { color: var(--bad); }
  .result { margin-top: 14px; padding: 14px; background: var(--panel); border: 1px solid var(--line); border-radius: 10px; display: none; }
  .result.show { display: block; }
  .result a { color: var(--accent); font-weight: 600; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 12px; background: #3a2417; color: var(--accent); }
  .spin { display: inline-block; width: 11px; height: 11px; border: 2px solid var(--dim);
          border-top-color: var(--accent); border-radius: 50%; animation: s .8s linear infinite; }
  @keyframes s { to { transform: rotate(360deg); } }
  footer { margin-top: 40px; color: #5d554d; font-size: 12px; }
</style>
</head>
<body>
<main>
  <h1>Tarpit<span>Crypt</span></h1>
  <p class="sub">拖进来，拿走一份 <code>.tarpit</code>。破解者每猜一次口令，都得跑一遍完整的 Argon2id。</p>

  <div class="tabs">
    <button class="tab active" data-mode="encrypt">加密</button>
    <button class="tab" data-mode="decrypt">解密</button>
  </div>

  <div class="drop" id="drop">
    <p><strong>把文件或整个文件夹拖到这里</strong></p>
    <p class="hint">
      或 <label class="link">选择文件<input type="file" id="pickFiles" multiple hidden></label>
      · <label class="link">选择文件夹<input type="file" id="pickDir" webkitdirectory multiple hidden></label>
    </p>
    <p class="hint" id="dropHint">支持多文件；文件夹会打包成一个 .tarpit</p>
  </div>
  <ul class="files" id="fileList"></ul>

  <div class="grid">
    <label>口令
      <input type="password" id="password" autocomplete="new-password" placeholder="长一点，别用生日">
    </label>
    <label id="confirmWrap">再输一次
      <input type="password" id="password2" autocomplete="new-password">
    </label>
    <label>keyfile（可选）
      <input type="file" id="keyfile">
    </label>
    <label>强度预设
      <select id="preset">
        <option value="fast">快速 · 256 MiB × 2 轮（约 1 秒）</option>
        <option value="standard" selected>标准 · 1 GiB × 2 轮（约 3 秒）</option>
        <option value="hard">硬核 · 1 GiB × 3 轮（约 6 秒）</option>
      </select>
    </label>
  </div>

  <details id="advanced">
    <summary>高级：PoW / 算法 / 诱饵层</summary>
    <div class="grid">
      <label>PoW 难度
        <select id="pow">
          <option value="0" selected>关闭</option>
          <option value="16">16 bit</option>
          <option value="18">18 bit</option>
          <option value="20">20 bit（造文件会慢几秒）</option>
        </select>
      </label>
      <label>AEAD 算法
        <select id="cipher">
          <option value="aes-256-gcm" selected>aes-256-gcm</option>
          <option value="xchacha20-poly1305">xchacha20-poly1305（当前会降级）</option>
        </select>
      </label>
      <label class="decoy-only">诱饵明文（可选）
        <input type="file" id="decoy">
      </label>
      <label class="decoy-only">诱饵口令
        <input type="password" id="decoyPassword" placeholder="用别的口令才能解出诱饵">
      </label>
    </div>
  </details>

  <button class="go" id="go">加密并下载</button>
  <div class="status" id="status"></div>
  <div class="result" id="result"></div>

  <footer>本地运行 · 口令不会离开这台机器 · 单次上限 512 MB</footer>
</main>

<script>
(() => {
  const $ = (id) => document.getElementById(id);
  const drop = $("drop"), fileList = $("fileList"), status = $("status"), result = $("result");
  let mode = "encrypt";
  let picked = [];          // [{file, path}]
  let isFolder = false;

  const fmtSize = (n) => n > 1048576 ? (n / 1048576).toFixed(1) + " MB"
                   : n > 1024 ? (n / 1024).toFixed(1) + " KB" : n + " B";

  function render() {
    fileList.innerHTML = "";
    picked.forEach(({ file, path }) => {
      const li = document.createElement("li");
      const a = document.createElement("span");
      a.textContent = path;
      const b = document.createElement("span");
      b.textContent = fmtSize(file.size);
      li.append(a, b);
      fileList.append(li);
    });
    drop.querySelector("p strong").textContent = picked.length
      ? `已选 ${picked.length} 个文件`
      : "把文件或整个文件夹拖到这里";
  }

  function setFiles(list, folder) {
    picked = list;
    isFolder = folder || list.some((it) => it.path.includes("/"));
    render();
  }

  // 从 drop 的 DataTransfer 里递归展开目录
  async function walkEntry(entry, prefix, out) {
    if (entry.isFile) {
      const file = await new Promise((res, rej) => entry.file(res, rej));
      out.push({ file, path: prefix + file.name });
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      const readBatch = () => new Promise((res, rej) => reader.readEntries(res, rej));
      const entries = [];
      let batch;
      do {
        batch = await readBatch();
        entries.push(...batch);
      } while (batch.length);
      for (const child of entries) await walkEntry(child, prefix + entry.name + "/", out);
    }
  }

  async function collectFromDrop(dt) {
    const out = [];
    const roots = [];
    for (const item of Array.from(dt.items)) {
      const entry = item.webkitGetAsEntry && item.webkitGetAsEntry();
      if (entry) roots.push(entry);
    }
    for (const entry of roots) await walkEntry(entry, "", out);
    return out;
  }

  drop.addEventListener("click", (e) => {
    if (!e.target.closest("label")) $("pickFiles").click();
  });
  drop.addEventListener("dragover", (e) => { e.preventDefault(); drop.classList.add("over"); });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", async (e) => {
    e.preventDefault();
    drop.classList.remove("over");
    try {
      setFiles(await collectFromDrop(e.dataTransfer), false);
    } catch (err) {
      status.textContent = "读取拖入的内容失败：" + err.message;
    }
  });

  $("pickFiles").addEventListener("change", (e) => {
    setFiles([...e.target.files].map((f) => ({ file: f, path: f.name })), false);
  });
  $("pickDir").addEventListener("change", (e) => {
    setFiles([...e.target.files].map((f) => ({ file: f, path: f.webkitRelativePath || f.name })), true);
  });

  document.querySelectorAll(".tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
      tab.classList.add("active");
      mode = tab.dataset.mode;
      const enc = mode === "encrypt";
      $("confirmWrap").style.display = enc ? "" : "none";
      $("preset").closest("label").style.display = enc ? "" : "none";
      $("advanced").style.display = enc ? "" : "none";
      $("go").textContent = enc ? "加密并下载" : "解密并下载";
      $("dropHint").textContent = enc
        ? "支持多文件；文件夹会打包成一个 .tarpit"
        : "一次请上传一个 .tarpit 文件";
      $("pickDir").disabled = !enc;
      result.className = "result"; status.textContent = "";
    });
  });

  function say(text, kind) {
    status.className = "status" + (kind ? " " + kind : "");
    status.textContent = text;
  }

  $("go").addEventListener("click", async () => {
    result.className = "result";
    if (!picked.length) return say("先拖点东西进来", "bad");
    const pw = $("password").value;
    if (!pw) return say("口令不能为空", "bad");
    if (mode === "encrypt" && $("password2").value !== pw) return say("两次口令不一致", "bad");
    if (mode === "decrypt" && picked.length !== 1) return say("解密一次只能上传一个文件", "bad");

    const fd = new FormData();
    fd.append("password", pw);
    fd.append("preset", $("preset").value);
    fd.append("bundle", isFolder || picked.length > 1 ? "1" : "0");
    if (mode === "encrypt") {
      fd.append("pow", $("pow").value);
      fd.append("cipher", $("cipher").value);
      const kf = $("keyfile").files[0];
      if (kf) fd.append("keyfile", kf, "keyfile");
      const decoy = $("decoy").files[0];
      if (decoy) {
        fd.append("decoy", decoy, "decoy");
        fd.append("decoy_password", $("decoyPassword").value);
      }
    } else {
      const kf = $("keyfile").files[0];
      if (kf) fd.append("keyfile", kf, "keyfile");
    }
    picked.forEach(({ file, path }) => fd.append("files", file, path));

    const btn = $("go");
    btn.disabled = true;
    const t0 = performance.now();
    const tick = setInterval(() => {
      const s = ((performance.now() - t0) / 1000).toFixed(0);
      say(`正在跑 Argon2id… ${s}s（这是在故意烧时间）`);
    }, 250);
    say("处理中…");

    try {
      const res = await fetch(mode === "encrypt" ? "/api/encrypt" : "/api/decrypt", {
        method: "POST", body: fd,
      });
      clearInterval(tick);
      if (!res.ok) {
        let msg = `HTTP ${res.status}`;
        try { msg = (await res.json()).error || msg; } catch (e) {}
        return say("失败：" + msg, "bad");
      }
      const elapsed = (performance.now() - t0) / 1000;
      const isDecoy = res.headers.get("X-Tarpit-Decoy") === "1";
      const blob = await res.blob();
      const cd = res.headers.get("Content-Disposition") || "";
      const m = /filename\\*=UTF-8''([^;]+)/.exec(cd);
      const name = m ? decodeURIComponent(m[1]) : (mode === "encrypt" ? "output.tarpit" : "output.bin");

      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url; a.download = name;
      document.body.append(a); a.click(); a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 60000);

      say(`完成，用时 ${elapsed.toFixed(1)}s`, "ok");
      result.innerHTML = "";
      if (isDecoy) {
        const p = document.createElement("p");
        const badge = document.createElement("span");
        badge.className = "badge";
        badge.textContent = "诱饵层";
        p.append(badge, document.createTextNode(" 你解出的是诱饵内容。"));
        result.append(p);
      }
      const line = document.createElement("p");
      const link = document.createElement("a");
      link.href = url; link.download = name; link.textContent = name;
      line.append(document.createTextNode("已下载 "), link,
                  document.createTextNode(`（${fmtSize(blob.size)}）`));
      result.append(line);
      const hint = document.createElement("p");
      hint.className = "hint";
      hint.textContent = "解密时请用对应的口令" + (mode === "encrypt" ? "和 keyfile" : "") + "。";
      result.append(hint);
      result.className = "result show";
    } catch (err) {
      clearInterval(tick);
      say("请求失败：" + err.message, "bad");
    } finally {
      btn.disabled = false;
    }
  });
})();
</script>
</body>
</html>
"""


if __name__ == "__main__":
    raise SystemExit(main())
