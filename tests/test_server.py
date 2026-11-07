"""TarpitCrypt Web 入口的测试。

分两层：纯函数（multipart 解析、zip 打包、参数合并）直接测；
端到端用真实 ``ThreadingHTTPServer`` 起在随机端口上跑一遍加密→解密。
"""

from __future__ import annotations

import io
import json
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
from urllib.parse import unquote
import zipfile
from collections.abc import Iterator
from http import HTTPStatus
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tarpitcrypt as tc  # noqa: E402
import tarpitcrypt_server as ts  # noqa: E402

BOUNDARY = "----tarpitcrypttestboundary"


def build_multipart(
    fields: dict[str, str], files: list[tuple[str, str, bytes]]
) -> tuple[str, bytes]:
    """手搓一段 multipart/form-data 请求体。"""
    chunks: list[bytes] = []
    for key, value in fields.items():
        chunks.append(
            f'--{BOUNDARY}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n'.encode()
            + value.encode("utf-8")
            + b"\r\n"
        )
    for name, filename, data in files:
        chunks.append(
            (
                f"--{BOUNDARY}\r\n"
                f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                "Content-Type: application/octet-stream\r\n\r\n"
            ).encode()
            + data
            + b"\r\n"
        )
    chunks.append(f"--{BOUNDARY}--\r\n".encode())
    return f"multipart/form-data; boundary={BOUNDARY}", b"".join(chunks)


# ---------------------------------------------------------------------------
# 纯函数
# ---------------------------------------------------------------------------


def test_parse_form_separates_fields_and_files() -> None:
    """表单字段、文件名、文件内容必须各自归位。"""
    content_type, body = build_multipart(
        {"password": "s3cret", "preset": "fast"},
        [("files", "dir/a.txt", b"hello"), ("keyfile", "keyfile", b"KEY")],
    )
    fields, files = ts.parse_form(content_type, body)
    assert fields == {"password": "s3cret", "preset": "fast"}
    assert [(name, filename) for name, filename, _ in files] == [
        ("files", "dir/a.txt"),
        ("keyfile", "keyfile"),
    ]
    assert files[0][2] == b"hello"


def test_parse_form_handles_binary_with_boundary_like_bytes() -> None:
    """正文里出现像边界的字节序列时也不能被切断。"""
    payload = b"\r\n--" + BOUNDARY[:8].encode() + b"\x00\xff" * 20
    content_type, body = build_multipart({"password": "x"}, [("files", "b.bin", payload)])
    _, files = ts.parse_form(content_type, body)
    assert files[0][2] == payload


def test_parse_form_rejects_non_multipart() -> None:
    """非 multipart 请求直接拒绝。"""
    with pytest.raises(ValueError):
        ts.parse_form("application/json", b"{}")


def test_sanitize_member_path_blocks_traversal() -> None:
    """zip-slip：任何形式的上级目录都要被吃掉。"""
    assert ts.sanitize_member_path("../../etc/passwd") == "etc/passwd"
    assert ts.sanitize_member_path("..\\..\\windows\\x") == "windows/x"
    assert ts.sanitize_member_path("./a/./b.txt") == "a/b.txt"
    assert ts.sanitize_member_path("") == "unnamed"
    assert ts.sanitize_member_path("..") == "unnamed"


def test_bundle_files_is_ordered_and_dedupes() -> None:
    """打包结果按路径排序，重复路径自动改名，且包内路径已净化。"""
    blob = ts.bundle_files(
        [
            ("b.txt", b"B"),
            ("a.txt", b"A"),
            ("../evil.txt", b"EVIL"),
            ("a.txt", b"A2"),
        ]
    )
    with zipfile.ZipFile(io.BytesIO(blob)) as archive:
        names = archive.namelist()
        assert "evil.txt" in names
        assert all(".." not in name for name in names)
        assert names == sorted(names)
        assert archive.read("a.txt") == b"A"
        assert archive.read("a(1).txt") == b"A2"


def test_params_from_form_uses_preset_then_overrides() -> None:
    """预设打底，显式字段覆盖。"""
    params = ts.params_from_form({"preset": "hard"})
    assert (params.mem, params.time, params.para, params.rounds) == (1_048_576, 4, 4, 3)

    params = ts.params_from_form({"preset": "hard", "rounds": "2", "pow": "16"})
    assert params.rounds == 2
    assert params.pow == 16


def test_params_from_form_rejects_out_of_range() -> None:
    """越界参数必须被 CryptoParams 拦下，不能带着进 Argon2。"""
    with pytest.raises(ValueError):
        ts.params_from_form({"preset": "fast", "mem": "999999999"})
    with pytest.raises(ValueError):
        ts.params_from_form({"preset": "fast", "rounds": "99"})


def test_normalize_password_matches_cli_rule() -> None:
    """NFC 规范化 + UTF-8，必须和 CLI 完全一致。"""
    composed = "pa\u0301ss"
    assert ts.normalize_password(composed) == "p\u00e1ss".encode("utf-8")


# ---------------------------------------------------------------------------
# 端到端
# ---------------------------------------------------------------------------


@pytest.fixture()
def web_base(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    """在随机端口起一个真实服务；输出目录指到临时目录，别污染用户主目录。"""
    monkeypatch.setattr(ts, "_OUT_DIR", tmp_path / "out")
    server = ts.TarpitWebServer(("127.0.0.1", 0), ts.TarpitRequestHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _post(url: str, content_type: str, body: bytes, extra: dict[str, str] | None = None):
    """发一个 POST，返回 (状态码, 响应头, 响应体)。"""
    request = urllib.request.Request(url, data=body, method="POST")
    request.add_header("Content-Type", content_type)
    for key, value in (extra or {}).items():
        request.add_header(key, value)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.status, dict(response.headers), response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers), exc.read()


def test_web_encrypt_then_decrypt_roundtrip(web_base: str) -> None:
    """网页接口走通：加密得到 .tarpit，再用同口令解回原文。"""
    payload = "本地网页测试 · hello".encode("utf-8")
    content_type, body = build_multipart(
        {"password": "pw-web", "bundle": "0", "mem": "8192", "time": "1",
         "para": "1", "rounds": "1"},
        [("files", "note.txt", payload)],
    )
    status, headers, blob = _post(f"{web_base}/api/encrypt", content_type, body)
    assert status == HTTPStatus.OK
    assert headers["Content-Disposition"].endswith("note.txt.tarpit")
    assert blob[:8] == b"TARPITCR"

    content_type, body = build_multipart(
        {"password": "pw-web"}, [("files", "note.txt.tarpit", blob)]
    )
    status, headers, plain = _post(f"{web_base}/api/decrypt", content_type, body)
    assert status == HTTPStatus.OK
    assert plain == payload
    assert headers.get("X-Tarpit-Decoy") == "0"


def test_web_wrong_password_returns_422(web_base: str) -> None:
    """口令错误 → 422 + 可读错误信息，不是 500。"""
    content_type, body = build_multipart(
        {"password": "right", "mem": "8192", "time": "1", "para": "1", "rounds": "1"},
        [("files", "a.txt", b"data")],
    )
    _, _, blob = _post(f"{web_base}/api/encrypt", content_type, body)

    content_type, body = build_multipart({"password": "wrong"}, [("files", "a.tarpit", blob)])
    status, _, payload = _post(f"{web_base}/api/decrypt", content_type, body)
    assert status == HTTPStatus.UNPROCESSABLE_ENTITY
    assert json.loads(payload)["ok"] is False


def test_web_folder_bundle_comes_back_as_zip(web_base: str) -> None:
    """文件夹上传 → 打成一个 .tarpit；解开后是 .zip，结构保留。"""
    content_type, body = build_multipart(
        {"password": "pw-dir", "bundle": "1", "mem": "8192", "time": "1",
         "para": "1", "rounds": "1"},
        [("files", "proj/a.txt", b"A"), ("files", "proj/sub/b.txt", b"B")],
    )
    status, headers, blob = _post(f"{web_base}/api/encrypt", content_type, body)
    assert status == HTTPStatus.OK
    assert headers["Content-Disposition"].endswith("proj.tarpit")

    content_type, body = build_multipart({"password": "pw-dir"}, [("files", "proj.tarpit", blob)])
    status, headers, plain = _post(f"{web_base}/api/decrypt", content_type, body)
    assert status == HTTPStatus.OK
    assert headers["Content-Disposition"].endswith("proj.zip")
    with zipfile.ZipFile(io.BytesIO(plain)) as archive:
        assert archive.read("proj/a.txt") == b"A"
        assert archive.read("proj/sub/b.txt") == b"B"


def test_web_decoy_hit_sets_header(web_base: str) -> None:
    """诱饵口令命中时通过响应头告知前端。"""
    content_type, body = build_multipart(
        {"password": "main-pw", "decoy_password": "decoy-pw", "mem": "8192",
         "time": "1", "para": "1", "rounds": "1"},
        [("files", "real.txt", b"REAL"), ("decoy", "fake.txt", b"FAKE")],
    )
    status, _, blob = _post(f"{web_base}/api/encrypt", content_type, body)
    assert status == HTTPStatus.OK

    content_type, body = build_multipart({"password": "decoy-pw"}, [("files", "x.tarpit", blob)])
    status, headers, plain = _post(f"{web_base}/api/decrypt", content_type, body)
    assert status == HTTPStatus.OK
    assert plain == b"FAKE"
    assert headers.get("X-Tarpit-Decoy") == "1"


def test_web_rejects_cross_origin(web_base: str) -> None:
    """来自其他站点的跨源 POST 必须被拒。"""
    content_type, body = build_multipart({"password": "x"}, [("files", "a.txt", b"d")])
    status, _, _ = _post(
        f"{web_base}/api/encrypt", content_type, body, {"Origin": "https://evil.example"}
    )
    assert status == HTTPStatus.FORBIDDEN


def test_web_accepts_loopback_origin(web_base: str) -> None:
    """本机来源照常放行。"""
    content_type, body = build_multipart(
        {"password": "pw", "mem": "8192", "time": "1", "para": "1", "rounds": "1"},
        [("files", "a.txt", b"d")],
    )
    status, _, _ = _post(
        f"{web_base}/api/encrypt", content_type, body, {"Origin": "http://127.0.0.1:1234"}
    )
    assert status == HTTPStatus.OK


def test_web_missing_password_is_400(web_base: str) -> None:
    """没给口令 → 400，而不是让 Argon2 拿空口令跑一遍。"""
    content_type, body = build_multipart({"bundle": "0"}, [("files", "a.txt", b"d")])
    status, _, payload = _post(f"{web_base}/api/encrypt", content_type, body)
    assert status == HTTPStatus.BAD_REQUEST
    assert "口令" in json.loads(payload)["error"]


def _legacy_empty_password_blob(payload: bytes = b"legacy") -> bytes:
    """手工造一份历史上「空口令加密」的 v1 文件（当前 encrypt 已拒绝空口令）。"""
    salt = bytes(range(tc.SALT_LEN))
    nonce = bytes(range(tc.NONCE_LEN))
    key = tc._derive(b"", b"", salt, 8192, 1, 1, 1)
    ct_len = len(payload) + tc.TAG_LEN
    header = tc._pack_header(
        flags=0,
        mem=8192,
        time=1,
        para=1,
        rounds=1,
        pow_diff=0,
        salt=salt,
        nonce=nonce,
        pow_nonce=b"\x00" * tc.POW_NONCE_LEN,
        ct_len=ct_len,
    )
    return header + tc._aead_encrypt(tc.CIPHER_AESGCM, key, nonce, header, payload)


def test_web_decrypt_accepts_legacy_empty_password(web_base: str) -> None:
    """解密端保留空口令兼容；页面自己有非空校验，不影响普通用户。"""
    blob = _legacy_empty_password_blob()
    content_type, body = build_multipart(
        {"password": ""}, [("files", "legacy.tarpit", blob)]
    )
    status, _, plain = _post(f"{web_base}/api/decrypt", content_type, body)
    assert status == HTTPStatus.OK
    assert plain == b"legacy"


def test_web_empty_keyfile_is_400(web_base: str) -> None:
    """0 字节 keyfile 不能被静默当成「没启用 keyfile」。"""
    content_type, body = build_multipart(
        {"password": "pw", "mem": "8192", "time": "1", "para": "1", "rounds": "1"},
        [("files", "a.txt", b"data"), ("keyfile", "empty.key", b"")],
    )
    status, _, payload = _post(f"{web_base}/api/encrypt", content_type, body)
    assert status == HTTPStatus.BAD_REQUEST
    assert "keyfile" in json.loads(payload)["error"]


def test_web_oversized_keyfile_is_400(web_base: str) -> None:
    """超过 1 MiB 的 keyfile 在 Web 入口同样被拒。"""
    content_type, body = build_multipart(
        {"password": "pw", "mem": "8192", "time": "1", "para": "1", "rounds": "1"},
        [
            ("files", "a.txt", b"data"),
            ("keyfile", "big.key", b"k" * (tc.MAX_KEYFILE_BYTES + 1)),
        ],
    )
    status, _, payload = _post(f"{web_base}/api/encrypt", content_type, body)
    assert status == HTTPStatus.BAD_REQUEST
    assert "keyfile" in json.loads(payload)["error"]


# ---------------------------------------------------------------------------
# 另存到磁盘 + 打开所在目录
# ---------------------------------------------------------------------------


def _encrypt_once(web_base: str, name: str = "note.txt") -> tuple[dict, bytes]:
    """发一次加密请求，返回 (响应头, 密文字节)。"""
    content_type, body = build_multipart(
        {"password": "pw", "bundle": "0", "mem": "8192", "time": "1",
         "para": "1", "rounds": "1"},
        [("files", name, b"data")],
    )
    status, headers, blob = _post(f"{web_base}/api/encrypt", content_type, body)
    assert status == HTTPStatus.OK
    return headers, blob


def test_encrypt_saves_copy_to_disk(web_base: str, tmp_path: Path) -> None:
    """加密结果要另存一份到输出目录，并把路径回给页面。"""
    headers, blob = _encrypt_once(web_base)
    assert "X-Tarpit-Artifact" in headers
    saved_raw = headers.get("X-Tarpit-Saved-Path")
    assert saved_raw, "响应里缺少保存路径"

    saved = Path(unquote(saved_raw))
    assert saved.exists() and saved.read_bytes() == blob
    assert saved.parent == tmp_path / "out"
    assert saved.name.endswith(".tarpit")


def test_reveal_rejects_unknown_token(web_base: str) -> None:
    """没登记过的令牌一律拒绝——绝不能让接口变成「打开任意路径」。"""
    body = json.dumps({"artifact": "deadbeefdeadbeef"}).encode()
    status, _, _ = _post(f"{web_base}/api/reveal", "application/json", body)
    assert status == HTTPStatus.NOT_FOUND


def test_reveal_rejects_path_like_token(web_base: str) -> None:
    """就算把路径当令牌传进来也没用（只做字典查表）。"""
    body = json.dumps({"artifact": "../../etc/passwd"}).encode()
    status, _, _ = _post(f"{web_base}/api/reveal", "application/json", body)
    assert status == HTTPStatus.NOT_FOUND


def test_reveal_opens_known_artifact(
    web_base: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """已登记的产物 → 调用系统文件管理器并回 200。"""
    opened: list[Path] = []
    monkeypatch.setattr(ts, "open_in_file_manager", lambda path: opened.append(path))

    headers, _ = _encrypt_once(web_base)
    token = headers["X-Tarpit-Artifact"]
    body = json.dumps({"artifact": token}).encode()
    status, _, payload = _post(f"{web_base}/api/reveal", "application/json", body)

    assert status == HTTPStatus.OK
    assert json.loads(payload)["ok"] is True
    assert opened and opened[0].exists()


def test_decrypt_saves_copy_and_returns_artifact(web_base: str) -> None:
    """解密同样落盘并给出令牌。"""
    _, blob = _encrypt_once(web_base)
    content_type, body = build_multipart({"password": "pw"}, [("files", "note.tarpit", blob)])
    status, headers, plain = _post(f"{web_base}/api/decrypt", content_type, body)

    assert status == HTTPStatus.OK
    assert plain == b"data"
    assert "X-Tarpit-Artifact" in headers
    saved = Path(unquote(headers["X-Tarpit-Saved-Path"]))
    assert saved.exists() and saved.read_bytes() == b"data"


def test_web_index_serves_page(web_base: str) -> None:
    """首页能打开，且不泄漏任何服务端路径。"""
    with urllib.request.urlopen(f"{web_base}/", timeout=10) as response:
        html = response.read().decode("utf-8")
    assert response.status == HTTPStatus.OK
    assert "Tarpit" in html
    assert "drop" in html
    assert "/api/encrypt" in html
