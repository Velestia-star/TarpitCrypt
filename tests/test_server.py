"""TarpitCrypt Web 入口的测试。

分两层：纯函数（multipart 解析、zip 打包、参数合并）直接测；
端到端用真实 ``ThreadingHTTPServer`` 起在随机端口上跑一遍加密→解密。
"""

from __future__ import annotations

import io
import json
import sys
import threading
import time
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


def test_parse_content_length_rejects_bad_values() -> None:
    """负数 / 非整数 / 超限的 Content-Length 一律拒绝。"""
    assert ts._parse_content_length("0") == 0
    assert ts._parse_content_length("123") == 123
    for raw in (None, "-1", "abc", str(ts.MAX_BODY_BYTES + 1)):
        with pytest.raises(ValueError):
            ts._parse_content_length(raw)


def test_content_disposition_sanitizes_control_chars() -> None:
    """文件名里的引号 / CR / LF 不能进入响应头。"""
    header = ts._content_disposition('a"\r\nX-Evil: 1.txt')
    assert "\r" not in header and "\n" not in header
    assert 'filename="aX-Evil: 1.txt"' in header

    chinese = ts._content_disposition("中文.txt")
    assert "filename*=UTF-8''" in chinese
    assert "%E4%B8%AD%E6%96%87" in chinese


def test_safe_output_name_strips_control_chars() -> None:
    assert ts._safe_output_name('a"\r\nb.txt', "") == "ab.txt"


def test_save_artifact_never_overwrites(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """同名结果自动加序号，两份内容都在。"""
    monkeypatch.setattr(ts, "_OUT_DIR", tmp_path)
    first = ts._save_artifact("x.tarpit", b"one")
    second = ts._save_artifact("x.tarpit", b"two")
    assert first != second
    assert first.read_bytes() == b"one"
    assert second.read_bytes() == b"two"


def test_save_artifact_is_race_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """并发保存同名结果也不能互相覆盖。"""
    from concurrent.futures import ThreadPoolExecutor

    monkeypatch.setattr(ts, "_OUT_DIR", tmp_path)
    with ThreadPoolExecutor(max_workers=8) as pool:
        paths = list(pool.map(lambda _index: ts._save_artifact("same.bin", b"data"), range(8)))

    assert len(set(paths)) == 8
    assert all(path.read_bytes() == b"data" for path in paths)


def test_main_refuses_non_loopback() -> None:
    """非回环地址默认拒绝启动，必须显式 --allow-remote。"""
    assert ts.main(["--host", "0.0.0.0", "--port", "9"]) == 2


def test_main_refuses_missing_docs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """没有 docs/ 时本地 Web 要明确报错，而不是起一个空服务。"""
    monkeypatch.setattr(ts, "DOCS_DIR", tmp_path)
    assert ts.main(["--no-open", "--port", "9"]) == 2


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


def test_web_unexpected_exception_returns_500(
    web_base: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """未预期异常要回可读的 500，而不是直接断连接。"""

    def boom(*_args: object, **_kwargs: object) -> tuple[dict[str, str], list[object]]:
        raise RuntimeError("boom")

    monkeypatch.setattr(ts, "parse_form", boom)
    content_type, body = build_multipart({"password": "pw"}, [("files", "a.txt", b"d")])
    status, _, payload = _post(f"{web_base}/api/encrypt", content_type, body)
    assert status == HTTPStatus.INTERNAL_SERVER_ERROR
    assert json.loads(payload)["ok"] is False


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
    """首页直接复用 docs/，并注入本地模式标记；不泄漏服务端路径。"""
    with urllib.request.urlopen(f"{web_base}/", timeout=10) as response:
        html = response.read().decode("utf-8")
    assert response.status == HTTPStatus.OK
    assert "Tarpit" in html
    assert "drop" in html
    assert "window.TARPIT_LOCAL = true" in html
    assert "app.js" in html
    assert 'id="armorPanel"' in html
    assert 'data-armor-mode="sidecar"' in html
    assert 'data-armor-mode="report"' in html
    assert "armor_ui.js" in html
    assert "/api/encrypt" not in html


def test_web_serves_docs_assets(web_base: str) -> None:
    """本地服务要能把 docs/ 的脚本、样式和适配器一起发出去。"""
    for path, needle in (
        ("/app.js", "./core_adapter.js"),
        ("/core_adapter.js", "TARPIT_LOCAL"),
        ("/armor_ui.js", "armorPanel"),
        ("/style.css", "--accent"),
    ):
        with urllib.request.urlopen(f"{web_base}{path}", timeout=10) as response:
            body = response.read().decode("utf-8")
        assert response.status == HTTPStatus.OK
        assert needle in body, f"{path} 内容不对"


def test_web_rejects_static_path_traversal(web_base: str) -> None:
    """docs/ 静态路由不能把仓库里的其他文件带出去。"""
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(f"{web_base}/%2e%2e/README.md", timeout=10)
    assert exc.value.code == HTTPStatus.NOT_FOUND


def test_web_artifact_download(web_base: str) -> None:
    """登记过的产出物可以按令牌下载，且只认令牌。"""
    content_type, body = build_multipart(
        {"password": "pw", "mem": "8192", "time": "1", "para": "1", "rounds": "1"},
        [("files", "a.txt", b"artifact-data")],
    )
    status, headers, blob = _post(f"{web_base}/api/encrypt", content_type, body)
    assert status == HTTPStatus.OK
    artifact = headers["X-Tarpit-Artifact"]
    with urllib.request.urlopen(f"{web_base}/api/artifacts/{artifact}", timeout=10) as response:
        assert response.status == HTTPStatus.OK
        assert response.read() == blob
        assert "attachment" in response.headers["Content-Disposition"]

    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(f"{web_base}/api/artifacts/not-a-token", timeout=10)
    assert exc.value.code == HTTPStatus.NOT_FOUND


# ---------------------------------------------------------------------------
# armor 后端 API
# ---------------------------------------------------------------------------


def _wait_armor_job(web_base: str, job_id: str, timeout: float = 120.0) -> dict:
    """轮询 armor 任务，直到 done / error。"""
    deadline = time.time() + timeout
    last: dict = {}
    while time.time() < deadline:
        with urllib.request.urlopen(
            f"{web_base}/api/armor/jobs/{job_id}", timeout=15
        ) as response:
            last = json.load(response)["job"]
        if last.get("status") in ("done", "error"):
            return last
        time.sleep(0.2)
    raise AssertionError(f"armor 任务超时：{last}")


def test_armor_profiles_endpoint(web_base: str) -> None:
    with urllib.request.urlopen(f"{web_base}/api/armor/profiles", timeout=10) as response:
        data = json.load(response)
    assert data["ok"] is True
    assert data["defaults"]["profile"] in data["profiles"]
    assert data["defaults"]["poison"] in data["poisons"]


def test_armor_pack_rejects_weak_password(web_base: str) -> None:
    content_type, body = build_multipart(
        {"password": "password", "layers": "2", "sidecar": "0"},
        [("files", "a.txt", b"x")],
    )
    status, _, payload = _post(f"{web_base}/api/armor/pack", content_type, body)
    assert status == HTTPStatus.BAD_REQUEST
    assert "口令" in json.loads(payload)["error"]


def test_armor_pack_inspect_restore_roundtrip(web_base: str) -> None:
    """web 端走的 armor 闭环：加固 → 检查 → 还原。"""
    content_type, body = build_multipart(
        {
            "password": "ArmorPass1!",
            "layers": "2",
            "profile": "轻（秒级）",
            "sidecar": "0",
            "out_subdir": "p4-test",
        },
        [("files", "hello.txt", b"armor payload")],
    )
    status, _, payload = _post(f"{web_base}/api/armor/pack", content_type, body)
    assert status == HTTPStatus.ACCEPTED
    job = _wait_armor_job(web_base, json.loads(payload)["job"])
    assert job["status"] == "done", job
    saved = Path(job["result"]["savedPath"])
    assert saved.exists()
    assert saved.parent.name == "p4-test"
    armored = saved.read_bytes()
    assert armored[:8] == b"TPARMOR3"
    with urllib.request.urlopen(
        f"{web_base}/api/artifacts/{job['result']['artifact']}", timeout=10
    ) as response:
        assert response.read() == armored

    content_type, body = build_multipart({}, [("files", saved.name, armored)])
    status, _, payload = _post(f"{web_base}/api/armor/inspect", content_type, body)
    assert status == HTTPStatus.OK
    info = json.loads(payload)
    assert info["layers"] == 2

    content_type, body = build_multipart(
        {"password": "ArmorPass1!", "parallel": "1"},
        [("files", saved.name, armored)],
    )
    status, _, payload = _post(f"{web_base}/api/armor/restore", content_type, body)
    assert status == HTTPStatus.ACCEPTED
    job = _wait_armor_job(web_base, json.loads(payload)["job"])
    assert job["status"] == "done", job
    restored = Path(job["result"]["savedPath"])
    with zipfile.ZipFile(io.BytesIO(restored.read_bytes())) as archive:
        assert archive.read("hello.txt") == b"armor payload"


def test_armor_pack_with_sidecar(web_base: str) -> None:
    """伴生诱饵目录和它的下载 zip 都要真的落盘。"""
    content_type, body = build_multipart(
        {
            "password": "ArmorPass1!",
            "layers": "2",
            "sidecar": "1",
            "out_subdir": "kit-test",
        },
        [("files", "hello.txt", b"sidecar payload")],
    )
    status, _, payload = _post(f"{web_base}/api/armor/pack", content_type, body)
    assert status == HTTPStatus.ACCEPTED
    job = _wait_armor_job(web_base, json.loads(payload)["job"])
    assert job["status"] == "done", job
    result = job["result"]
    assert Path(result["sidecarPath"]).parent.name == "kit-test"
    assert Path(result["sidecarPath"]).is_dir()
    sidecar_zip = Path(result["sidecarZipPath"])
    assert sidecar_zip.is_file()
    with zipfile.ZipFile(sidecar_zip) as archive:
        assert archive.namelist()


def test_armor_standalone_sidecar(web_base: str) -> None:
    """独立伴生页签：只给源包，不先加固也能生成伴生目录。"""
    content_type, body = build_multipart(
        {"layers": "2", "out_subdir": "standalone-kit"},
        [("files", "hello.txt", b"standalone sidecar")],
    )
    status, _, payload = _post(f"{web_base}/api/armor/sidecar", content_type, body)
    assert status == HTTPStatus.ACCEPTED
    job = _wait_armor_job(web_base, json.loads(payload)["job"])
    assert job["status"] == "done", job
    result = job["result"]
    assert result["fileCount"] > 0
    assert result["traps"] >= 1
    assert Path(result["savedPath"]).parent.name == "standalone-kit"
    zip_path = Path(result["zipPath"])
    assert zip_path.is_file()
    with zipfile.ZipFile(zip_path) as archive:
        assert archive.namelist()


def test_armor_report_and_clear(web_base: str) -> None:
    """运行报告要记录本次会话，且能被清空。"""
    _post(f"{web_base}/api/armor/report/clear", "application/json", b"{}")
    content_type, body = build_multipart(
        {
            "password": "ArmorPass1!",
            "layers": "2",
            "sidecar": "0",
        },
        [("files", "report.txt", b"report payload")],
    )
    status, _, payload = _post(f"{web_base}/api/armor/pack", content_type, body)
    assert status == HTTPStatus.ACCEPTED
    job = _wait_armor_job(web_base, json.loads(payload)["job"])
    assert job["status"] == "done", job

    with urllib.request.urlopen(f"{web_base}/api/armor/report", timeout=10) as response:
        report = json.load(response)
    assert report["attempts"], report
    assert any(item["action"] == "加固" for item in report["attempts"])
    assert report["summary"]

    _post(f"{web_base}/api/armor/report/clear", "application/json", b"{}")
    with urllib.request.urlopen(f"{web_base}/api/armor/report", timeout=10) as response:
        cleared = json.load(response)
    assert cleared["attempts"] == []


def test_armor_desktop_path_mode(
    web_base: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """桌面壳专用路径模式：源、输出、容器都可直接走本机路径。"""
    source = tmp_path / "hello.txt"
    source.write_bytes(b"path mode payload")
    out_dir = tmp_path / "out"
    token = "test-path-token"
    monkeypatch.setattr(ts, "_ALLOW_PATHS", True)
    monkeypatch.setattr(ts, "_PATH_TOKEN", token)
    headers = {"X-Tarpit-Path-Token": token}

    content_type, body = build_multipart(
        {
            "password": "ArmorPass1!",
            "layers": "2",
            "sidecar": "0",
            "source_path": str(source),
            "out_dir": str(out_dir),
        },
        [],
    )
    status, _, payload = _post(
        f"{web_base}/api/armor/pack", content_type, body, extra=headers
    )
    assert status == HTTPStatus.ACCEPTED
    job = _wait_armor_job(web_base, json.loads(payload)["job"])
    assert job["status"] == "done", job
    saved = Path(job["result"]["savedPath"])
    assert saved.parent == out_dir.resolve()
    assert source.read_bytes() == b"path mode payload"

    content_type, body = build_multipart({"path": str(saved)}, [])
    status, _, payload = _post(
        f"{web_base}/api/armor/inspect", content_type, body, extra=headers
    )
    assert status == HTTPStatus.OK
    assert json.loads(payload)["layers"] == 2

    content_type, body = build_multipart(
        {"password": "ArmorPass1!", "container_path": str(saved)},
        [],
    )
    status, _, payload = _post(
        f"{web_base}/api/armor/restore", content_type, body, extra=headers
    )
    assert status == HTTPStatus.ACCEPTED
    job = _wait_armor_job(web_base, json.loads(payload)["job"])
    assert job["status"] == "done", job
    restored = Path(job["result"]["savedPath"])
    with zipfile.ZipFile(io.BytesIO(restored.read_bytes())) as archive:
        assert archive.read("hello.txt") == b"path mode payload"

    # 没有令牌时，路径模式必须拒绝。
    content_type, body = build_multipart(
        {"password": "ArmorPass1!", "source_path": str(source)}, []
    )
    status, _, payload = _post(f"{web_base}/api/armor/pack", content_type, body)
    assert status == HTTPStatus.BAD_REQUEST
    assert "令牌" in json.loads(payload)["error"]


def test_desktop_server_starts_with_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """桌面壳启动的服务要带路径令牌，普通浏览器入口仍然可读。"""
    import desktop_web

    old = (ts._OUT_DIR, ts._ALLOW_PATHS, ts._PATH_TOKEN)
    try:
        server, url, token = desktop_web.start_local_server(tmp_path / "out")
        try:
            assert token
            with urllib.request.urlopen(url, timeout=10) as response:
                html = response.read().decode("utf-8")
            assert "TARPIT_LOCAL = true" in html
            assert "TARPIT_PATH_TOKEN" in html
            assert token in html
        finally:
            server.shutdown()
            server.server_close()
    finally:
        ts._OUT_DIR, ts._ALLOW_PATHS, ts._PATH_TOKEN = old
