"""浏览器版与 Python 版的双向兼容性测试。

这是整个网页版最重要的一条测试：它证明 `docs/tarpit_core.js` 与
`tarpitcrypt.py` 生成的文件**可以互相解开**。

做法：
1. Python 造一份密文，连同 KDF 黄金向量一起嵌进一个临时自测页；
2. 用本机浏览器（Edge / Chrome）无头打开它，让浏览器去解 Python 的文件，
   并自己造一份文件、把字节吐回 DOM；
3. Python 再解浏览器造的那份，顺带校验它产出的 zip。

没有可用浏览器时整条跳过（`pytest -k browser`）。
"""

from __future__ import annotations

import base64
import io
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import zipfile
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Iterator

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tarpitcrypt as tc  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
DOCS = REPO / "docs"

BROWSER_CANDIDATES = (
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "/usr/bin/google-chrome",
    "/usr/bin/chromium",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
)

SELFTEST_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>compat</title></head>
<body><pre id="out">RUNNING</pre>
<script src="vendor/argon2.umd.min.js"></script>
<script type="module">
import * as core from './tarpit_core.js';

const PY_B64 = "__PY_B64__";
const EXPECT = { k1: "__K1__", k2: "__K2__", k3: "__K3__" };
const enc = new TextEncoder();
const dec = new TextDecoder();
const hex = (b) => Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const lines = [];
const ok = (name, cond) => lines.push(`${cond ? "PASS" : "FAIL"} ${name}`);

async function main() {
  try {
    const salt = new Uint8Array(32);
    for (let i = 0; i < 32; i++) salt[i] = i;
    const pw = enc.encode("pw-vector");
    const empty = new Uint8Array(0);
    const base = { mem: 8192, time: 1, para: 1, rounds: 1 };

    ok("KDF rounds=1", hex(await core.derive(pw, empty, salt, base)) === EXPECT.k1);
    ok("KDF rounds=2", hex(await core.derive(pw, empty, salt, { ...base, rounds: 2 })) === EXPECT.k2);
    ok("KDF keyfile", hex(await core.derive(pw, enc.encode("keyfile-bytes"), salt, base)) === EXPECT.k3);

    const params = { mem: 8192, time: 1, para: 1, rounds: 1, pow: 0 };
    const made = await core.encrypt(enc.encode("js-made-payload"), enc.encode("js-pw"), { params });
    ok("JS 自解", dec.decode((await core.decrypt(made, enc.encode("js-pw"))).data) === "js-made-payload");
    lines.push("JSFILE " + hex(made));

    const pyBlob = unb64(PY_B64);
    ok("解 Python 文件",
       dec.decode((await core.decrypt(pyBlob, enc.encode("cross-test"))).data) === "python-made-payload");

    let rejected = false;
    try { await core.decrypt(pyBlob, enc.encode("wrong")); } catch (e) { rejected = true; }
    ok("错口令被拒", rejected);

    const dBlob = await core.encrypt(enc.encode("real"), enc.encode("main-pw"), {
      params, decoyPlaintext: enc.encode("fake"), decoyPassword: enc.encode("decoy-pw") });
    const mainR = await core.decrypt(dBlob, enc.encode("main-pw"));
    const decR = await core.decrypt(dBlob, enc.encode("decoy-pw"));
    ok("诱饵-主层", dec.decode(mainR.data) === "real" && mainR.isDecoy === false);
    ok("诱饵-诱饵层", dec.decode(decR.data) === "fake" && decR.isDecoy === true);
    lines.push("DECOYFILE " + hex(dBlob));

    const kfBlob = await core.encrypt(enc.encode("kf"), enc.encode("kf-pw"),
      { params, keyfile: enc.encode("KEYFILE") });
    let kfRejected = false;
    try { await core.decrypt(kfBlob, enc.encode("kf-pw")); } catch (e) { kfRejected = true; }
    ok("缺 keyfile 被拒", kfRejected);
    ok("带 keyfile 解开",
       dec.decode((await core.decrypt(kfBlob, enc.encode("kf-pw"),
         { keyfile: enc.encode("KEYFILE") })).data) === "kf");

    const powBlob = await core.encrypt(enc.encode("pow"), enc.encode("pow-pw"),
      { params: { ...params, pow: 16 } });
    ok("PoW 头", powBlob[18] === 16);
    ok("PoW 解密", dec.decode((await core.decrypt(powBlob, enc.encode("pow-pw"))).data) === "pow");

    const zip = core.makeZip([
      { path: "proj/a.txt", data: enc.encode("A") },
      { path: "../evil.txt", data: enc.encode("E") },
    ]);
    ok("zip 头", core.isZip(zip));
    lines.push("ZIPHEX " + hex(zip));
  } catch (e) {
    lines.push("ERROR " + (e && (e.stack || e.message)));
  }
  document.getElementById("out").textContent = "RESULT\\n" + lines.join("\\n") + "\\nEND";
}
main();
</script></body></html>
"""


def find_browser() -> str | None:
    """返回可用的浏览器可执行文件路径。"""
    override = os.environ.get("DSH_BROWSER")
    if override and Path(override).exists():
        return override
    for candidate in BROWSER_CANDIDATES:
        if Path(candidate).exists():
            return candidate
    return None


class _QuietHandler(SimpleHTTPRequestHandler):
    """不往测试输出里刷访问日志。"""

    def log_message(self, fmt: str, *args: object) -> None:  # noqa: D102
        return None


@pytest.fixture()
def served_site(tmp_path: Path) -> Iterator[str]:
    """把自测页放进临时站点目录并用 HTTP 提供出来。"""
    site = tmp_path / "site"
    shutil.copytree(DOCS, site)
    salt = bytes(range(32))
    blob = tc.encrypt(
        b"python-made-payload", b"cross-test", params=tc.CryptoParams(mem=8192, time=1, para=1, rounds=1)
    )
    html = (
        SELFTEST_HTML.replace("__PY_B64__", base64.b64encode(blob).decode())
        .replace("__K1__", tc._derive(b"pw-vector", b"", salt, 8192, 1, 1, 1).hex())
        .replace("__K2__", tc._derive(b"pw-vector", b"", salt, 8192, 1, 1, 2).hex())
        .replace("__K3__", tc._derive(b"pw-vector", b"keyfile-bytes", salt, 8192, 1, 1, 1).hex())
    )
    (site / "_selftest.html").write_text(html, encoding="utf-8")

    handler = lambda *a, **kw: _QuietHandler(*a, directory=str(site), **kw)  # noqa: E731
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/_selftest.html"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


@pytest.mark.browser
def test_js_and_python_are_byte_compatible(served_site: str, tmp_path: Path) -> None:
    """浏览器与 Python 必须能互相解开对方生成的文件。"""
    browser = find_browser()
    if browser is None:
        pytest.skip("本机没有 Edge/Chrome，跳过浏览器兼容性测试")

    probe = subprocess.run(
        [browser, "--headless", "--disable-gpu", "--dump-dom", "data:text/html,<h1>x</h1>"],
        capture_output=True, text=True, timeout=90,
    )
    if "dump-dom" not in probe.stdout and "<h1>" not in probe.stdout:
        pytest.skip(f"浏览器不支持 --dump-dom：{browser}")

    def dump_once() -> tuple[str, subprocess.CompletedProcess[str]]:
        """跑一次无头浏览器，只取 <pre id="out"> 里的文本。

        注意：不能拿整段 DOM 去正则匹配 `RESULT...END`——`--dump-dom` 会把
        内联 `<script>` 的**源码**也吐出来，源码里同样有这两个字面量，
        页面还没跑完时会先命中脚本源码，得到一个空结果。
        """
        run = subprocess.run(
            [
                browser, "--headless", "--disable-gpu", "--no-first-run",
                "--no-default-browser-check",
                f"--user-data-dir={tmp_path / 'profile'}",
                "--virtual-time-budget=300000",
                "--dump-dom", served_site,
            ],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300,
        )
        found = re.search(r'<pre id="out">(.*?)</pre>', run.stdout, re.S)
        return (found.group(1).strip() if found else ""), run

    output = ""
    result: subprocess.CompletedProcess[str] | None = None
    for _attempt in range(3):
        output, result = dump_once()
        if output.startswith("RESULT"):
            break
        time.sleep(0.8)

    assert output.startswith("RESULT") and result is not None, (
        f"页面没有产出结果（dump={len(result.stdout) if result else 0}B）\n"
        f"---- 页面文本 ----\n{output[:400]}\n"
        f"---- 浏览器 stderr ----\n{(result.stderr[-600:] if result else '')}"
    )

    body = output[len("RESULT"):].rsplit("END", 1)[0]
    fails = [line for line in body.splitlines() if line.startswith("FAIL")]
    errors = [line for line in body.splitlines() if line.startswith("ERROR")]
    assert not fails, f"浏览器端断言失败：{fails}\n{errors}"
    assert not errors, f"浏览器端异常：{errors}"

    def extract(tag: str) -> bytes:
        found = re.search(rf"{tag} ([0-9a-f]+)", body)
        assert found, f"结果里缺少 {tag}；页面输出：\n{body[:800]}"
        return bytes.fromhex(found.group(1))

    # 方向一：Python 解浏览器造的文件
    assert tc.decrypt(extract("JSFILE"), b"js-pw") == (b"js-made-payload", False)

    # 方向二：Python 解浏览器造的诱饵文件
    decoy_blob = extract("DECOYFILE")
    assert tc.decrypt(decoy_blob, b"main-pw") == (b"real", False)
    assert tc.decrypt(decoy_blob, b"decoy-pw") == (b"fake", True)

    # 方向三：浏览器打的 zip 必须能被 Python 正常展开（含 zip-slip 净化）
    with zipfile.ZipFile(io.BytesIO(extract("ZIPHEX"))) as archive:
        assert archive.testzip() is None
        assert archive.namelist() == ["evil.txt", "proj/a.txt"]
        assert archive.read("evil.txt") == b"E"
        assert archive.read("proj/a.txt") == b"A"


@pytest.mark.browser
def test_index_page_boots(served_site: str, tmp_path: Path) -> None:
    """真实页面能被加载，且 `app.js` 模块执行到底（界面胶水没有语法错）。"""
    browser = find_browser()
    if browser is None:
        pytest.skip("本机没有 Edge/Chrome，跳过浏览器兼容性测试")

    url = served_site.rsplit("/", 1)[0] + "/index.html"
    dom = ""
    for _attempt in range(3):
        run = subprocess.run(
            [
                browser, "--headless", "--disable-gpu", "--no-first-run",
                "--no-default-browser-check",
                f"--user-data-dir={tmp_path / 'profile2'}",
                "--virtual-time-budget=20000",
                "--dump-dom", url,
            ],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180,
        )
        dom = run.stdout
        if 'data-app="ready"' in dom:
            break
        time.sleep(0.8)

    assert 'data-app="ready"' in dom, f"页面模块没有执行完：\n{dom[:600]}"
    assert 'id="drop"' in dom
    assert "加密并下载" in dom
    assert "/api/" not in dom, "纯前端页面不应再引用后端接口"


@pytest.mark.browser
def test_queue_drawer_opens_from_hash(served_site: str, tmp_path: Path) -> None:
    """右侧加密队列抽屉：DOM 齐全，且 `#queue` 能把它直接展开。

    抽屉里的拖拽排序没法用无头浏览器模拟，这里只保证「加载后不报错、
    抽屉能被打开」——脚本报错的话 app.js 跑不到挂 ready 标记那一步。
    """
    browser = find_browser()
    if browser is None:
        pytest.skip("本机没有 Edge/Chrome，跳过浏览器兼容性测试")

    base = served_site.rsplit("/", 1)[0]
    dom = ""
    for _attempt in range(3):
        run = subprocess.run(
            [
                browser, "--headless", "--disable-gpu", "--no-first-run",
                "--no-default-browser-check",
                f"--user-data-dir={tmp_path / 'profile3'}",
                "--virtual-time-budget=20000",
                "--dump-dom", f"{base}/index.html#queue",
            ],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180,
        )
        dom = run.stdout
        if 'data-app="ready"' in dom:
            break
        time.sleep(0.8)

    assert 'data-app="ready"' in dom, f"页面模块没有执行完：\n{dom[:600]}"
    for element_id in ("queueToggle", "drawer", "queueList", "queueRun", "queuePickDir",
                       "queueSelectAll", "queueDelete", "openPath", "pathModal",
                       "historyList", "historyClear", "queueSelectAll"):
        assert f'id="{element_id}"' in dom, f"缺少工作区节点 #{element_id}"
    assert 'class="drawer open"' in dom, "`#queue` 应当直接展开抽屉"
    assert 'aria-expanded="true"' in dom


@pytest.mark.browser
def test_history_view_deeplink(served_site: str, tmp_path: Path) -> None:
    """`#history` 深链：抽屉直接打开并切到历史视图。"""
    browser = find_browser()
    if browser is None:
        pytest.skip("本机没有 Edge/Chrome，跳过浏览器兼容性测试")

    base = served_site.rsplit("/", 1)[0]
    dom = ""
    for _attempt in range(3):
        run = subprocess.run(
            [
                browser, "--headless", "--disable-gpu", "--no-first-run",
                "--no-default-browser-check",
                f"--user-data-dir={tmp_path / 'profile4'}",
                "--virtual-time-budget=20000",
                "--dump-dom", f"{base}/index.html#history",
            ],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=180,
        )
        dom = run.stdout
        if 'data-app="ready"' in dom:
            break
        time.sleep(0.8)

    assert 'data-app="ready"' in dom, f"页面模块没有执行完：\n{dom[:600]}"
    assert 'class="drawer open"' in dom
    # 历史面板可见、工作区面板隐藏
    assert "viewWorkspace" in dom and "viewHistory" in dom
    assert 'id="viewWorkspace" hidden' in dom, "历史视图下工作区应隐藏"
    assert 'class="dtab active" data-view="history"' in dom, "历史标签应高亮"
