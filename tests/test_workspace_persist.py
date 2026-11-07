"""工作区持久化 + 拖到左侧加密的端到端测试。

为什么不用 `--dump-dom`：无头浏览器在 dump-dom 模式下 **IndexedDB 回调根本不触发**，
只能拿 CDP（--remote-debugging-port）用真实时间去驱动页面。

依赖：`pip install websocket-client`；没有就整条跳过。
"""

from __future__ import annotations

import json
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

import pytest

websocket = pytest.importorskip("websocket", reason="需要 websocket-client 才能驱动 CDP")

from test_browser_compat import DOCS, find_browser  # noqa: E402

ADD_FILE_JS = """
(async () => {
  const file = new File([new TextEncoder().encode("persist-test-payload")],
                        "持久化测试.txt", { type: "text/plain" });
  const dt = new DataTransfer();
  dt.items.add(file);
  const input = document.getElementById("queuePickFiles");
  input.files = dt.files;
  input.dispatchEvent(new Event("change", { bubbles: true }));
  await new Promise((r) => setTimeout(r, 600));
  document.getElementById("password").value = "pw123456";
  document.getElementById("password2").value = "pw123456";
  return document.querySelectorAll("#queueList .queue-row").length;
})()
"""

DRAG_TO_ENCRYPT_JS = """
(async () => {
  const row = document.querySelector("#queueList .queue-row");
  if (!row) return { error: "没有行" };
  const dt = new DataTransfer();
  dt.setData("application/x-tarpit-item", row.dataset.id);
  // 故意丢在 body 上：等价于「拖到左侧任意位置松手」，不必精确落进虚线框
  document.body.dispatchEvent(new DragEvent("drop", {
    dataTransfer: dt, bubbles: true, cancelable: true,
  }));
  // renderWorkspace 会重建行，必须每次重新查询，不能抓着旧引用
  let current = null;
  for (let i = 0; i < 300; i += 1) {
    await new Promise((r) => setTimeout(r, 200));
    current = document.querySelector("#queueList .queue-row");
    if (current && (current.classList.contains("done") || current.classList.contains("error"))) break;
  }
  return {
    status: current && current.classList.contains("done") ? "done"
          : current && current.classList.contains("error") ? "error" : "timeout",
    text: current && current.querySelector(".q-out") ? current.querySelector(".q-out").textContent : "",
  };
})()
"""

AFTER_RELOAD_JS = """
(async () => {
  for (let i = 0; i < 100; i += 1) {
    const rows = document.querySelectorAll("#queueList .queue-row");
    if (rows.length > 0) {
      const row = rows[0];
      return {
        rows: rows.length,
        names: [...document.querySelectorAll("#queueList .q-name")].map((e) => e.textContent),
        status: row.classList.contains("done") ? "done"
              : row.classList.contains("error") ? "error" : "pending",
        out: row.querySelector(".q-out") ? row.querySelector(".q-out").textContent : "",
      };
    }
    await new Promise((r) => setTimeout(r, 100));
  }
  return { rows: 0, names: [], status: "none", out: "" };
})()
"""


DROP_ON_MAIN_JS = """
(async () => {
  const file = new File([new TextEncoder().encode("hello")], "拖入测试.txt", { type: "text/plain" });
  const dt = new DataTransfer();
  dt.items.add(file);
  document.body.dispatchEvent(new DragEvent("dragover", { dataTransfer: dt, bubbles: true, cancelable: true }));
  document.body.dispatchEvent(new DragEvent("drop", { dataTransfer: dt, bubbles: true, cancelable: true }));
  await new Promise((r) => setTimeout(r, 500));
  return { listItems: document.querySelectorAll("#fileList li").length };
})()
"""

DROP_ON_DRAWER_JS = """
(async () => {
  const file = new File([new TextEncoder().encode("hello")], "抽屉测试.txt", { type: "text/plain" });
  const dt = new DataTransfer();
  dt.items.add(file);
  const drawer = document.getElementById("drawer");
  drawer.dispatchEvent(new DragEvent("dragover", { dataTransfer: dt, bubbles: true, cancelable: true }));
  drawer.dispatchEvent(new DragEvent("drop", { dataTransfer: dt, bubbles: true, cancelable: true }));
  await new Promise((r) => setTimeout(r, 800));
  return { workspaceRows: document.querySelectorAll("#queueList .queue-row").length };
})()
"""



ADD_TWO_FILES_JS = """
(async () => {
  const make = (name, body) => new File([new TextEncoder().encode(body)], name, { type: "text/plain" });
  const dt = new DataTransfer();
  dt.items.add(make("A文件.txt", "aaa"));
  dt.items.add(make("B文件.txt", "bbb"));
  const input = document.getElementById("queuePickFiles");
  input.files = dt.files;
  input.dispatchEvent(new Event("change", { bubbles: true }));
  await new Promise((r) => setTimeout(r, 800));
  return document.querySelectorAll("#queueList .queue-row").length;
})()
"""


REORDER_JS = """
(async () => {
  const rows = [...document.querySelectorAll("#queueList .queue-row")];
  if (rows.length < 2) return { error: "需要两行" };
  const before = rows.map((r) => r.querySelector(".q-name").textContent);
  const dt = new DataTransfer();
  dt.setData("application/x-tarpit-item", rows[0].dataset.id);
  rows[0].dispatchEvent(new DragEvent("dragstart", { dataTransfer: dt, bubbles: true }));
  const rect = rows[1].getBoundingClientRect();
  const evt = { dataTransfer: dt, bubbles: true, cancelable: true,
                clientY: rect.top + rect.height * 0.8 };
  rows[1].dispatchEvent(new DragEvent("dragover", evt));
  rows[1].dispatchEvent(new DragEvent("drop", evt));
  await new Promise((r) => setTimeout(r, 400));
  const after = [...document.querySelectorAll("#queueList .queue-row")]
    .map((r) => r.querySelector(".q-name").textContent);
  const anyDone = [...document.querySelectorAll("#queueList .queue-row")]
    .some((r) => r.classList.contains("done") || r.classList.contains("running"));
  return { before, after, anyDone, status: document.getElementById("status").textContent };
})()
"""


class Cdp:
    """够用的极简 CDP 客户端。"""
    def __init__(self, url: str) -> None:
        self.ws = websocket.create_connection(url, timeout=180)
        self.counter = 0

    def call(self, method: str, params: dict | None = None) -> dict:
        self.counter += 1
        target = self.counter
        self.ws.send(json.dumps({"id": target, "method": method, "params": params or {}}))
        while True:
            message = json.loads(self.ws.recv())
            if message.get("id") == target:
                if "error" in message:
                    raise RuntimeError(f"{method} 失败: {message['error']}")
                return message.get("result", {})

    def evaluate(self, expression: str):
        result = self.call(
            "Runtime.evaluate",
            {"expression": expression, "awaitPromise": True, "returnByValue": True},
        )
        if "exceptionDetails" in result:
            raise RuntimeError(f"页面异常: {result['exceptionDetails']}")
        return result.get("result", {}).get("value")


def free_port() -> int:
    """拿一个空闲端口。"""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_page(port: int) -> str:
    """等 devtools 端口就绪，返回页面 target 的 ws 地址。"""
    for _ in range(80):
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=2) as resp:
                targets = json.load(resp)
            pages = [t for t in targets if t.get("type") == "page"]
            if pages:
                return pages[0]["webSocketDebuggerUrl"]
        except Exception:  # noqa: BLE001 - 启动中
            pass
        time.sleep(0.5)
    raise RuntimeError("devtools 端口没起来")


@pytest.mark.browser
def test_workspace_survives_reload() -> None:
    """加入文件 → 拖到左侧加密 → 刷新 → 记录和加密结果都还在。"""
    browser = find_browser()
    if browser is None:
        pytest.skip("本机没有 Edge/Chrome")

    temp = pathlib.Path(tempfile.mkdtemp(prefix="tc-persist-"))
    http_port = free_port()
    debug_port = free_port()
    base = f"http://127.0.0.1:{http_port}"

    server = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(http_port), "--bind", "127.0.0.1",
         "--directory", str(DOCS)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    edge = subprocess.Popen(
        [browser, "--headless=new", "--disable-gpu", "--no-first-run", "--no-default-browser-check",
         f"--remote-debugging-port={debug_port}", f"--user-data-dir={temp / 'profile'}", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(2)
        cdp = Cdp(wait_for_page(debug_port))
        cdp.call("Page.enable")
        cdp.call("Page.navigate", {"url": f"{base}/index.html#workspace"})
        time.sleep(2.5)

        assert cdp.evaluate(ADD_FILE_JS) == 1, "加入文件后应有一行"

        encrypted = cdp.evaluate(DRAG_TO_ENCRYPT_JS)
        assert encrypted.get("status") == "done", f"拖到左侧应触发加密：{encrypted}"
        assert ".tarpit" in encrypted.get("text", "")

        cdp.call("Page.reload")
        time.sleep(3)
        after = cdp.evaluate(AFTER_RELOAD_JS)

        assert after.get("rows") == 1, f"刷新后应恢复一行：{after}"
        assert any("持久化测试" in name for name in after.get("names", [])), "文件名应被恢复"
        assert after.get("status") == "done", "加密结果也应被恢复"
        assert ".tarpit" in after.get("out", "")
    finally:
        for process in (edge, server):
            process.terminate()
        for process in (edge, server):
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
        shutil.rmtree(temp, ignore_errors=True)


@pytest.mark.browser
@pytest.mark.browser
def test_reorder_inside_drawer_does_not_encrypt() -> None:
    """抽屉内上下拖动 = 排序，绝不能顺带触发加密。"""
    browser = find_browser()
    if browser is None:
        pytest.skip("本机没有 Edge/Chrome")

    temp = pathlib.Path(tempfile.mkdtemp(prefix="tc-reorder-"))
    http_port = free_port()
    debug_port = free_port()
    base = f"http://127.0.0.1:{http_port}"

    server = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(http_port), "--bind", "127.0.0.1",
         "--directory", str(DOCS)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    edge = subprocess.Popen(
        [browser, "--headless=new", "--disable-gpu", "--no-first-run",
         f"--remote-debugging-port={debug_port}", f"--user-data-dir={temp / 'profile'}", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(2)
        cdp = Cdp(wait_for_page(debug_port))
        cdp.call("Page.enable")
        cdp.call("Page.navigate", {"url": f"{base}/index.html#workspace"})
        time.sleep(2.5)

        assert cdp.evaluate(ADD_TWO_FILES_JS) == 2, "应加入两行"
        result = cdp.evaluate(REORDER_JS)

        assert "error" not in result, result
        assert result["after"] != result["before"], f"顺序应当变化：{result}"
        assert result["after"][-1] == result["before"][0], f"第一行应移到末尾：{result}"
        assert not result["anyDone"], f"抽屉内排序不应触发加密：{result}"
    finally:
        for process in (edge, server):
            process.terminate()
        for process in (edge, server):
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
        shutil.rmtree(temp, ignore_errors=True)


def test_file_drop_paths() -> None:
    """系统文件拖到左侧要能载入，拖到抽屉要能进工作区——都不能静默无反应。"""
    browser = find_browser()
    if browser is None:
        pytest.skip("本机没有 Edge/Chrome")

    temp = pathlib.Path(tempfile.mkdtemp(prefix="tc-drop-"))
    http_port = free_port()
    debug_port = free_port()
    base = f"http://127.0.0.1:{http_port}"

    server = subprocess.Popen(
        [sys.executable, "-m", "http.server", str(http_port), "--bind", "127.0.0.1",
         "--directory", str(DOCS)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    edge = subprocess.Popen(
        [browser, "--headless=new", "--disable-gpu", "--no-first-run",
         f"--remote-debugging-port={debug_port}", f"--user-data-dir={temp / 'profile'}", "about:blank"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(2)
        cdp = Cdp(wait_for_page(debug_port))
        cdp.call("Page.enable")
        cdp.call("Page.navigate", {"url": f"{base}/index.html#workspace"})
        time.sleep(2.5)

        main = cdp.evaluate(DROP_ON_MAIN_JS)
        assert main and main.get("listItems") == 1, f"拖到左侧应载入文件：{main}"

        drawer = cdp.evaluate(DROP_ON_DRAWER_JS)
        assert drawer and drawer.get("workspaceRows") == 1, f"拖到抽屉应进工作区：{drawer}"
    finally:
        for process in (edge, server):
            process.terminate()
        for process in (edge, server):
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
        shutil.rmtree(temp, ignore_errors=True)
