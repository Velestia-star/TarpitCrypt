/**
 * TarpitCrypt 网页版的界面逻辑。
 *
 * 全部加密运算都在浏览器里完成：文件不上传、口令不出内存。
 * 密码学实现见 `tarpit_core.js`，与 Python 版逐字节兼容。
 */

import * as core from "./tarpit_core.js";

const $ = (id) => document.getElementById(id);

const state = {
  mode: "encrypt",
  picked: [],
  isFolder: false,
};

const encoder = new TextEncoder();

/** 与 CLI / 服务端一致：NFC 规范化后 UTF-8。 */
function passwordBytes(text) {
  return encoder.encode(text.normalize("NFC"));
}

function formatSize(n) {
  if (n > 1048576) return `${(n / 1048576).toFixed(1)} MB`;
  if (n > 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${n} B`;
}

function status(text, kind) {
  const el = $("status");
  el.className = `status${kind ? ` ${kind}` : ""}`;
  el.textContent = text;
}

/** 让浏览器先把状态画出来，再去跑会卡住主线程的 Argon2。 */
const nextPaint = () => new Promise((resolve) => setTimeout(resolve, 30));

// ---------------------------------------------------------------------------
// 文件收集
// ---------------------------------------------------------------------------

function renderFiles() {
  const list = $("fileList");
  list.innerHTML = "";
  for (const { file, path } of state.picked) {
    const li = document.createElement("li");
    const name = document.createElement("span");
    name.textContent = path;
    const size = document.createElement("span");
    size.textContent = formatSize(file.size);
    li.append(name, size);
    list.append(li);
  }
  $("dropTitle").textContent = state.picked.length
    ? `已选 ${state.picked.length} 个文件`
    : "把文件或整个文件夹拖到这里";
}

function setFiles(items, folder) {
  state.picked = items;
  state.isFolder = folder || items.some((item) => item.path.includes("/"));
  renderFiles();
}

async function walkEntry(entry, prefix, out) {
  if (entry.isFile) {
    const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
    out.push({ file, path: prefix + file.name });
  } else if (entry.isDirectory) {
    const reader = entry.createReader();
    const readBatch = () => new Promise((resolve, reject) => reader.readEntries(resolve, reject));
    const children = [];
    let batch;
    do {
      batch = await readBatch();
      children.push(...batch);
    } while (batch.length);
    for (const child of children) await walkEntry(child, `${prefix}${entry.name}/`, out);
  }
}

async function collectFromDrop(dataTransfer) {
  const roots = [];
  for (const item of Array.from(dataTransfer.items)) {
    const entry = item.webkitGetAsEntry && item.webkitGetAsEntry();
    if (entry) roots.push(entry);
  }
  const out = [];
  for (const entry of roots) await walkEntry(entry, "", out);
  return out;
}

async function readBytes(file) {
  return new Uint8Array(await file.arrayBuffer());
}

// ---------------------------------------------------------------------------
// 下载
// ---------------------------------------------------------------------------

function download(bytes, filename) {
  const blob = new Blob([bytes], { type: "application/octet-stream" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
  return { url, blob };
}

function baseName(path) {
  const parts = String(path).replace(/\\/g, "/").split("/");
  return parts[parts.length - 1] || "file";
}

// ---------------------------------------------------------------------------
// 表单
// ---------------------------------------------------------------------------

function collectParams() {
  const preset = core.PRESETS[$("preset").value] || core.PRESETS.fast;
  return {
    ...preset,
    pow: Number($("pow").value),
  };
}

function switchMode(mode) {
  state.mode = mode;
  const encrypting = mode === "encrypt";
  for (const tab of document.querySelectorAll(".tab")) {
    tab.classList.toggle("active", tab.dataset.mode === mode);
  }
  $("confirmWrap").style.display = encrypting ? "" : "none";
  $("presetWrap").style.display = encrypting ? "" : "none";
  $("advanced").style.display = encrypting ? "" : "none";
  $("go").textContent = encrypting ? "加密并下载" : "解密并下载";
  $("dropHint").textContent = encrypting
    ? "支持多文件；文件夹会打包成一个 .tarpit"
    : "一次请上传一个 .tarpit 文件";
  $("pickDir").disabled = !encrypting;
  $("result").className = "result";
  status("");
}

// ---------------------------------------------------------------------------
// 主流程
// ---------------------------------------------------------------------------

async function runEncrypt() {
  const passwordText = $("password").value;
  if (!passwordText) throw new Error("口令不能为空");
  if ($("password2").value !== passwordText) throw new Error("两次口令不一致");

  const keyfileFile = $("keyfile").files[0];
  const keyfile = keyfileFile ? await readBytes(keyfileFile) : new Uint8Array(0);

  let payload;
  if (state.isFolder || state.picked.length > 1) {
    const entries = [];
    for (const { file, path } of state.picked) {
      entries.push({ path, data: await readBytes(file) });
    }
    payload = core.makeZip(entries);
  } else {
    payload = await readBytes(state.picked[0].file);
  }

  const decoyFile = $("decoy").files[0];
  let decoyPlaintext = null;
  let decoyPassword = null;
  if (decoyFile) {
    const text = $("decoyPassword").value;
    if (!text) throw new Error("启用了诱饵文件却没给诱饵口令");
    decoyPlaintext = await readBytes(decoyFile);
    decoyPassword = passwordBytes(text);
  }

  status("正在跑 Argon2id…（页面会卡住几秒，这是故意的）");
  await nextPaint();

  const blob = await core.encrypt(payload, passwordBytes(passwordText), {
    params: collectParams(),
    keyfile,
    decoyPlaintext,
    decoyPassword,
  });

  const sourceName = state.isFolder || state.picked.length > 1
    ? String(state.picked[0].path).split("/")[0]
    : baseName(state.picked[0].path);
  return { bytes: blob, filename: `${sourceName}.tarpit` };
}

async function runDecrypt() {
  const passwordText = $("password").value;
  if (!passwordText) throw new Error("口令不能为空");
  if (state.picked.length !== 1) throw new Error("解密一次只能上传一个文件");

  const keyfileFile = $("keyfile").files[0];
  const keyfile = keyfileFile ? await readBytes(keyfileFile) : new Uint8Array(0);
  const blob = await readBytes(state.picked[0].file);

  status("正在跑 Argon2id…（页面会卡住几秒，这是故意的）");
  await nextPaint();

  const { data, isDecoy } = await core.decrypt(blob, passwordBytes(passwordText), { keyfile });

  let filename = baseName(state.picked[0].path);
  if (filename.endsWith(".tarpit")) filename = filename.slice(0, -".tarpit".length);
  if (core.isZip(data) && !filename.endsWith(".zip")) filename += ".zip";
  return { bytes: data, filename: filename || "plain.bin", isDecoy };
}

async function onSubmit() {
  $("result").className = "result";
  if (!state.picked.length) return status("先拖点东西进来", "bad");

  const button = $("go");
  button.disabled = true;
  const started = performance.now();
  let timer = setInterval(() => {
    const seconds = ((performance.now() - started) / 1000).toFixed(0);
    status(`正在跑 Argon2id… ${seconds}s（这是在故意烧时间）`);
  }, 400);

  try {
    const outcome = state.mode === "encrypt" ? await runEncrypt() : await runDecrypt();
    clearInterval(timer);
    timer = null;
    const { url, blob } = download(outcome.bytes, outcome.filename);
    const elapsed = ((performance.now() - started) / 1000).toFixed(1);
    status(`完成，用时 ${elapsed}s`, "ok");

    const box = $("result");
    box.innerHTML = "";
    if (outcome.isDecoy) {
      const line = document.createElement("p");
      const badge = document.createElement("span");
      badge.className = "badge";
      badge.textContent = "诱饵层";
      line.append(badge, document.createTextNode(" 你解出的是诱饵内容。"));
      box.append(line);
    }
    const line = document.createElement("p");
    const link = document.createElement("a");
    link.href = url;
    link.download = outcome.filename;
    link.textContent = outcome.filename;
    line.append(document.createTextNode("已下载 "), link,
      document.createTextNode(`（${formatSize(blob.size)}）`));
    box.append(line);

    const hint = document.createElement("p");
    hint.className = "hint";
    hint.textContent = state.mode === "encrypt"
      ? "口令和 keyfile 丢了就永远解不开，没有后门。"
      : "解密成功。";
    box.append(hint);
    box.className = "result show";
  } catch (error) {
    clearInterval(timer);
    status(`失败：${error.message}`, "bad");
  } finally {
    button.disabled = false;
  }
}

// ---------------------------------------------------------------------------
// 右侧加密队列
// ---------------------------------------------------------------------------

const queue = { items: [], seq: 0 };

/** 打开右侧抽屉。 */
function openDrawer() {
  $("drawer").classList.add("open");
  $("drawer").setAttribute("aria-hidden", "false");
  $("queueToggle").setAttribute("aria-expanded", "true");
  $("drawerBackdrop").hidden = false;
  requestAnimationFrame(() => $("drawerBackdrop").classList.add("show"));
  document.body.classList.add("drawer-open");
  if (location.hash !== "#queue") history.replaceState(null, "", "#queue");
}

/** 关闭右侧抽屉。 */
function closeDrawer() {
  $("drawer").classList.remove("open");
  $("drawer").setAttribute("aria-hidden", "true");
  $("queueToggle").setAttribute("aria-expanded", "false");
  $("drawerBackdrop").classList.remove("show");
  setTimeout(() => { $("drawerBackdrop").hidden = true; }, 200);
  document.body.classList.remove("drawer-open");
  if (location.hash === "#queue") {
    history.replaceState(null, "", location.pathname + location.search);
  }
}

function drawerOpen() {
  return $("drawer").classList.contains("open");
}

/** 队列里所有文件的总字节数。 */
function queueItemSize(item) {
  return item.files.reduce((sum, entry) => sum + entry.file.size, 0);
}

function queueNote(text) {
  $("queueSummary").textContent = text;
}

/** 把若干项加入队列。 */
function addQueueEntries(entries) {
  if (!entries.length) return;
  for (const entry of entries) {
    queue.items.push({
      id: ++queue.seq,
      kind: entry.kind,
      name: entry.name,
      files: entry.files,
      status: "pending",
      output: null,
      error: null,
    });
  }
  renderQueue();
}

/** 重新渲染整个队列。 */
function renderQueue() {
  const list = $("queueList");
  const done = queue.items.filter((item) => item.status === "done").length;
  $("queueBadge").textContent = String(queue.items.length);
  $("queueEmpty").hidden = queue.items.length > 0;
  list.innerHTML = "";
  for (const item of queue.items) list.append(buildQueueRow(item));
  queueNote(
    queue.items.length
      ? `${queue.items.length} 项 · ${done} 项已加密`
      : "0 项",
  );
}

/** 构建一行：左源文件 → 箭头 → 右加密结果。 */
function buildQueueRow(item) {
  const li = document.createElement("li");
  li.className = `queue-row ${item.status}`;
  li.draggable = true;
  li.dataset.id = String(item.id);

  const source = document.createElement("div");
  source.className = "q-src";
  const name = document.createElement("span");
  name.className = "q-name";
  name.textContent = item.name;
  name.title = item.name;
  const meta = document.createElement("span");
  meta.className = "q-meta";
  meta.textContent = item.kind === "dir"
    ? `文件夹 · ${item.files.length} 个文件 · ${formatSize(queueItemSize(item))}`
    : `文件 · ${formatSize(queueItemSize(item))}`;
  source.append(name, meta);

  const arrow = document.createElement("div");
  arrow.className = "q-arrow";
  arrow.textContent = "→";

  const output = document.createElement("div");
  output.className = "q-out";
  if (item.status === "done" && item.output) {
    const link = document.createElement("a");
    link.href = item.output.url;
    link.download = item.output.name;
    link.textContent = item.output.name;
    link.title = `${item.output.name}（${formatSize(item.output.size)}）`;
    const size = document.createElement("span");
    size.className = "q-meta";
    size.textContent = formatSize(item.output.size);
    output.append(link, size);
  } else if (item.status === "running") {
    output.textContent = "加密中…";
  } else if (item.status === "error") {
    const error = document.createElement("span");
    error.className = "q-error";
    error.textContent = item.error || "失败";
    output.append(error);
  }
  // 未加密时右侧保持空白——这是有意为之。

  li.append(source, arrow, output);
  return li;
}

/** 把拖进抽屉的文件/文件夹收成队列项。 */
async function collectQueueEntries(dataTransfer) {
  const roots = [];
  for (const item of Array.from(dataTransfer.items || [])) {
    const entry = item.webkitGetAsEntry && item.webkitGetAsEntry();
    if (entry) roots.push(entry);
  }
  const items = [];
  for (const entry of roots) {
    if (entry.isFile) {
      const file = await new Promise((resolve, reject) => entry.file(resolve, reject));
      items.push({ kind: "file", name: file.name, files: [{ file, path: file.name }] });
    } else if (entry.isDirectory) {
      const files = [];
      await walkEntry(entry, "", files);
      items.push({ kind: "dir", name: entry.name, files });
    }
  }
  return items;
}

/** 取出一项待加密的明文（文件夹打 zip，单文件直传）。 */
async function queueItemPayload(item) {
  if (item.kind === "dir" || item.files.length > 1) {
    const entries = [];
    for (const entry of item.files) {
      entries.push({ path: entry.path, data: await readBytes(entry.file) });
    }
    return core.makeZip(entries);
  }
  return readBytes(item.files[0].file);
}

/** 逐项加密队列里待处理的项，结果留在右侧。 */
async function runQueue() {
  const pending = queue.items.filter((item) => item.status === "pending");
  if (!pending.length) {
    queueNote(queue.items.length ? "没有待加密的项" : "队列是空的");
    return;
  }
  const passwordText = $("password").value;
  if (!passwordText) {
    queueNote("先在上面表单里填口令");
    return;
  }
  if (passwordText !== $("password2").value && state.mode === "encrypt") {
    queueNote("两次口令不一致");
    return;
  }

  const params = collectParams();
  const keyfileFile = $("keyfile").files[0];
  const keyfile = keyfileFile ? await readBytes(keyfileFile) : new Uint8Array(0);
  const decoyFile = $("decoy").files[0];
  const decoyPlaintext = decoyFile ? await readBytes(decoyFile) : null;
  const decoyText = $("decoyPassword").value;
  if (decoyPlaintext && !decoyText) {
    queueNote("选了诱饵文件就要填诱饵口令");
    return;
  }

  $("queueRun").disabled = true;
  let index = 0;
  for (const item of pending) {
    index += 1;
    item.status = "running";
    item.error = null;
    renderQueue();
    queueNote(`正在加密 ${index}/${pending.length}：${item.name}`);
    await nextPaint();
    try {
      const payload = await queueItemPayload(item);
      const blob = await core.encrypt(payload, passwordBytes(passwordText), {
        params,
        keyfile,
        decoyPlaintext,
        decoyPassword: decoyPlaintext ? passwordBytes(decoyText) : null,
      });
      item.output = {
        url: URL.createObjectURL(new Blob([blob], { type: "application/octet-stream" })),
        name: `${item.name}.tarpit`,
        size: blob.length,
      };
      item.status = "done";
    } catch (error) {
      item.status = "error";
      item.error = error.message;
    }
    renderQueue();
  }
  $("queueRun").disabled = false;
}

/** 把 fromId 移到 toId 之前或之后。 */
function moveQueueItem(fromId, toId, after) {
  const from = queue.items.findIndex((item) => item.id === fromId);
  const to = queue.items.findIndex((item) => item.id === toId);
  if (from < 0 || to < 0 || from === to) return;
  const [moved] = queue.items.splice(from, 1);
  let target = queue.items.findIndex((item) => item.id === toId);
  if (after) target += 1;
  queue.items.splice(target, 0, moved);
  renderQueue();
}

/** 绑定队列相关事件。 */
function bindQueue() {
  $("queueToggle").addEventListener("click", () => {
    if (drawerOpen()) closeDrawer();
    else openDrawer();
  });
  $("drawerClose").addEventListener("click", closeDrawer);
  $("drawerBackdrop").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && drawerOpen()) closeDrawer();
  });

  $("queueRun").addEventListener("click", () => { void runQueue(); });
  $("queueClear").addEventListener("click", () => {
    for (const item of queue.items) {
      if (item.output) URL.revokeObjectURL(item.output.url);
    }
    queue.items = [];
    renderQueue();
  });

  $("queuePickFiles").addEventListener("change", (event) => {
    const entries = [...event.target.files].map((file) => ({
      kind: "file",
      name: file.name,
      files: [{ file, path: file.name }],
    }));
    addQueueEntries(entries);
    event.target.value = "";
  });

  $("queuePickDir").addEventListener("change", (event) => {
    const groups = new Map();
    for (const file of event.target.files) {
      const relative = file.webkitRelativePath || file.name;
      const root = relative.split("/")[0];
      if (!groups.has(root)) groups.set(root, []);
      groups.get(root).push({ file, path: relative });
    }
    addQueueEntries(
      [...groups].map(([name, files]) => ({ kind: "dir", name, files })),
    );
    event.target.value = "";
  });

  // 拖进抽屉 = 加入队列
  const drawer = $("drawer");
  let dragDepth = 0;
  drawer.addEventListener("dragenter", (event) => {
    if (!event.dataTransfer.types.includes("Files")) return;
    dragDepth += 1;
    drawer.classList.add("over");
  });
  drawer.addEventListener("dragleave", () => {
    dragDepth = Math.max(0, dragDepth - 1);
    if (dragDepth === 0) drawer.classList.remove("over");
  });
  drawer.addEventListener("dragover", (event) => {
    if (event.dataTransfer.types.includes("Files")) event.preventDefault();
  });
  drawer.addEventListener("drop", async (event) => {
    dragDepth = 0;
    drawer.classList.remove("over");
    if (!event.dataTransfer.types.includes("Files")) return;
    event.preventDefault();
    try {
      addQueueEntries(await collectQueueEntries(event.dataTransfer));
    } catch (error) {
      queueNote(`读取失败：${error.message}`);
    }
  });

  // 行内拖拽排序
  let dragId = null;
  const list = $("queueList");
  list.addEventListener("dragstart", (event) => {
    const row = event.target.closest(".queue-row");
    if (!row) return;
    dragId = Number(row.dataset.id);
    row.classList.add("dragging");
    event.dataTransfer.effectAllowed = "move";
  });
  list.addEventListener("dragend", () => {
    dragId = null;
    for (const row of list.querySelectorAll(".queue-row")) {
      row.classList.remove("dragging", "drop-before", "drop-after");
    }
  });
  list.addEventListener("dragover", (event) => {
    const row = event.target.closest(".queue-row");
    if (!row || dragId === null) return;
    event.preventDefault();
    const rect = row.getBoundingClientRect();
    const after = event.clientY > rect.top + rect.height / 2;
    for (const other of list.querySelectorAll(".queue-row")) {
      other.classList.toggle("drop-before", other === row && !after);
      other.classList.toggle("drop-after", other === row && after);
    }
  });
  list.addEventListener("drop", (event) => {
    const row = event.target.closest(".queue-row");
    if (!row || dragId === null) return;
    event.preventDefault();
    const rect = row.getBoundingClientRect();
    const after = event.clientY > rect.top + rect.height / 2;
    moveQueueItem(dragId, Number(row.dataset.id), after);
    dragId = null;
  });

  if (location.hash === "#queue") openDrawer();
  renderQueue();
}

// ---------------------------------------------------------------------------
// 事件绑定
// ---------------------------------------------------------------------------

function bind() {
  const drop = $("drop");
  drop.addEventListener("click", (event) => {
    if (!event.target.closest("label")) $("pickFiles").click();
  });
  drop.addEventListener("dragover", (event) => {
    event.preventDefault();
    drop.classList.add("over");
  });
  drop.addEventListener("dragleave", () => drop.classList.remove("over"));
  drop.addEventListener("drop", async (event) => {
    event.preventDefault();
    drop.classList.remove("over");
    try {
      setFiles(await collectFromDrop(event.dataTransfer), false);
    } catch (error) {
      status(`读取拖入的内容失败：${error.message}`, "bad");
    }
  });

  $("pickFiles").addEventListener("change", (event) => {
    setFiles([...event.target.files].map((file) => ({ file, path: file.name })), false);
  });
  $("pickDir").addEventListener("change", (event) => {
    setFiles([...event.target.files].map((file) => ({
      file, path: file.webkitRelativePath || file.name,
    })), true);
  });

  for (const tab of document.querySelectorAll(".tab")) {
    tab.addEventListener("click", () => switchMode(tab.dataset.mode));
  }
  $("go").addEventListener("click", onSubmit);
  bindQueue();
}

if (typeof document !== "undefined") {
  bind();
  switchMode("encrypt");
  // 就绪标记：既方便人工排查，也让无头浏览器测试能确认模块真的跑完了。
  document.documentElement.dataset.app = "ready";
}
