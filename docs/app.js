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
// 右侧工作区（存放与管理）
// ---------------------------------------------------------------------------

const HISTORY_KEY = "tarpitcrypt.history.v1";
const HISTORY_LIMIT = 200;
const ITEM_MIME = "application/x-tarpit-item";

const workspace = { items: [], seq: 0, view: "workspace" };
let historyEntries = loadHistory();

/** 读历史记录（只存名字/时间/大小，绝不存文件内容）。 */
function loadHistory() {
  try {
    const raw = localStorage.getItem(HISTORY_KEY);
    const list = raw ? JSON.parse(raw) : [];
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

function saveHistory(list) {
  try {
    localStorage.setItem(HISTORY_KEY, JSON.stringify(list.slice(0, HISTORY_LIMIT)));
  } catch {
    /* 隐私模式下写不了，忽略即可，不影响加密 */
  }
}

/** 打开右侧抽屉。 */
function openDrawer() {
  $("drawer").classList.add("open");
  $("drawer").setAttribute("aria-hidden", "false");
  $("queueToggle").setAttribute("aria-expanded", "true");
  $("drawerBackdrop").hidden = false;
  requestAnimationFrame(() => $("drawerBackdrop").classList.add("show"));
  document.body.classList.add("drawer-open");
  const target = "#" + workspace.view;
  if (location.hash !== target) history.replaceState(null, "", target);
}

/** 关闭右侧抽屉。 */
function closeDrawer() {
  $("drawer").classList.remove("open");
  $("drawer").setAttribute("aria-hidden", "true");
  $("queueToggle").setAttribute("aria-expanded", "false");
  $("drawerBackdrop").classList.remove("show");
  setTimeout(() => { $("drawerBackdrop").hidden = true; }, 200);
  document.body.classList.remove("drawer-open");
  if (["#workspace", "#history", "#queue"].includes(location.hash)) {
    history.replaceState(null, "", location.pathname + location.search);
  }
}

function drawerOpen() {
  return $("drawer").classList.contains("open");
}

function formatTime(ms) {
  const d = new Date(ms);
  const pad = (n) => String(n).padStart(2, "0");
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function itemSize(item) {
  return item.files.reduce((sum, entry) => sum + entry.file.size, 0);
}

function workspaceNote(text) {
  $("queueSummary").textContent = text;
}

/** 切换「工作区 / 历史」。 */
function setView(view) {
  workspace.view = view;
  for (const tab of document.querySelectorAll(".dtab")) {
    tab.classList.toggle("active", tab.dataset.view === view);
  }
  $("viewWorkspace").hidden = view !== "workspace";
  $("viewHistory").hidden = view !== "history";
  if (view === "history") renderHistory();
  if (drawerOpen()) history.replaceState(null, "", "#" + view);
}

/** 往工作区加项。 */
function addWorkspaceEntries(entries) {
  if (!entries.length) return;
  for (const entry of entries) {
    workspace.items.push({
      id: ++workspace.seq,
      kind: entry.kind,
      name: entry.name,
      files: entry.files,
      status: "pending",
      output: null,
      error: null,
      selected: false,
    });
  }
  renderWorkspace();
}

function selectedItems() {
  return workspace.items.filter((item) => item.selected);
}

function renderWorkspace() {
  const list = $("queueList");
  const done = workspace.items.filter((item) => item.status === "done").length;
  const selected = selectedItems().length;

  $("queueBadge").textContent = String(workspace.items.length);
  $("queueEmpty").hidden = workspace.items.length > 0;
  list.innerHTML = "";
  for (const item of workspace.items) list.append(buildWorkspaceRow(item));

  $("queueSelectAll").checked = workspace.items.length > 0 && selected === workspace.items.length;
  $("queueDelete").disabled = selected === 0;
  $("queueDelete").textContent = selected ? `删除选中（${selected}）` : "删除选中";
  workspaceNote(`${workspace.items.length} 项 · ${done} 项已加密 · 选中 ${selected}`);
}

/** 一行：勾选 · 源 · 箭头 · 结果。 */
function buildWorkspaceRow(item) {
  const li = document.createElement("li");
  li.className = `queue-row ${item.status}${item.selected ? " selected" : ""}`;
  li.draggable = true;
  li.dataset.id = String(item.id);

  const check = document.createElement("span");
  check.className = "q-check";
  const box = document.createElement("input");
  box.type = "checkbox";
  box.checked = Boolean(item.selected);
  box.addEventListener("change", () => {
    item.selected = box.checked;
    renderWorkspace();
  });
  check.append(box);

  const source = document.createElement("div");
  source.className = "q-src";
  const name = document.createElement("span");
  name.className = "q-name";
  name.textContent = item.name;
  name.title = `${item.name}（拖到左侧可重新加密）`;
  const meta = document.createElement("span");
  meta.className = "q-meta";
  meta.textContent = item.kind === "dir"
    ? `文件夹 · ${item.files.length} 个文件 · ${formatSize(itemSize(item))}`
    : `文件 · ${formatSize(itemSize(item))}`;
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
  // 未加密时右侧保持空白——有意为之。

  li.append(check, source, arrow, output);
  return li;
}

/** 渲染历史记录。 */
function renderHistory() {
  const list = $("historyList");
  $("historyEmpty").hidden = historyEntries.length > 0;
  list.innerHTML = "";
  for (const entry of historyEntries) {
    const li = document.createElement("li");
    li.className = "history-row";

    const dot = document.createElement("span");
    dot.className = "history-empty-dot";
    dot.title = "已加密";

    const source = document.createElement("div");
    source.className = "q-src";
    const name = document.createElement("span");
    name.className = "q-name";
    name.textContent = entry.name;
    name.title = entry.name;
    const meta = document.createElement("span");
    meta.className = "q-meta";
    meta.textContent = `${formatTime(entry.at)} · ${formatSize(entry.sizeIn)}`;
    source.append(name, meta);

    const arrow = document.createElement("div");
    arrow.className = "q-arrow";
    arrow.textContent = "→";

    const output = document.createElement("div");
    output.className = "q-out";
    const outName = document.createElement("span");
    outName.className = "q-name";
    outName.textContent = entry.outName;
    outName.title = entry.outName;
    const outMeta = document.createElement("span");
    outMeta.className = "q-meta";
    outMeta.textContent = formatSize(entry.sizeOut);
    const del = document.createElement("button");
    del.className = "history-del";
    del.type = "button";
    del.textContent = "×";
    del.title = "从历史里删掉这条记录（不影响已下载的文件）";
    del.addEventListener("click", () => {
      historyEntries = historyEntries.filter((item) => item.at !== entry.at);
      saveHistory(historyEntries);
      renderHistory();
    });
    output.append(outName, outMeta);

    const tail = document.createElement("div");
    tail.append(del);

    li.append(dot, source, arrow, output);
    li.append(tail);
    list.append(li);
  }
}

/** 把拖进抽屉的文件/文件夹收成工作区条目。 */
async function collectWorkspaceEntries(dataTransfer) {
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
async function workspaceItemPayload(item) {
  if (item.kind === "dir" || item.files.length > 1) {
    const entries = [];
    for (const entry of item.files) {
      entries.push({ path: entry.path, data: await readBytes(entry.file) });
    }
    return core.makeZip(entries);
  }
  return readBytes(item.files[0].file);
}

/** 逐项加密，结果留在右侧，同时写入历史。 */
async function runWorkspace() {
  const pending = workspace.items.filter((item) => item.status === "pending");
  if (!pending.length) {
    workspaceNote(workspace.items.length ? "没有待加密的项" : "工作区是空的");
    return;
  }
  const passwordText = $("password").value;
  if (!passwordText) {
    workspaceNote("先在上面表单里填口令");
    return;
  }

  const params = collectParams();
  const keyfileFile = $("keyfile").files[0];
  const keyfile = keyfileFile ? await readBytes(keyfileFile) : new Uint8Array(0);
  const decoyFile = $("decoy").files[0];
  const decoyPlaintext = decoyFile ? await readBytes(decoyFile) : null;
  const decoyText = $("decoyPassword").value;
  if (decoyPlaintext && !decoyText) {
    workspaceNote("选了诱饵文件就要填诱饵口令");
    return;
  }

  $("queueRun").disabled = true;
  let index = 0;
  for (const item of pending) {
    index += 1;
    item.status = "running";
    item.error = null;
    renderWorkspace();
    workspaceNote(`正在加密 ${index}/${pending.length}：${item.name}`);
    await nextPaint();
    try {
      const payload = await workspaceItemPayload(item);
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
      historyEntries.unshift({
        name: item.name,
        kind: item.kind,
        sizeIn: itemSize(item),
        outName: item.output.name,
        sizeOut: item.output.size,
        at: Date.now(),
      });
      historyEntries = historyEntries.slice(0, HISTORY_LIMIT);
      saveHistory(historyEntries);
    } catch (error) {
      item.status = "error";
      item.error = error.message;
    }
    renderWorkspace();
  }
  $("queueRun").disabled = false;
}

/** 删除选中的行（只删记录，不动已下载的文件）。 */
function deleteSelected() {
  const selected = new Set(selectedItems().map((item) => item.id));
  if (!selected.size) return;
  for (const item of workspace.items) {
    if (selected.has(item.id) && item.output) URL.revokeObjectURL(item.output.url);
  }
  workspace.items = workspace.items.filter((item) => !selected.has(item.id));
  renderWorkspace();
}

/** 把 fromId 移到 toId 之前或之后。 */
function moveWorkspaceItem(fromId, toId, after) {
  const from = workspace.items.findIndex((item) => item.id === fromId);
  const to = workspace.items.findIndex((item) => item.id === toId);
  if (from < 0 || to < 0 || from === to) return;
  const [moved] = workspace.items.splice(from, 1);
  let target = workspace.items.findIndex((item) => item.id === toId);
  if (after) target += 1;
  workspace.items.splice(target, 0, moved);
  renderWorkspace();
}

/** 绑定工作区相关事件。 */
function bindWorkspace() {
  $("queueToggle").addEventListener("click", () => {
    if (drawerOpen()) closeDrawer();
    else openDrawer();
  });
  $("drawerClose").addEventListener("click", closeDrawer);
  $("drawerBackdrop").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && drawerOpen()) closeDrawer();
  });

  for (const tab of document.querySelectorAll(".dtab")) {
    tab.addEventListener("click", () => setView(tab.dataset.view));
  }

  $("queueRun").addEventListener("click", () => { void runWorkspace(); });
  $("queueDelete").addEventListener("click", deleteSelected);
  $("queueSelectAll").addEventListener("change", (event) => {
    for (const item of workspace.items) item.selected = event.target.checked;
    renderWorkspace();
  });

  $("historyClear").addEventListener("click", () => {
    historyEntries = [];
    saveHistory(historyEntries);
    renderHistory();
  });

  $("openPath").addEventListener("click", () => { $("pathModal").hidden = false; });
  $("pathModalClose").addEventListener("click", () => { $("pathModal").hidden = true; });
  $("pathModal").addEventListener("click", (event) => {
    if (event.target === $("pathModal")) $("pathModal").hidden = true;
  });

  $("queuePickFiles").addEventListener("change", (event) => {
    const entries = [...event.target.files].map((file) => ({
      kind: "file",
      name: file.name,
      files: [{ file, path: file.name }],
    }));
    addWorkspaceEntries(entries);
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
    addWorkspaceEntries(
      [...groups].map(([name, files]) => ({ kind: "dir", name, files })),
    );
    event.target.value = "";
  });

  // 拖进抽屉 = 加入工作区
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
      addWorkspaceEntries(await collectWorkspaceEntries(event.dataTransfer));
    } catch (error) {
      workspaceNote(`读取失败：${error.message}`);
    }
  });

  // 行内拖拽排序；拖到左侧主区域则交给上面绑定的事件重新加密
  let dragId = null;
  const list = $("queueList");
  list.addEventListener("dragstart", (event) => {
    const row = event.target.closest(".queue-row");
    if (!row) return;
    dragId = Number(row.dataset.id);
    row.classList.add("dragging");
    event.dataTransfer.effectAllowed = "copyMove";
    event.dataTransfer.setData(ITEM_MIME, String(dragId));
    event.dataTransfer.setData("text/plain", String(dragId));
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
    moveWorkspaceItem(dragId, Number(row.dataset.id), after);
    dragId = null;
  });

  if (location.hash === "#history") {
    setView("history");
    openDrawer();
  } else if (location.hash === "#workspace" || location.hash === "#queue") {
    openDrawer();
  }
  renderWorkspace();
  renderHistory();
}

/** 从工作区拖出来的条目 → 找回对应的 item。 */
function workspaceItemById(id) {
  return workspace.items.find((item) => item.id === Number(id)) || null;
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
    // 从工作区里拖出来的一行 → 直接放到左侧，走「加密并下载」原来的流程
    const itemId = event.dataTransfer.getData(ITEM_MIME);
    if (itemId) {
      const item = workspaceItemById(itemId);
      if (item) {
        setFiles(item.files, item.kind === "dir");
        status(`已从工作区取出「${item.name}」，可以直接加密`, "ok");
      }
      return;
    }
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
  bindWorkspace();
}

if (typeof document !== "undefined") {
  bind();
  switchMode("encrypt");
  // 就绪标记：既方便人工排查，也让无头浏览器测试能确认模块真的跑完了。
  document.documentElement.dataset.app = "ready";
}
