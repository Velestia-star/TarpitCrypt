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
}

if (typeof document !== "undefined") {
  bind();
  switchMode("encrypt");
}
