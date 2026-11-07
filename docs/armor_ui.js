/**
 * 本地版 armor 面板：加固 / 还原。
 *
 * 只在本机 Web（tarpitcrypt_server.py 注入 TARPIT_LOCAL）里启用；在线版
 * 直接 return，面板保持 hidden。所有耗时计算都在服务端 worker 里跑，
 * 这里只负责收集源包、轮询进度、展示下载/打开入口。
 */

import { checkPasswordStrength } from "./core_adapter.js";

const LOCAL = globalThis.TARPIT_LOCAL === true;
const $ = (id) => document.getElementById(id);

let armorPicked = [];
let armorRestoreFile = null;

function formatSize(bytes) {
  if (bytes > 1048576) return `${(bytes / 1048576).toFixed(1)} MB`;
  if (bytes > 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${bytes} B`;
}

function setStatus(element, text, kind = "") {
  element.className = `status${kind ? ` ${kind}` : ""}`;
  element.textContent = text;
}

function setBar(wrap, bar, value) {
  wrap.hidden = false;
  bar.style.width = `${Math.round(Math.max(0, Math.min(1, value)) * 100)}%`;
}

function errorText(data, status) {
  return (data && data.error) || `HTTP ${status}`;
}

async function readEntry(entry, prefix, out) {
  return new Promise((resolve) => {
    if (entry.isFile) {
      entry.file(
        (file) => {
          out.push({ file, path: prefix + file.name });
          resolve();
        },
        () => resolve(),
      );
      return;
    }
    if (entry.isDirectory) {
      const reader = entry.createReader();
      const readBatch = () => {
        reader.readEntries(
          (entries) => {
            if (!entries.length) {
              resolve();
              return;
            }
            Promise.all(
              entries.map((child) => readEntry(child, `${prefix}${entry.name}/`, out)),
            ).then(readBatch, readBatch);
          },
          () => resolve(),
        );
      };
      readBatch();
      return;
    }
    resolve();
  });
}

async function collectDropFiles(dataTransfer) {
  const items = [...(dataTransfer.items || [])];
  const entries = items
    .map((item) => (item.webkitGetAsEntry ? item.webkitGetAsEntry() : null))
    .filter(Boolean);
  if (!entries.length) {
    return [...dataTransfer.files].map((file) => ({ file, path: file.name }));
  }
  const out = [];
  await Promise.all(entries.map((entry) => readEntry(entry, "", out)));
  return out;
}

function renderPicked() {
  const list = $("armorFiles");
  list.innerHTML = "";
  for (const { file, path } of armorPicked) {
    const line = document.createElement("li");
    const name = document.createElement("span");
    name.textContent = path;
    const size = document.createElement("span");
    size.textContent = formatSize(file.size);
    line.append(name, size);
    list.append(line);
  }
}

function setPicked(entries) {
  armorPicked = entries;
  renderPicked();
}

function bindPickDrop() {
  const drop = $("armorDrop");
  const pick = $("armorPickFiles");
  const pickDir = $("armorPickDir");

  drop.addEventListener("click", (event) => {
    if (!event.target.closest("label")) pick.click();
  });
  pick.addEventListener("change", (event) => {
    setPicked([...event.target.files].map((file) => ({ file, path: file.name })));
  });
  pickDir.addEventListener("change", (event) => {
    setPicked(
      [...event.target.files].map((file) => ({
        file,
        path: file.webkitRelativePath || file.name,
      })),
    );
  });

  for (const [eventName, add] of [["dragenter", true], ["dragover", true], ["dragleave", false]]) {
    drop.addEventListener(eventName, (event) => {
      event.preventDefault();
      drop.classList.toggle("over", add);
    });
  }
  drop.addEventListener("drop", async (event) => {
    event.preventDefault();
    drop.classList.remove("over");
    try {
      const entries = await collectDropFiles(event.dataTransfer);
      if (entries.length) setPicked(entries);
    } catch (error) {
      setStatus($("armorStatus"), `读取拖入内容失败：${error.message}`, "bad");
    }
  });

  const restoreDrop = $("armorRestoreDrop");
  const restorePick = $("armorRestorePick");
  restoreDrop.addEventListener("click", (event) => {
    if (!event.target.closest("label")) restorePick.click();
  });
  restorePick.addEventListener("change", (event) => {
    armorRestoreFile = event.target.files[0] || null;
    $("armorRestoreName").textContent = armorRestoreFile
      ? armorRestoreFile.name
      : "还没有选择文件";
  });
  for (const [eventName, add] of [["dragenter", true], ["dragover", true], ["dragleave", false]]) {
    restoreDrop.addEventListener(eventName, (event) => {
      event.preventDefault();
      restoreDrop.classList.toggle("over", add);
    });
  }
  restoreDrop.addEventListener("drop", (event) => {
    event.preventDefault();
    restoreDrop.classList.remove("over");
    const file = event.dataTransfer.files[0];
    if (file) {
      armorRestoreFile = file;
      $("armorRestoreName").textContent = file.name;
    }
  });
}

function fillSelect(element, values, selected) {
  element.innerHTML = "";
  for (const value of values) {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = value;
    if (value === selected) option.selected = true;
    element.append(option);
  }
}

async function loadProfiles() {
  const response = await fetch("/api/armor/profiles");
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(errorText(data, response.status));
  fillSelect($("armorProfile"), data.profiles, data.defaults.profile);
  fillSelect($("armorPoison"), data.poisons, data.defaults.poison);
  fillSelect($("armorStyle"), data.styles, data.defaults.style);
  fillSelect($("armorInjection"), data.injections, data.defaults.injection);
  $("armorLayers").value = data.defaults.layers;
  $("armorSidecar").checked = Boolean(data.defaults.sidecar);
}

function updatePasswordHint() {
  const box = $("armorPwWarning");
  const text = $("armorPassword").value;
  if (!text) {
    box.hidden = true;
    box.textContent = "";
    return;
  }
  const result = checkPasswordStrength(text);
  if (result.ok) {
    box.hidden = true;
    box.textContent = "";
    return;
  }
  box.hidden = false;
  box.textContent = `口令偏弱：${result.hint}。加固要求口令至少 8 位、至少两类字符。`;
}

async function pollJob(jobId, status, barWrap, bar, timeoutMs = 15 * 60 * 1000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const response = await fetch(`/api/armor/jobs/${jobId}`);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(errorText(data, response.status));
    const job = data.job;
    status.textContent = job.message || job.status;
    if (typeof job.progress === "number") setBar(barWrap, bar, job.progress);
    if (job.status === "done") return job;
    if (job.status === "error") throw new Error(job.error || "任务失败");
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("任务超时（15 分钟）");
}

function addDownload(result, url, label) {
  const line = document.createElement("p");
  const link = document.createElement("a");
  link.href = url;
  link.textContent = label;
  line.append(link);
  result.append(line);
  return link;
}

function addOpenButton(result, artifact, statusElement, label = "打开所在目录") {
  const line = document.createElement("p");
  const button = document.createElement("button");
  button.type = "button";
  button.textContent = label;
  button.style.cssText = [
    "background:none", "border:0", "padding:0", "font:inherit",
    "color:var(--accent)", "cursor:pointer", "text-decoration:underline dotted",
  ].join(";");
  button.addEventListener("click", async () => {
    try {
      const response = await fetch("/api/reveal", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ artifact }),
      });
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(errorText(data, response.status));
      setStatus(statusElement, "已在文件管理器中打开", "ok");
    } catch (error) {
      setStatus(statusElement, `打开失败：${error.message}`, "bad");
    }
  });
  line.append(button);
  result.append(line);
}

function showNotice(result, text, kind = "hint") {
  const line = document.createElement("p");
  line.className = kind;
  line.textContent = text;
  result.append(line);
}

async function runPack() {
  const status = $("armorStatus");
  const result = $("armorResult");
  const button = $("armorGo");
  const password = $("armorPassword").value;
  const again = $("armorPassword2").value;

  if (!armorPicked.length) return setStatus(status, "先拖入或选择程序包", "bad");
  if (!password) return setStatus(status, "口令不能为空", "bad");
  if (password !== again) return setStatus(status, "两次口令不一致", "bad");
  const strength = checkPasswordStrength(password);
  if (!strength.ok) return setStatus(status, `口令偏弱：${strength.hint}`, "bad");
  const layers = Number($("armorLayers").value);
  if (!Number.isInteger(layers) || layers < 2 || layers > 8) {
    return setStatus(status, "层数必须是 2~8 的整数", "bad");
  }

  button.disabled = true;
  result.className = "result";
  result.innerHTML = "";
  setStatus(status, "正在提交加固任务…");
  $("armorBarWrap").hidden = false;
  $("armorBar").style.width = "0%";

  try {
    const form = new FormData();
    form.append("password", password);
    form.append("layers", String(layers));
    form.append("profile", $("armorProfile").value);
    form.append("poison", $("armorPoison").value);
    form.append("style", $("armorStyle").value);
    form.append("injection", $("armorInjection").value);
    form.append("sidecar", $("armorSidecar").checked ? "1" : "0");
    for (const { file, path } of armorPicked) form.append("files", file, path);

    const response = await fetch("/api/armor/pack", { method: "POST", body: form });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(errorText(data, response.status));

    const job = await pollJob(
      data.job,
      status,
      $("armorBarWrap"),
      $("armorBar"),
    );
    const info = job.result;
    setStatus(status, "加固完成", "ok");
    result.className = "result show";
    showNotice(
      result,
      `已生成 ${info.layers} 层容器，${formatSize(info.size)}；原程序没有被修改。`,
    );
    addDownload(result, `/api/artifacts/${info.artifact}`, "下载 .armored");
    if (info.sidecarArtifact) {
      addDownload(result, `/api/artifacts/${info.sidecarArtifact}`, "下载伴生诱饵 zip");
    }
    if (info.sidecarError) {
      showNotice(result, `伴生诱饵未生成：${info.sidecarError}`, "pw-warn");
    }
    addOpenButton(result, info.artifact, status);
  } catch (error) {
    setStatus(status, `失败：${error.message}`, "bad");
  } finally {
    button.disabled = false;
  }
}

async function runRestore() {
  const status = $("armorRestoreStatus");
  const result = $("armorRestoreResult");
  const button = $("armorRestoreGo");
  const password = $("armorRestorePassword").value;

  if (!armorRestoreFile) return setStatus(status, "先选择 .armored 文件", "bad");
  if (!password) return setStatus(status, "口令不能为空", "bad");

  button.disabled = true;
  result.className = "result";
  result.innerHTML = "";
  setStatus(status, "正在提交还原任务…");
  $("armorRestoreBarWrap").hidden = false;
  $("armorRestoreBar").style.width = "0%";

  try {
    const form = new FormData();
    form.append("password", password);
    form.append("files", armorRestoreFile, armorRestoreFile.name);
    const response = await fetch("/api/armor/restore", { method: "POST", body: form });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(errorText(data, response.status));

    const job = await pollJob(
      data.job,
      status,
      $("armorRestoreBarWrap"),
      $("armorRestoreBar"),
    );
    const info = job.result;
    setStatus(status, "还原完成", "ok");
    result.className = "result show";
    showNotice(result, `已还原 ${info.fileCount} 个文件，${formatSize(info.size)}。`);
    addDownload(result, `/api/artifacts/${info.artifact}`, "下载还原 zip");
    addOpenButton(result, info.artifact, status);
  } catch (error) {
    setStatus(status, `失败：${error.message}`, "bad");
  } finally {
    button.disabled = false;
  }
}

function bindTabs() {
  const tabs = [...document.querySelectorAll(".armor-tab")];
  const panes = {
    pack: $("armorPackPane"),
    restore: $("armorRestorePane"),
  };
  for (const tab of tabs) {
    tab.addEventListener("click", () => {
      for (const item of tabs) item.classList.toggle("active", item === tab);
      for (const [mode, pane] of Object.entries(panes)) {
        pane.hidden = mode !== tab.dataset.armorMode;
      }
    });
  }
}

async function init() {
  const panel = $("armorPanel");
  if (!panel) return;
  panel.hidden = false;
  bindTabs();
  bindPickDrop();
  $("armorPassword").addEventListener("input", updatePasswordHint);
  $("armorGo").addEventListener("click", runPack);
  $("armorRestoreGo").addEventListener("click", runRestore);

  try {
    await loadProfiles();
  } catch (error) {
    setStatus($("armorStatus"), `加载 armor 参数失败：${error.message}`, "bad");
    $("armorGo").disabled = true;
  }
}

if (LOCAL && typeof document !== "undefined") {
  init();
}
