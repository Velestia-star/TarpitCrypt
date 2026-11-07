/**
 * 本地版 armor 面板：加固 / 还原 / 伴生 / 运行报告。
 *
 * 只在本机 Web（tarpitcrypt_server.py 注入 TARPIT_LOCAL）里启用；在线版
 * 直接 return，面板保持 hidden。所有耗时计算都在服务端 worker 里跑，
 * 这里只负责收集源包、轮询进度、展示下载/打开入口和会话报告。
 */

import { checkPasswordStrength } from "./core_adapter.js";

const LOCAL = globalThis.TARPIT_LOCAL === true;
const $ = (id) => document.getElementById(id);

let armorPicked = [];
let armorRestoreFile = null;
let armorKitPicked = [];
let armorKitArmored = null;
let armorReportData = null;
let armorSourcePath = "";
let armorKitSourcePath = "";
let armorRestorePath = "";
let armorOutDir = "";

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

function pathHeaders() {
  const token = globalThis.TARPIT_PATH_TOKEN;
  return token ? { "X-Tarpit-Path-Token": token } : {};
}

function logArmor(message, prefix = "") {
  const log = $("armorLog");
  const stamp = new Date().toLocaleTimeString();
  const line = `[${stamp}]${prefix ? ` ${prefix}` : ""} ${message}`;
  log.textContent += `${line}\n`;
  const lines = log.textContent.split("\n");
  if (lines.length > 240) log.textContent = lines.slice(-240).join("\n");
  log.scrollTop = log.scrollHeight;
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

function renderPicked(entries, target) {
  target.innerHTML = "";
  for (const { file, path } of entries) {
    const line = document.createElement("li");
    const name = document.createElement("span");
    name.textContent = path;
    const size = document.createElement("span");
    size.textContent = formatSize(file.size);
    line.append(name, size);
    target.append(line);
  }
}

function bindDrop(drop, pick, pickDir, setter, list) {
  drop.addEventListener("click", (event) => {
    if (!event.target.closest("label") && !event.target.closest("button")) pick.click();
  });
  pick.addEventListener("change", (event) => {
    setter([...event.target.files].map((file) => ({ file, path: file.name })));
    renderPicked(
      pick.id === "armorPickFiles" ? armorPicked : armorKitPicked,
      list,
    );
  });
  pickDir.addEventListener("change", (event) => {
    setter(
      [...event.target.files].map((file) => ({
        file,
        path: file.webkitRelativePath || file.name,
      })),
    );
    renderPicked(
      pick.id === "armorPickFiles" ? armorPicked : armorKitPicked,
      list,
    );
  });
  for (const [eventName, add] of [
    ["dragenter", true],
    ["dragover", true],
    ["dragleave", false],
  ]) {
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
      if (entries.length) {
        setter(entries);
        renderPicked(
          pick.id === "armorPickFiles" ? armorPicked : armorKitPicked,
          list,
        );
      }
    } catch (error) {
      setStatus($("armorStatus"), `读取拖入内容失败：${error.message}`, "bad");
    }
  });
}

function setArmorPicked(entries) {
  armorPicked = entries;
}

function setKitPicked(entries) {
  armorKitPicked = entries;
}

function bindPickDrop() {
  bindDrop(
    $("armorDrop"), $("armorPickFiles"), $("armorPickDir"),
    setArmorPicked, $("armorFiles"),
  );
  bindDrop(
    $("armorKitDrop"), $("armorKitPickFiles"), $("armorKitPickDir"),
    setKitPicked, $("armorKitFiles"),
  );

  const restoreDrop = $("armorRestoreDrop");
  const restorePick = $("armorRestorePick");
  restoreDrop.addEventListener("click", (event) => {
    if (!event.target.closest("label") && !event.target.closest("button")) restorePick.click();
  });
  restorePick.addEventListener("change", (event) => {
    armorRestoreFile = event.target.files[0] || null;
    $("armorRestoreName").textContent = armorRestoreFile
      ? armorRestoreFile.name
      : "还没有选择文件";
  });
  for (const [eventName, add] of [
    ["dragenter", true],
    ["dragover", true],
    ["dragleave", false],
  ]) {
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

  $("armorKitArmored").addEventListener("change", (event) => {
    armorKitArmored = event.target.files[0] || null;
  });
  $("armorKitUsePack").addEventListener("click", () => {
    if (!armorPicked.length) {
      setStatus($("armorKitStatus"), "加固页还没有源包", "bad");
      return;
    }
    setKitPicked([...armorPicked]);
    renderPicked(armorKitPicked, $("armorKitFiles"));
    setStatus($("armorKitStatus"), `已复用加固页的 ${armorPicked.length} 个文件`, "ok");
  });

  const clearPackPath = () => {
    armorSourcePath = "";
    $("armorSourcePathLabel").hidden = true;
  };
  $("armorPickFiles").addEventListener("change", clearPackPath);
  $("armorPickDir").addEventListener("change", clearPackPath);
  $("armorDrop").addEventListener("drop", clearPackPath);

  const clearKitPath = () => {
    armorKitSourcePath = "";
    $("armorKitSourcePathLabel").hidden = true;
  };
  $("armorKitPickFiles").addEventListener("change", clearKitPath);
  $("armorKitPickDir").addEventListener("change", clearKitPath);
  $("armorKitDrop").addEventListener("drop", clearKitPath);

  const clearRestorePath = () => {
    armorRestorePath = "";
    $("armorRestorePathLabel").hidden = true;
  };
  $("armorRestorePick").addEventListener("change", clearRestorePath);
  $("armorRestoreDrop").addEventListener("drop", clearRestorePath);
}

function setNativePath(labelId, path) {
  const label = $(labelId);
  if (!label) return;
  label.hidden = false;
  label.textContent = path;
}

async function pickNativePath(method, setter, labelId) {
  const api = globalThis.pywebview?.api;
  if (!api || typeof api[method] !== "function") return;
  try {
    const path = await api[method]();
    if (!path) return;
    setter(path);
    setNativePath(labelId, path);
    logArmor(`已选择本机路径：${path}`, "[桌面]");
  } catch (error) {
    logArmor(`原生选择失败：${error.message}`, "[桌面]");
  }
}

function setupDesktop() {
  const api = globalThis.pywebview?.api;
  if (!api) return;
  document.querySelectorAll(".desktop-only").forEach((element) => {
    element.hidden = false;
  });
  if (setupDesktop.done) return;
  setupDesktop.done = true;

  $("armorPickFilePath").addEventListener("click", () =>
    pickNativePath("pick_file", (path) => { armorSourcePath = path; }, "armorSourcePathLabel"));
  $("armorPickFolderPath").addEventListener("click", () =>
    pickNativePath("pick_folder", (path) => { armorSourcePath = path; }, "armorSourcePathLabel"));
  $("armorKitPickFilePath").addEventListener("click", () =>
    pickNativePath("pick_file", (path) => { armorKitSourcePath = path; }, "armorKitSourcePathLabel"));
  $("armorKitPickFolderPath").addEventListener("click", () =>
    pickNativePath("pick_folder", (path) => { armorKitSourcePath = path; }, "armorKitSourcePathLabel"));
  $("armorPickContainerPath").addEventListener("click", () =>
    pickNativePath("pick_armored", (path) => {
      armorRestorePath = path;
      $("armorRestoreName").textContent = path;
    }, "armorRestorePathLabel"));
  $("armorPickOutDir").addEventListener("click", () =>
    pickNativePath("pick_output_dir", (path) => { armorOutDir = path; }, "armorOutDirLabel"));
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
  fillSelect($("armorKitStyle"), data.styles, data.defaults.style);
  fillSelect($("armorKitPoison"), data.poisons, data.defaults.poison);
  fillSelect($("armorKitInjection"), data.injections, data.defaults.injection);
  $("armorKitLayers").value = data.defaults.layers;
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

function outSubdir(form) {
  const value = $("armorOutSubdir").value.trim();
  if (value) form.append("out_subdir", value);
}

function appendOutput(form) {
  if (armorOutDir) {
    form.append("out_dir", armorOutDir);
  } else {
    outSubdir(form);
  }
}

async function submitJob(url, form, prefix, headers = undefined) {
  const response = await fetch(url, { method: "POST", body: form, headers });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(errorText(data, response.status));
  logArmor(`任务已提交：${data.job}`, prefix);
  return data.job;
}

async function pollJob(jobId, status, barWrap, bar, prefix, timeoutMs = 15 * 60 * 1000) {
  const deadline = Date.now() + timeoutMs;
  let lastMessage = "";
  while (Date.now() < deadline) {
    const response = await fetch(`/api/armor/jobs/${jobId}`);
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(errorText(data, response.status));
    const job = data.job;
    const message = job.message || job.status;
    status.textContent = message;
    if (message !== lastMessage) {
      logArmor(message, prefix);
      lastMessage = message;
    }
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
  button.className = "armor-link";
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

  if (!armorPicked.length && !armorSourcePath) {
    return setStatus(status, "先拖入或选择程序包", "bad");
  }
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
  logArmor(
    `提交加固：${armorSourcePath || `${armorPicked.length} 个文件`} / ${layers} 层`,
    "[加固]",
  );

  try {
    const form = new FormData();
    form.append("password", password);
    form.append("layers", String(layers));
    form.append("profile", $("armorProfile").value);
    form.append("poison", $("armorPoison").value);
    form.append("style", $("armorStyle").value);
    form.append("injection", $("armorInjection").value);
    form.append("sidecar", $("armorSidecar").checked ? "1" : "0");
    appendOutput(form);
    if (armorSourcePath) {
      form.append("source_path", armorSourcePath);
    } else {
      for (const { file, path } of armorPicked) form.append("files", file, path);
    }
    const usePath = Boolean(armorSourcePath || armorOutDir);

    const jobId = await submitJob(
      "/api/armor/pack", form, "[加固]", usePath ? pathHeaders() : undefined,
    );
    const job = await pollJob(
      jobId, status, $("armorBarWrap"), $("armorBar"), "[加固]",
    );
    const info = job.result;
    setStatus(status, "加固完成", "ok");
    logArmor(
      `完成：${info.layers} 层 / ${formatSize(info.size)} / ${info.savedPath}`,
      "[加固]",
    );
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
    await loadReport(false);
  } catch (error) {
    setStatus(status, `失败：${error.message}`, "bad");
    logArmor(`失败：${error.message}`, "[加固]");
  } finally {
    button.disabled = false;
  }
}

async function runRestore() {
  const status = $("armorRestoreStatus");
  const result = $("armorRestoreResult");
  const button = $("armorRestoreGo");
  const password = $("armorRestorePassword").value;

  if (!armorRestoreFile && !armorRestorePath) {
    return setStatus(status, "先选择 .armored 文件", "bad");
  }
  if (!password) return setStatus(status, "口令不能为空", "bad");

  button.disabled = true;
  result.className = "result";
  result.innerHTML = "";
  setStatus(status, "正在提交还原任务…");
  $("armorRestoreBarWrap").hidden = false;
  $("armorRestoreBar").style.width = "0%";
  logArmor(
    `提交还原：${armorRestorePath || armorRestoreFile.name}${$("armorParallel").checked ? " / 并行" : ""}`,
    "[还原]",
  );

  try {
    const form = new FormData();
    form.append("password", password);
    form.append("parallel", $("armorParallel").checked ? "1" : "0");
    appendOutput(form);
    if (armorRestorePath) {
      form.append("container_path", armorRestorePath);
    } else {
      form.append("files", armorRestoreFile, armorRestoreFile.name);
    }
    const usePath = Boolean(armorRestorePath || armorOutDir);
    const jobId = await submitJob(
      "/api/armor/restore", form, "[还原]", usePath ? pathHeaders() : undefined,
    );
    const job = await pollJob(
      jobId, status, $("armorRestoreBarWrap"), $("armorRestoreBar"), "[还原]",
    );
    const info = job.result;
    setStatus(status, "还原完成", "ok");
    logArmor(
      `完成：${info.fileCount} 个文件 / ${formatSize(info.size)} / ${info.savedPath}`,
      "[还原]",
    );
    result.className = "result show";
    showNotice(result, `已还原 ${info.fileCount} 个文件，${formatSize(info.size)}。`);
    addDownload(result, `/api/artifacts/${info.artifact}`, "下载还原 zip");
    addOpenButton(result, info.artifact, status);
    await loadReport(false);
  } catch (error) {
    setStatus(status, `失败：${error.message}`, "bad");
    logArmor(`失败：${error.message}`, "[还原]");
  } finally {
    button.disabled = false;
  }
}

async function runInspect() {
  const status = $("armorRestoreStatus");
  const infoBox = $("armorInspectInfo");
  if (!armorRestoreFile && !armorRestorePath) {
    return setStatus(status, "先选择 .armored 文件", "bad");
  }
  try {
    const form = new FormData();
    if (armorRestorePath) {
      form.append("path", armorRestorePath);
    } else {
      form.append("files", armorRestoreFile, armorRestoreFile.name);
    }
    const response = await fetch("/api/armor/inspect", {
      method: "POST",
      body: form,
      headers: armorRestorePath ? pathHeaders() : undefined,
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(errorText(data, response.status));
    infoBox.hidden = false;
    infoBox.textContent = [
      `版本 v${data.version}`,
      `${data.layers} 层`,
      `容器 ${formatSize(data.totalSize)}`,
      `规格草稿 ${formatSize(data.noteSize)}`,
      `digest ${data.digest.slice(0, 16)}…`,
      `层尺寸 ${data.layerSizes.join(" / ")} B`,
    ].join(" · ");
    logArmor(`摘要：v${data.version} / ${data.layers} 层 / ${formatSize(data.totalSize)}`, "[摘要]");
    setStatus(status, "摘要读取成功", "ok");
  } catch (error) {
    infoBox.hidden = true;
    setStatus(status, `读取摘要失败：${error.message}`, "bad");
    logArmor(`摘要失败：${error.message}`, "[摘要]");
  }
}

async function runKit() {
  const status = $("armorKitStatus");
  const result = $("armorKitResult");
  const button = $("armorKitGo");
  if (!armorKitPicked.length && !armorKitSourcePath) {
    return setStatus(status, "先拖入或选择源程序包", "bad");
  }
  const layers = Number($("armorKitLayers").value);
  if (!Number.isInteger(layers) || layers < 2 || layers > 8) {
    return setStatus(status, "层数必须是 2~8 的整数", "bad");
  }

  button.disabled = true;
  result.className = "result";
  result.innerHTML = "";
  setStatus(status, "正在提交伴生任务…");
  $("armorKitBarWrap").hidden = false;
  $("armorKitBar").style.width = "0%";
  logArmor(
    `提交伴生：${armorKitSourcePath || `${armorKitPicked.length} 个文件`} / ${layers} 层`,
    "[伴生]",
  );

  try {
    const form = new FormData();
    form.append("layers", String(layers));
    form.append("style", $("armorKitStyle").value);
    form.append("poison", $("armorKitPoison").value);
    form.append("injection", $("armorKitInjection").value);
    appendOutput(form);
    if (armorKitSourcePath) {
      form.append("source_path", armorKitSourcePath);
    } else {
      for (const { file, path } of armorKitPicked) form.append("files", file, path);
    }
    if (armorKitArmored) form.append("armored", armorKitArmored, armorKitArmored.name);
    const usePath = Boolean(armorKitSourcePath || armorOutDir);

    const jobId = await submitJob(
      "/api/armor/sidecar", form, "[伴生]", usePath ? pathHeaders() : undefined,
    );
    const job = await pollJob(
      jobId, status, $("armorKitBarWrap"), $("armorKitBar"), "[伴生]",
    );
    const info = job.result;
    setStatus(status, "伴生诱饵包生成完成", "ok");
    logArmor(
      `完成：${info.fileCount} 份文件 / ${info.traps} 组线索 / ${info.savedPath}`,
      "[伴生]",
    );
    result.className = "result show";
    showNotice(
      result,
      `已生成 ${info.fileCount} 份拟态文件 / ${info.traps} 组互相矛盾的字段线索。`,
    );
    addDownload(result, `/api/artifacts/${info.artifact}`, "下载伴生诱饵 zip");
    addOpenButton(result, info.artifact, status);
    await loadReport(false);
  } catch (error) {
    setStatus(status, `失败：${error.message}`, "bad");
    logArmor(`失败：${error.message}`, "[伴生]");
  } finally {
    button.disabled = false;
  }
}

function renderReport(data) {
  const summary = $("armorReportSummary");
  const list = $("armorReportList");
  summary.innerHTML = "";
  list.innerHTML = "";
  for (const [key, value] of Object.entries(data.summary || {})) {
    const card = document.createElement("div");
    card.className = "metric";
    const label = document.createElement("span");
    label.textContent = key;
    const number = document.createElement("b");
    number.textContent = String(value);
    card.append(label, number);
    summary.append(card);
  }

  if (!data.attempts || !data.attempts.length) {
    const empty = document.createElement("p");
    empty.className = "hint";
    empty.textContent = "本次会话还没有记录。做一次加固、还原或伴生即可。";
    list.append(empty);
    return;
  }

  const table = document.createElement("table");
  const head = document.createElement("thead");
  head.innerHTML =
    "<tr><th>时间</th><th>操作</th><th>对象</th><th>结果</th>" +
    "<th>层尝试</th><th>耗时</th><th>估算轮数</th><th>备注</th></tr>";
  table.append(head);
  const body = document.createElement("tbody");
  for (const item of data.attempts) {
    const row = document.createElement("tr");
    const cells = [
      item.ts,
      item.action,
      item.label,
      item.ok ? "成功" : "失败",
      String(item.layers_tried),
      `${Number(item.seconds).toFixed(3)}s`,
      String(item.layers_tried + (item.ok ? 2 : 0)),
      item.note || "",
    ];
    cells.forEach((value, index) => {
      const cell = document.createElement("td");
      cell.textContent = value;
      if (index === 3) cell.className = item.ok ? "ok" : "bad";
      row.append(cell);
    });
    body.append(row);
  }
  table.append(body);
  list.append(table);
}

async function loadReport(showStatus = true) {
  const status = $("armorReportStatus");
  try {
    const response = await fetch("/api/armor/report");
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(errorText(data, response.status));
    armorReportData = data;
    renderReport(data);
    if (showStatus) {
      setStatus(status, `已刷新（${(data.attempts || []).length} 条）`, "ok");
    }
    return data;
  } catch (error) {
    if (showStatus) setStatus(status, `刷新失败：${error.message}`, "bad");
    return null;
  }
}

function downloadText(text, filename, type) {
  const blob = new Blob([text], { type });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 60000);
}

async function exportReport(kind) {
  const data = armorReportData || (await loadReport(false));
  if (!data) {
    setStatus($("armorReportStatus"), "报告加载失败", "bad");
    return;
  }
  if (kind === "csv") {
    const escape = (value) => `"${String(value ?? "").replaceAll('"', '""')}"`;
    const lines = ["ts,action,label,ok,layers_tried,seconds,est_tokens,note"];
    for (const item of data.attempts || []) {
      lines.push([
        item.ts, item.action, item.label, item.ok, item.layers_tried,
        item.seconds, item.est_tokens, item.note,
      ].map(escape).join(","));
    }
    downloadText("\ufeff" + lines.join("\r\n") + "\r\n", "tarpit_report.csv", "text/csv;charset=utf-8");
  } else {
    const lines = [
      "# TarpitCrypt 本地运行报告",
      "",
      `> 生成时间：${new Date().toLocaleString()}`,
      "> 估算值不是真实 LLM token 计数；数据只来自本机界面操作，不含口令。",
      "",
      "## 汇总",
      "",
      "| 指标 | 值 |",
      "| --- | --- |",
    ];
    for (const [key, value] of Object.entries(data.summary || {})) {
      lines.push(`| ${key} | ${value} |`);
    }
    lines.push(
      "",
      "## 明细",
      "",
      "| 时间 | 操作 | 对象 | 结果 | 层尝试 | 耗时(s) | 估算轮数 | 备注 |",
      "| --- | --- | --- | --- | --- | --- | --- | --- |",
    );
    for (const item of data.attempts || []) {
      lines.push(
        `| ${item.ts} | ${item.action} | ${item.label} | ${item.ok ? "成功" : "失败"} | ` +
        `${item.layers_tried} | ${item.seconds} | ` +
        `${item.layers_tried + (item.ok ? 2 : 0)} | ${(item.note || "").replaceAll("|", "\\|")} |`,
      );
    }
    downloadText(lines.join("\n") + "\n", "tarpit_report.md", "text/markdown;charset=utf-8");
  }
  setStatus($("armorReportStatus"), `已导出 ${kind.toUpperCase()}`, "ok");
}

async function clearReport() {
  if (!window.confirm("清空本次会话的运行报告？")) return;
  try {
    const response = await fetch("/api/armor/report/clear", { method: "POST" });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(errorText(data, response.status));
    await loadReport(false);
    setStatus($("armorReportStatus"), "记录已清空", "ok");
    logArmor("运行报告已清空", "[报告]");
  } catch (error) {
    setStatus($("armorReportStatus"), `清空失败：${error.message}`, "bad");
  }
}

function bindTabs() {
  const tabs = [...document.querySelectorAll(".armor-tab")];
  const panes = {
    pack: $("armorPackPane"),
    restore: $("armorRestorePane"),
    sidecar: $("armorSidecarPane"),
    report: $("armorReportPane"),
  };
  for (const tab of tabs) {
    tab.addEventListener("click", () => {
      for (const item of tabs) item.classList.toggle("active", item === tab);
      for (const [mode, pane] of Object.entries(panes)) {
        pane.hidden = mode !== tab.dataset.armorMode;
      }
      if (tab.dataset.armorMode === "report") loadReport(true);
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
  $("armorInspectGo").addEventListener("click", runInspect);
  $("armorKitGo").addEventListener("click", runKit);
  $("armorReportRefresh").addEventListener("click", () => loadReport(true));
  $("armorReportCsv").addEventListener("click", () => exportReport("csv"));
  $("armorReportMd").addEventListener("click", () => exportReport("md"));
  $("armorReportClear").addEventListener("click", clearReport);

  try {
    await loadProfiles();
    logArmor("本地 armor 面板就绪", "[系统]");
  } catch (error) {
    setStatus($("armorStatus"), `加载 armor 参数失败：${error.message}`, "bad");
    logArmor(`参数加载失败：${error.message}`, "[系统]");
    $("armorGo").disabled = true;
    $("armorKitGo").disabled = true;
  }
}

if (LOCAL && typeof document !== "undefined") {
  init();
  window.addEventListener("pywebviewready", setupDesktop);
  if (globalThis.pywebview?.api) setupDesktop();
}
