/**
 * 在线 / 本地双模式核心适配器。
 *
 * - 在线版（GitHub Pages）：`window.TARPIT_LOCAL` 不是 true，所有调用直接走
 *   `tarpit_core.js`，仍然在浏览器里完成加密。
 * - 本地版（tarpitcrypt_server.py）：服务端在返回首页时注入
 *   `window.TARPIT_LOCAL = true`，`encrypt` / `decrypt` 改为调本地 Python
 *   核心；其余工具函数（makeZip / checkPasswordStrength / isZip …）继续复用
 *   浏览器实现。
 *
 * 这样 `docs/` 只有一份界面，在线和本地共享同一套最新功能，不再维护
 * `tarpitcrypt_server.py` 里那套会漂移的内嵌 HTML。
 */

import * as online from "./tarpit_core.js";

export * from "./tarpit_core.js";

const LOCAL = globalThis.TARPIT_LOCAL === true;
const PARAM_KEYS = ["mem", "time", "para", "rounds", "pow", "cipher"];

function formWithParams(params) {
  const form = new FormData();
  for (const key of PARAM_KEYS) {
    const value = params && params[key];
    if (value !== undefined && value !== null) form.append(key, String(value));
  }
  return form;
}

function decodePassword(bytes) {
  return new TextDecoder().decode(bytes);
}

async function errorMessage(response) {
  try {
    const data = await response.json();
    if (data && data.error) return data.error;
  } catch {
    // 不是 JSON 就退回状态码。
  }
  return `HTTP ${response.status}`;
}

function attachLocalMeta(bytes, response) {
  bytes.localMeta = {
    artifact: response.headers.get("X-Tarpit-Artifact"),
    savedPath: response.headers.get("X-Tarpit-Saved-Path"),
  };
  return bytes;
}

/** 本地模式：把明文交给 /api/encrypt；在线模式：走浏览器 WASM。 */
export async function encrypt(plaintext, password, options = {}) {
  if (!LOCAL) return online.encrypt(plaintext, password, options);

  const form = formWithParams(options.params);
  form.append("password", decodePassword(password));
  form.append("files", new Blob([plaintext]), options.filename || "payload.bin");
  form.append("bundle", "0");

  if (options.keyfile && options.keyfile.length) {
    form.append("keyfile", new Blob([options.keyfile]), "keyfile");
  }
  if (options.decoyPlaintext && options.decoyPassword) {
    form.append("decoy", new Blob([options.decoyPlaintext]), "decoy");
    form.append("decoy_password", decodePassword(options.decoyPassword));
  }

  const response = await fetch("/api/encrypt", { method: "POST", body: form });
  if (!response.ok) throw new Error(await errorMessage(response));
  return attachLocalMeta(new Uint8Array(await response.arrayBuffer()), response);
}

/** 本地模式：把密文交给 /api/decrypt；在线模式：走浏览器 WASM。 */
export async function decrypt(blob, password, options = {}) {
  if (!LOCAL) return online.decrypt(blob, password, options);

  const form = new FormData();
  form.append("password", decodePassword(password));
  form.append("files", new Blob([blob]), options.filename || "input.tarpit");
  if (options.keyfile && options.keyfile.length) {
    form.append("keyfile", new Blob([options.keyfile]), "keyfile");
  }

  const response = await fetch("/api/decrypt", { method: "POST", body: form });
  if (!response.ok) throw new Error(await errorMessage(response));
  const data = attachLocalMeta(new Uint8Array(await response.arrayBuffer()), response);
  return {
    data,
    isDecoy: response.headers.get("X-Tarpit-Decoy") === "1",
    localMeta: data.localMeta,
  };
}
