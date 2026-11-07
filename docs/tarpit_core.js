/**
 * TarpitCrypt 浏览器核心。
 *
 * 目标：与 `tarpitcrypt.py` **逐字节兼容**——同一份 `.tarpit` 文件，
 * 网页和命令行必须能互相解开。
 *
 * 为了做到这一点，下面每个细节都是对齐出来的，改动前请先读注释：
 *
 * 1. `_derive`  = HKDF-SHA256(ikm=口令, salt=keyfile摘要, info=域标签)
 *                 → 串行 rounds 次 Argon2id → 32 字节主密钥
 * 2. Argon2id 用 hash-wasm（参考实现的 WASM 编译），版本 v1.3，与
 *    argon2-cffi 默认值一致；memorySize 单位是 KiB。
 * 3. AEAD 用 WebCrypto AES-256-GCM：nonce 取文件头 24 字节里的前 12 字节，
 *    输出天然是 `密文 || 16 字节标签`，与 cryptography 的 AESGCM 相同。
 * 4. AAD 绑定整段 91 字节文件头；诱饵层 AAD 追加 `DECOY_NONCE || DECOY_LEN`。
 *
 * 所有随机数来自 `crypto.getRandomValues`（浏览器/Node 的 CSPRNG），
 * 没有任何 `Math.random`。
 */

export const MAGIC = new TextEncoder().encode("TARPITCR");
export const VERSION = 1;

export const FLAG_POW = 1 << 0;
export const FLAG_KEYFILE = 1 << 1;
export const FLAG_DECOY = 1 << 2;
export const KNOWN_FLAGS = FLAG_POW | FLAG_KEYFILE | FLAG_DECOY;

export const SALT_LEN = 32;
export const NONCE_LEN = 24;
export const POW_NONCE_LEN = 8;
export const GCM_NONCE_LEN = 12;
export const TAG_LEN = 16;
export const KEY_LEN = 32;
export const HEADER_LEN = 91;
export const DECOY_FIXED_LEN = NONCE_LEN + 8;

export const PRESETS = {
  fast: { mem: 262144, time: 3, para: 2, rounds: 2 },
  standard: { mem: 524288, time: 3, para: 2, rounds: 2 },
  hard: { mem: 1048576, time: 3, para: 4, rounds: 2 },
};

export const LIMITS = {
  minMem: 8 * 1024,
  maxMem: 2 * 1024 * 1024,
  minTime: 1,
  maxTime: 10,
  minPara: 1,
  maxPara: 8,
  minRounds: 1,
  maxRounds: 8,
  maxWork: 16 * 1024 * 1024,
};

export const ALLOWED_POW_BITS = [0, 16, 18, 20];

const enc = (text) => new TextEncoder().encode(text);

const KEYFILE_DOMAIN = enc("tarpitcrypt/v1/keyfile\u0000");
const NO_KEYFILE_DOMAIN = enc("tarpitcrypt/v1/no-keyfile\u0000");
const KDF_INPUT_DOMAIN = enc("tarpitcrypt/v1/kdf-input\u0000");
const ROUND_DOMAIN = enc("tarpitcrypt/v1/round\u0000");
const POW_DOMAIN = enc("tarpitcrypt/v1/pow\u0000");
const DECOY_SALT_DOMAIN = enc("tarpitcrypt/v1/decoy-salt\u0000");

/** 把若干 Uint8Array 拼成一个。 */
export function concat(...arrays) {
  const total = arrays.reduce((sum, item) => sum + item.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const item of arrays) {
    out.set(item, offset);
    offset += item.length;
  }
  return out;
}

/** 取 n 字节 CSPRNG 随机数。 */
export function randomBytes(n) {
  const buffer = new Uint8Array(n);
  globalThis.crypto.getRandomValues(buffer);
  return buffer;
}

/** SHA-256，输入可拼接多段。 */
export async function sha256(...parts) {
  const digest = await globalThis.crypto.subtle.digest("SHA-256", concat(...parts));
  return new Uint8Array(digest);
}

/** HKDF-SHA256 派生 32 字节，语义等同 cryptography 的 HKDF(length=32)。 */
async function hkdf32(ikm, salt, info) {
  const base = await globalThis.crypto.subtle.importKey("raw", ikm, "HKDF", false, ["deriveBits"]);
  const bits = await globalThis.crypto.subtle.deriveBits(
    { name: "HKDF", hash: "SHA-256", salt, info },
    base,
    KEY_LEN * 8,
  );
  return new Uint8Array(bits);
}

/** keyfile → 32 字节摘要；未启用时用带独立域标签的常量哈希。 */
export async function keyfileSecret(keyfile) {
  if (keyfile && keyfile.length) {
    return sha256(KEYFILE_DOMAIN, keyfile);
  }
  return sha256(NO_KEYFILE_DOMAIN);
}

/** Argon2id（hash-wasm WASM 实现），参数语义与 argon2-cffi 一致。 */
async function argon2idRaw(material, salt, mem, time, para) {
  const api = globalThis.hashwasm && globalThis.hashwasm.argon2id;
  if (!api) {
    throw new Error("argon2 WASM 未加载，无法派生密钥");
  }
  const binary = await api({
    password: material,
    salt,
    parallelism: para,
    iterations: time,
    memorySize: mem,
    hashLength: KEY_LEN,
    outputType: "binary",
  });
  return new Uint8Array(binary);
}

/**
 * 派生 32 字节主密钥：`rounds` 次串行 Argon2id。
 * 与 Python `_derive` 完全一致，任何一处顺序变动都会导致两边不兼容。
 */
export async function derive(password, keyfile, salt, params) {
  const p = normalizeParams(params);
  const kfDigest = await keyfileSecret(keyfile);
  let material = await hkdf32(password, kfDigest, KDF_INPUT_DOMAIN);
  let out = new Uint8Array(0);
  for (let round = 0; round < p.rounds; round += 1) {
    out = await argon2idRaw(material, salt, p.mem, p.time, p.para);
    material = await sha256(ROUND_DOMAIN, out, kfDigest);
  }
  return out;
}

/** 校验参数区间，越界直接抛错，绝不带着坏参数进 Argon2。 */
export function normalizeParams(input) {
  const p = { ...input };
  const ints = { mem: [LIMITS.minMem, LIMITS.maxMem], time: [LIMITS.minTime, LIMITS.maxTime],
                 para: [LIMITS.minPara, LIMITS.maxPara], rounds: [LIMITS.minRounds, LIMITS.maxRounds] };
  for (const [key, [min, max]] of Object.entries(ints)) {
    const value = p[key];
    if (!Number.isInteger(value) || value < min || value > max) {
      throw new Error(`参数 ${key}=${value} 越界，必须在 [${min}, ${max}] 之间`);
    }
  }
  p.pow = p.pow ?? 0;
  if (!ALLOWED_POW_BITS.includes(p.pow)) {
    throw new Error(`pow 必须是 ${ALLOWED_POW_BITS.join("/")} 之一`);
  }
  // 与 Python 的 DEFAULT_MAX_WORK_KIB_ROUNDS 对齐：浏览器版没有 --allow-heavy，
  // 打开一个声明了 2 GiB / time=10 / rounds=8 的畸形文件时，先在解析阶段拒绝，
  // 不让标签页为它跑满 Argon2。
  const work = p.mem * p.time * p.rounds;
  if (work > LIMITS.maxWork) {
    throw new Error(
      `KDF 工作量 ${work} KiB·轮 超过默认上限 ${LIMITS.maxWork}，已拒绝执行`,
    );
  }
  return p;
}

/**
 * 口令最低强度体检，返回 `{ ok, hint }`。
 *
 * 与 Python `tarpitcrypt.check_password_strength` / armor 的判定保持同一口径；
 * 只用于提示，不阻止加密，也不记录口令。
 */
export function checkPasswordStrength(text) {
  if (!text) return { ok: false, hint: "口令不能为空" };
  if (Array.from(text).length < 8) return { ok: false, hint: "至少 8 个字符" };
  const classes = [
    /\p{Ll}/u,
    /\p{Lu}/u,
    /\p{Nd}/u,
    /[^\p{L}\p{N}]/u,
  ].filter((pattern) => pattern.test(text)).length;
  if (classes < 2) {
    return { ok: false, hint: "建议混用大小写、数字或符号中的至少两类" };
  }
  if (["password", "12345678", "qwertyui", "admin123"].includes(text.toLowerCase())) {
    return { ok: false, hint: "这是常见弱口令，换一个" };
  }
  return { ok: true, hint: "长度与字符种类达标（不等于高熵，长口令更可靠）" };
}

/** 前导零比特数。 */
export function leadingZeroBits(bytes) {
  let count = 0;
  for (const byte of bytes) {
    if (byte === 0) {
      count += 8;
      continue;
    }
    count += Math.clz32(byte) - 24;
    break;
  }
  return count;
}

/** PoW 校验值 = SHA-256(域标签 || 主密钥 || POW_NONCE)。 */
export function powValue(key, powNonce) {
  return sha256(POW_DOMAIN, key, powNonce);
}

/** 检查 nonce 是否满足前导零要求。 */
export async function powOk(key, powNonce, powBits) {
  if (powBits <= 0) return true;
  return leadingZeroBits(await powValue(key, powNonce)) >= powBits;
}

/** 磨一个满足前导零要求的 8 字节 nonce。 */
export async function grindPow(key, powBits, onTick) {
  if (powBits <= 0) return randomBytes(POW_NONCE_LEN);
  const start = bytesToBigInt(randomBytes(POW_NONCE_LEN));
  const mask = (1n << 64n) - 1n;
  const limit = 1 << (powBits + 4);
  for (let offset = 0; offset < limit; offset += 1) {
    const nonce = bigIntToBytes((start + BigInt(offset)) & mask, POW_NONCE_LEN);
    if (await powOk(key, nonce, powBits)) return nonce;
    if (onTick && offset % 4096 === 0) await onTick(offset);
  }
  throw new Error("PoW 搜索超限，请降低难度");
}

function bytesToBigInt(bytes) {
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  return value;
}

function bigIntToBytes(value, length) {
  const out = new Uint8Array(length);
  let rest = value;
  for (let i = length - 1; i >= 0; i -= 1) {
    out[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  return out;
}

/** 序列化 91 字节文件头。 */
export function packHeader(fields) {
  const header = new Uint8Array(HEADER_LEN);
  header.set(MAGIC, 0);
  header[8] = VERSION;
  header[9] = fields.flags;
  const view = new DataView(header.buffer);
  view.setUint32(10, fields.mem, false);
  view.setUint16(14, fields.time, false);
  header[16] = fields.para;
  header[17] = fields.rounds;
  header[18] = fields.powDiff;
  header.set(fields.salt, 19);
  header.set(fields.nonce, 51);
  header.set(fields.powNonce, 75);
  view.setBigUint64(83, BigInt(fields.ctLen), false);
  return header;
}

/** 解析并校验文件头；任何不自洽都直接抛错。 */
export function parseHeader(blob) {
  if (blob.length < HEADER_LEN) {
    throw new Error(`文件过短：${blob.length} 字节，至少需要 ${HEADER_LEN} 字节`);
  }
  for (let i = 0; i < MAGIC.length; i += 1) {
    if (blob[i] !== MAGIC[i]) throw new Error("MAGIC 不匹配，这不是 TarpitCrypt 文件");
  }
  const version = blob[8];
  if (version !== VERSION) throw new Error(`不支持的 VERSION=${version}`);
  const flags = blob[9];
  if (flags & ~KNOWN_FLAGS) throw new Error(`FLAGS 含未知位：0x${flags.toString(16)}`);

  const view = new DataView(blob.buffer, blob.byteOffset, blob.byteLength);
  const header = {
    version,
    flags,
    mem: view.getUint32(10, false),
    time: view.getUint16(14, false),
    para: blob[16],
    rounds: blob[17],
    powDiff: blob[18],
    salt: blob.slice(19, 51),
    nonce: blob.slice(51, 75),
    powNonce: blob.slice(75, 83),
    ctLen: Number(view.getBigUint64(83, false)),
  };
  // 文件头是不可信输入：参数先过区间，再进 Argon2。
  normalizeParams({ mem: header.mem, time: header.time, para: header.para,
                    rounds: header.rounds, pow: header.powDiff });
  header.raw = blob.slice(0, HEADER_LEN);
  return header;
}

async function importAesKey(key) {
  return globalThis.crypto.subtle.importKey("raw", key, { name: "AES-GCM" }, false,
    ["encrypt", "decrypt"]);
}

/** AES-256-GCM 加密；输出 `密文 || 16 字节标签`。 */
export async function aeadEncrypt(key, nonce, aad, data) {
  const cryptoKey = await importAesKey(key);
  const result = await globalThis.crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce.slice(0, GCM_NONCE_LEN), additionalData: aad, tagLength: 128 },
    cryptoKey,
    data,
  );
  return new Uint8Array(result);
}

/** AES-256-GCM 解密；认证失败返回 null。 */
export async function aeadDecrypt(key, nonce, aad, data) {
  const cryptoKey = await importAesKey(key);
  try {
    const result = await globalThis.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce.slice(0, GCM_NONCE_LEN), additionalData: aad, tagLength: 128 },
      cryptoKey,
      data,
    );
    return new Uint8Array(result);
  } catch {
    return null;
  }
}

/** 由主盐派生诱饵层的盐。 */
export function decoySalt(salt) {
  return sha256(DECOY_SALT_DOMAIN, salt);
}

/**
 * 加密。
 *
 * @param {Uint8Array} plaintext
 * @param {Uint8Array} password
 * @param {object} options `{ params, keyfile, decoyPlaintext, decoyPassword, onProgress }`
 * @returns {Promise<Uint8Array>} 完整 .tarpit 文件字节
 */
export async function encrypt(plaintext, password, options = {}) {
  const params = normalizeParams(options.params);
  const keyfile = options.keyfile || new Uint8Array(0);
  const decoyPlaintext = options.decoyPlaintext || null;
  const decoyPassword = options.decoyPassword || null;
  const onProgress = options.onProgress || null;

  if (!plaintext || plaintext.length === 0) throw new Error("明文不能为空");
  if (decoyPlaintext === null !== (decoyPassword === null)) {
    throw new Error("诱饵明文与诱饵口令必须同时提供或同时省略");
  }
  if (decoyPassword && sameBytes(decoyPassword, password)) {
    throw new Error("诱饵口令不能与主口令相同");
  }

  let flags = 0;
  if (keyfile.length) flags |= FLAG_KEYFILE;
  if (params.pow) flags |= FLAG_POW;
  if (decoyPlaintext) flags |= FLAG_DECOY;

  const salt = randomBytes(SALT_LEN);
  const nonce = randomBytes(NONCE_LEN);

  const mainKey = await derive(password, keyfile, salt, params);
  const powNonce = await grindPow(mainKey, params.pow, onProgress);

  const ctLen = plaintext.length + TAG_LEN;
  const header = packHeader({
    flags, mem: params.mem, time: params.time, para: params.para, rounds: params.rounds,
    powDiff: params.pow, salt, nonce, powNonce, ctLen,
  });
  const ciphertext = await aeadEncrypt(mainKey, nonce, header, plaintext);

  if (!decoyPlaintext) {
    return concat(header, ciphertext);
  }

  const dNonce = randomBytes(NONCE_LEN);
  const dKey = await derive(decoyPassword, keyfile, await decoySalt(salt), params);
  const dLen = decoyPlaintext.length + TAG_LEN;
  const dAad = concat(header, dNonce, u64(dLen));
  const dCt = await aeadEncrypt(dKey, dNonce, dAad, decoyPlaintext);
  return concat(header, ciphertext, dNonce, u64(dLen), dCt);
}

/**
 * 解密。
 *
 * @returns {Promise<{data: Uint8Array, isDecoy: boolean}>}
 * @throws {Error} 口令/keyfile 错误或文件被篡改
 */
export async function decrypt(blob, password, options = {}) {
  const keyfile = options.keyfile || new Uint8Array(0);
  const header = parseHeader(blob);

  const ctStart = HEADER_LEN;
  const ctEnd = ctStart + header.ctLen;
  if (ctEnd > blob.length) {
    throw new Error(`CT_LEN=${header.ctLen} 超出文件剩余长度`);
  }
  const ciphertext = blob.slice(ctStart, ctEnd);

  let decoy = null;
  if (header.flags & FLAG_DECOY) {
    const rest = blob.slice(ctEnd);
    if (rest.length < DECOY_FIXED_LEN) throw new Error("诱饵段过短");
    const dNonce = rest.slice(0, NONCE_LEN);
    const dLen = Number(new DataView(rest.buffer, rest.byteOffset, rest.byteLength)
      .getBigUint64(NONCE_LEN, false));
    const dPayload = rest.slice(DECOY_FIXED_LEN);
    if (dPayload.length !== dLen) throw new Error(`DECOY_LEN=${dLen} 与实长 ${dPayload.length} 不一致`);
    decoy = { nonce: dNonce, payload: dPayload };
  } else if (ctEnd !== blob.length) {
    throw new Error("主密文之后存在多余字节");
  }

  const params = { mem: header.mem, time: header.time, para: header.para,
                   rounds: header.rounds, pow: header.powDiff };
  const mainKey = await derive(password, keyfile, header.salt, params);
  if (await powOk(mainKey, header.powNonce, header.powDiff)) {
    const plaintext = await aeadDecrypt(mainKey, header.nonce, header.raw, ciphertext);
    if (plaintext) return { data: plaintext, isDecoy: false };
  }

  if (decoy) {
    const dKey = await derive(password, keyfile, await decoySalt(header.salt), params);
    const dAad = concat(header.raw, decoy.nonce, u64(decoy.payload.length));
    const plaintext = await aeadDecrypt(dKey, decoy.nonce, dAad, decoy.payload);
    if (plaintext) return { data: plaintext, isDecoy: true };
  }

  throw new Error("解密失败：口令或 keyfile 不正确，或文件已被篡改");
}

function u64(value) {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value), false);
  return out;
}

function sameBytes(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ---------------------------------------------------------------------------
// 文件夹打包（store 模式的 zip，浏览器端没压缩库也能生成合法 zip）
// ---------------------------------------------------------------------------

let CRC_TABLE = null;

function crcTable() {
  if (CRC_TABLE) return CRC_TABLE;
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i += 1) {
    let c = i;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[i] = c >>> 0;
  }
  CRC_TABLE = table;
  return table;
}

/** CRC-32。 */
export function crc32(bytes) {
  const table = crcTable();
  let crc = 0xffffffff;
  for (const byte of bytes) crc = table[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

/** 清洗 zip 内路径，挡住 `../` 逃逸。 */
export function sanitizeMemberPath(name) {
  const parts = String(name).replace(/\\/g, "/").split("/").filter((p) => p && p !== "." && p !== "..");
  return parts.length ? parts.join("/") : "unnamed";
}

/**
 * 把若干文件打成 zip（不压缩，只存）。
 *
 * @param {Array<{path: string, data: Uint8Array}>} entries
 * @returns {Uint8Array}
 */
export function makeZip(entries) {
  const encoder = new TextEncoder();
  const taken = new Set();
  const normalized = [];
  for (const entry of [...entries].sort((a, b) => a.path.localeCompare(b.path))) {
    let path = sanitizeMemberPath(entry.path);
    if (taken.has(path)) {
      const dot = path.lastIndexOf(".");
      const stem = dot > 0 ? path.slice(0, dot) : path;
      const ext = dot > 0 ? path.slice(dot) : "";
      let i = 1;
      while (taken.has(`${stem}(${i})${ext}`)) i += 1;
      path = `${stem}(${i})${ext}`;
    }
    taken.add(path);
    normalized.push({ path, data: entry.data });
  }

  const chunks = [];
  const central = [];
  let offset = 0;
  for (const { path, data } of normalized) {
    const nameBytes = encoder.encode(path);
    const crc = crc32(data);
    const local = new Uint8Array(30 + nameBytes.length);
    const lv = new DataView(local.buffer);
    lv.setUint32(0, 0x04034b50, true);
    lv.setUint16(4, 20, true);
    lv.setUint16(6, 0x0800, true);
    lv.setUint16(8, 0, true);
    lv.setUint16(10, 0, true);
    lv.setUint16(12, 0x21, true);
    lv.setUint32(14, crc, true);
    lv.setUint32(18, data.length, true);
    lv.setUint32(22, data.length, true);
    lv.setUint16(26, nameBytes.length, true);
    lv.setUint16(28, 0, true);
    local.set(nameBytes, 30);

    const cd = new Uint8Array(46 + nameBytes.length);
    const cv = new DataView(cd.buffer);
    cv.setUint32(0, 0x02014b50, true);
    cv.setUint16(4, 20, true);
    cv.setUint16(6, 20, true);
    cv.setUint16(8, 0x0800, true);
    cv.setUint16(10, 0, true);
    cv.setUint16(12, 0, true);
    cv.setUint16(14, 0x21, true);
    cv.setUint32(16, crc, true);
    cv.setUint32(20, data.length, true);
    cv.setUint32(24, data.length, true);
    cv.setUint16(28, nameBytes.length, true);
    cv.setUint16(30, 0, true);
    cv.setUint16(32, 0, true);
    cv.setUint16(34, 0, true);
    cv.setUint16(36, 0, true);
    cv.setUint32(38, 0, true);
    cv.setUint32(42, offset, true);
    cd.set(nameBytes, 46);

    chunks.push(local, data);
    central.push(cd);
    offset += local.length + data.length;
  }

  const centralSize = central.reduce((sum, item) => sum + item.length, 0);
  const end = new Uint8Array(22);
  const ev = new DataView(end.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, normalized.length, true);
  ev.setUint16(10, normalized.length, true);
  ev.setUint32(12, centralSize, true);
  ev.setUint32(16, offset, true);

  return concat(...chunks, ...central, end);
}

/** 粗判是不是 zip（用于解密后决定给不给 .zip 后缀）。 */
export function isZip(bytes) {
  return bytes.length > 4 && bytes[0] === 0x50 && bytes[1] === 0x4b
    && bytes[2] === 0x03 && bytes[3] === 0x04;
}
