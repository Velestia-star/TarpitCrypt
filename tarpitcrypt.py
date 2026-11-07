#!/usr/bin/env python3
"""TarpitCrypt —— 让每一次口令猜测都付出完整代价的本地文件加密工具。

设计目标
--------
不是让数据「解不开」，而是让**离线暴力破解者每猜一次口令**都必须完整执行
``rounds × Argon2id(mem, time, para)``，并在启用诱饵层时额外再付一次同样的
代价。单次尝试成本被钉死在文件的文件头里，试得越多亏得越多。

安全声明（必须如实理解）
------------------------
1. 机密性与完整性来自 **Argon2id + AEAD**：
   ``XChaCha20-Poly1305`` 或 ``AES-256-GCM``，AAD 覆盖密文之前的全部文件头。
2. **PoW 不是破解成本的主体**。``POW_NONCE`` 明文存放在文件里，验证方只需一次
   SHA-256 就能确认；破解者每个候选口令仍然只多花一次哈希。PoW 的真实作用是
   「造文件税」——让批量生成文件变贵。它的校验位于 ``_derive`` 之后，因此
   **并不能为错误口令提供提前返回**：Argon2 的成本已经付掉了，省下的只是一次
   AEAD。真正的「焦油」是 ``memory_cost × time_cost × rounds``。有诱饵层时，
   本工具自带的 ``decrypt`` 会尝试两次派生，但这不构成攻击者的固定成本——
   攻击者只攻主层即可判定失败，详见 README「什么情况下不安全」。
3. keyfile 不是 Argon2id 的独立 ``secret`` / pepper 参数。``hash_secret_raw``
   只有单一输入，实现先用 **HKDF-SHA256** 把口令与 keyfile 摘要合成为
   ``_kdf_input``，再整体喂给 Argon2id；**缺 keyfile 的尝试同样要跑完整
   Argon2 才会失败**，不产生时间侧信道。

禁止事项
--------
- 不实现任何自创的加密算法 / KDF / MAC，只组合已过审计的原语。
- 不提供破解他人数据、绕过认证、攻击第三方系统的能力。
- 仅用于加密使用者自己拥有的数据。

文件格式（VERSION = 1，所有整数字段大端，即 ``>``）
-------------------------------------------------
============ ========= ============================================
字段         长度      说明
============ ========= ============================================
MAGIC        8         ``b"TARPITCR"``
VERSION      1         ``1``
FLAGS        1         bit0=POW, bit1=KEYFILE, bit2=DECOY
KDF参数      8         ``>IHBB``: mem(KiB,u32)|time(u16)|para(u8)|rounds(u8)
POW_DIFF     1         前导零比特数，取值 {0, 16, 18, 20}
SALT         32        每次加密重新生成
NONCE        24        每次加密重新生成（GCM 只取前 12 字节）
POW_NONCE    8         PoW 解
CT_LEN       8         主密文长度（u64）
CT           CT_LEN    主密文（含 16 字节认证标签）
DECOY_NONCE  24        仅当 FLAGS.bit2 置位
DECOY_LEN    8         仅当 FLAGS.bit2 置位
DECOY_CT     DECOY_LEN 仅当 FLAGS.bit2 置位
============ ========= ============================================

头部长 = 8 + 1 + 1 + 8 + 1 + 32 + 24 + 8 + 8 = **91 字节**。
AAD：主层为整段文件头；诱饵层为 ``文件头 || DECOY_NONCE || DECOY_LEN``，
借此阻止两段密文互换或长度重写。
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import json
import logging
import os
import secrets
import stat
import struct
import sys
import tempfile
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final, Mapping, Sequence

__all__ = [
    "CIPHERS",
    "Cipher",
    "CryptoParams",
    "DecryptError",
    "EnvironmentSetupError",
    "MAX_KEYFILE_BYTES",
    "TarpitError",
    "UsageError",
    "decrypt",
    "describe",
    "encrypt",
    "main",
    "sanitize_ai_config",
]

_LOGGER: Final[logging.Logger] = logging.getLogger("tarpitcrypt")

# ---------------------------------------------------------------------------
# 依赖导入（缺失时走契约 4 的退出码 4，不在 import 期直接崩溃）
# ---------------------------------------------------------------------------

_DEPS_ERROR: str | None = None
try:  # pragma: no cover - 依赖齐全时无分支
    # argon2-cffi 在 low_level 里导出的是 ``Type``（D=0 / I=1 / ID=2）。
    # 注意：``hash_secret_raw`` 的第一个参数 ``secret`` 就是**口令本身**，
    # 它没有单独的 pepper 参数，口令与 keyfile 必须先合成再喂进去。
    from argon2.low_level import Type as _Argon2Type
    from argon2.low_level import hash_secret_raw
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers import aead as _aead
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
except ImportError as _exc:  # pragma: no cover
    _DEPS_ERROR = str(_exc)

#: 能力探测：``cryptography`` 直到 50.x 都没有提供 XChaCha20-Poly1305
#: （只有 12 字节 nonce 的 RFC 8439 ``ChaCha20Poly1305``）。这里探测它是否存在，
#: 存在就用原生 24 字节 nonce 实现，不存在则明确降级到 AES-256-GCM。
_XCHACHA_CLS = None if _DEPS_ERROR is not None else getattr(_aead, "XChaCha20Poly1305", None)


def _require_deps() -> None:
    """确认密码学依赖已安装。

    Raises:
        EnvironmentSetupError: argon2-cffi 或 cryptography 未安装。
    """
    if _DEPS_ERROR is not None:
        raise EnvironmentSetupError(
            f"缺少密码学依赖（{_DEPS_ERROR}）。请执行：pip install argon2-cffi cryptography"
        )


# ---------------------------------------------------------------------------
# 异常
# ---------------------------------------------------------------------------


class TarpitError(Exception):
    """TarpitCrypt 异常基类。"""


class EnvironmentSetupError(TarpitError):
    """运行环境不满足要求（依赖缺失、文件不可读），对应退出码 4。"""


class UsageError(TarpitError):
    """调用参数非法，对应退出码 1。"""


class DecryptError(ValueError, TarpitError):
    """解密失败：口令 / keyfile 错误，或文件被篡改。

    契约 3 要求解密失败必须 ``raise ValueError``，故同时继承 ``ValueError``。
    """


# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

MAGIC: Final[bytes] = b"TARPITCR"
VERSION: Final[int] = 1
SUPPORTED_VERSIONS: Final[frozenset[int]] = frozenset({VERSION})

FLAG_POW: Final[int] = 1 << 0
FLAG_KEYFILE: Final[int] = 1 << 1
FLAG_DECOY: Final[int] = 1 << 2
KNOWN_FLAGS: Final[int] = FLAG_POW | FLAG_KEYFILE | FLAG_DECOY

SALT_LEN: Final[int] = 32
NONCE_LEN: Final[int] = 24
POW_NONCE_LEN: Final[int] = 8
GCM_NONCE_LEN: Final[int] = 12
TAG_LEN: Final[int] = 16
KEY_LEN: Final[int] = 32
KEYFILE_HINT_LEN: Final[int] = 64

#: keyfile 只是「第二个因子」，不是数据容器。1 MiB 足够容纳任何合理的
#: 随机字节文件，同时挡住「误把一个大文件当 keyfile」把内存吃光。
MAX_KEYFILE_BYTES: Final[int] = 1024 * 1024

_KDF_STRUCT: Final[struct.Struct] = struct.Struct(">IHBB")
_U64: Final[struct.Struct] = struct.Struct(">Q")

HEADER_LEN: Final[int] = (
    len(MAGIC)
    + 1
    + 1
    + _KDF_STRUCT.size
    + 1
    + SALT_LEN
    + NONCE_LEN
    + POW_NONCE_LEN
    + _U64.size
)
DECOY_FIXED_LEN: Final[int] = NONCE_LEN + _U64.size

#: 从文件读到的 KDF 参数一律视为**不可信输入**：先过区间，再进 Argon2。
#: 否则一个 ``mem = 4 GiB, time = 100`` 的恶意文件就能在认证之前把机器拖死。
MIN_MEM_KIB: Final[int] = 8 * 1024
MAX_MEM_KIB: Final[int] = 2 * 1024 * 1024
MIN_TIME: Final[int] = 1
MAX_TIME: Final[int] = 10
MIN_PARA: Final[int] = 1
MAX_PARA: Final[int] = 8
MIN_ROUNDS: Final[int] = 1
MAX_ROUNDS: Final[int] = 8

#: 契约 5：允许的 PoW 难度（前导零比特数）。
ALLOWED_POW_BITS: Final[frozenset[int]] = frozenset({0, 16, 18, 20})

Cipher = str
CIPHER_XCHACHA: Final[Cipher] = "xchacha20-poly1305"
CIPHER_AESGCM: Final[Cipher] = "aes-256-gcm"
CIPHERS: Final[tuple[Cipher, ...]] = (CIPHER_XCHACHA, CIPHER_AESGCM)

#: 域分离标签。它们不是「自创 KDF」，只是无歧义的分隔前缀，
#: 用于防止不同用途的哈希输入发生长度扩展歧义。
_KEYFILE_DOMAIN: Final[bytes] = b"tarpitcrypt/v1/keyfile\x00"
_NO_KEYFILE_DOMAIN: Final[bytes] = b"tarpitcrypt/v1/no-keyfile\x00"
_KDF_INPUT_DOMAIN: Final[bytes] = b"tarpitcrypt/v1/kdf-input\x00"
_ROUND_DOMAIN: Final[bytes] = b"tarpitcrypt/v1/round\x00"
_POW_DOMAIN: Final[bytes] = b"tarpitcrypt/v1/pow\x00"
_DECOY_SALT_DOMAIN: Final[bytes] = b"tarpitcrypt/v1/decoy-salt\x00"

#: CLI 退出码（契约 4）。
EXIT_OK: Final[int] = 0
EXIT_USAGE: Final[int] = 1
EXIT_DECOY: Final[int] = 2
EXIT_DECRYPT: Final[int] = 3
EXIT_ENV: Final[int] = 4

#: 契约 5 的 AI 配置白名单。
AI_WHITELIST: Final[Mapping[str, frozenset[Any]]] = {
    "mem": frozenset({262144, 524288, 1048576, 2097152}),
    "time": frozenset({3, 4, 5}),
    "para": frozenset({2, 4, 6}),
    "rounds": frozenset({2, 3, 4}),
    "pow": frozenset({0, 16, 18, 20}),
    "cipher": frozenset({CIPHER_XCHACHA, CIPHER_AESGCM}),
}


# ---------------------------------------------------------------------------
# PoW
# ---------------------------------------------------------------------------


def _leading_zero_bits(digest: bytes) -> int:
    """返回 *digest* 的前导零比特数。"""
    value = int.from_bytes(digest, "big")
    return len(digest) * 8 - value.bit_length()


def _pow_value(key: bytes, pow_nonce: bytes) -> bytes:
    """计算 PoW 校验值 ``SHA-256(域标签 || 主密钥 || POW_NONCE)``。"""
    return hashlib.sha256(_POW_DOMAIN + key + pow_nonce).digest()


def _pow_ok(key: bytes, pow_nonce: bytes, pow_bits: int) -> bool:
    """检查 *key* 是否满足 *pow_bits* 位前导零要求。"""
    if pow_bits <= 0:
        return True
    return _leading_zero_bits(_pow_value(key, pow_nonce)) >= pow_bits


def _grind_pow(key: bytes, pow_bits: int, *, seed: bytes | None = None) -> bytes:
    """搜索一个 8 字节 nonce，使 PoW 校验值满足 *pow_bits* 位前导零。

    只用 SHA-256 磨，不重跑 Argon2；期望迭代 ``2**pow_bits`` 次，
    上限 ``2**(pow_bits + 4)`` 次后放弃，避免陷入无限循环。

    Args:
        key: 32 字节主密钥。
        pow_bits: 目标前导零比特数；``<= 0`` 时直接返回随机 nonce。
        seed: 仅测试用。给定 8 字节起点后结果可复现。

    Returns:
        8 字节 PoW nonce。

    Raises:
        UsageError: ``seed`` 长度不是 8 字节。
        TarpitError: 搜索超限（概率极低，视作异常事件）。
    """
    if seed is None:
        start = int.from_bytes(secrets.token_bytes(POW_NONCE_LEN), "big")
    else:
        if len(seed) != POW_NONCE_LEN:
            raise UsageError("PoW seed 必须为 8 字节")
        start = int.from_bytes(seed, "big")

    if pow_bits <= 0:
        return start.to_bytes(POW_NONCE_LEN, "big")

    limit = 1 << (pow_bits + 4)
    mask = (1 << (POW_NONCE_LEN * 8)) - 1
    for offset in range(limit):
        nonce = ((start + offset) & mask).to_bytes(POW_NONCE_LEN, "big")
        if _leading_zero_bits(_pow_value(key, nonce)) >= pow_bits:
            return nonce
    raise TarpitError(f"PoW 搜索 {limit} 次未命中，请降低 POW_DIFF")


# ---------------------------------------------------------------------------
# 密钥派生（契约 1）
# ---------------------------------------------------------------------------


def _keyfile_secret(keyfile: bytes) -> bytes:
    """把 keyfile 折算成 Argon2 的 ``secret``（pepper），恒为 32 字节。

    未启用 keyfile 时使用带独立域标签的常量哈希，保证「无 keyfile」与
    「任意真实 keyfile」走完全相同的 Argon2 路径与代价。
    """
    if keyfile:
        return hashlib.sha256(_KEYFILE_DOMAIN + keyfile).digest()
    return hashlib.sha256(_NO_KEYFILE_DOMAIN).digest()


def _kdf_input(password: bytes, keyfile_digest: bytes) -> bytes:
    """把口令与 keyfile 摘要合成为 Argon2id 的输入。

    Argon2 的低层 API 只有一个输入参数，没有独立的 pepper，所以用
    **HKDF-SHA256**（cryptography 提供，非自创构造）把两者绑在一起：
    ``ikm = password``、``salt = keyfile_digest``、``info`` 做域分离。

    这样做的直接后果是：**缺 keyfile 或者 keyfile 不对，派生出的密钥必然不同**，
    而且仍然要跑完整的 Argon2 才会失败，不产生时间侧信道。
    """
    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=keyfile_digest,
        info=_KDF_INPUT_DOMAIN,
    ).derive(password)


def _derive(
    password: bytes,
    keyfile: bytes,
    salt: bytes,
    mem: int,
    time: int,
    para: int,
    rounds: int,
) -> bytes:
    """派生 32 字节主密钥：``rounds`` 次**串行** Argon2id。

    每一轮的输入由上一轮输出与 keyfile 摘要重新合成，构成严格串行依赖，
    不存在任何并行走捷径的余地。

    Args:
        password: 口令原始字节（CLI 已做 NFC 规范化 + UTF-8 编码）。
        keyfile: keyfile 内容；未启用时传 ``b""``。
        salt: 32 字节盐。
        mem: Argon2id memory_cost，单位 KiB。
        time: Argon2id time_cost。
        para: Argon2id parallelism。
        rounds: 串行 Argon2id 执行次数，``>= 1``。

    Returns:
        32 字节主密钥。

    Raises:
        ValueError: ``rounds < 1`` 或盐过短。
        EnvironmentSetupError: 密码学依赖缺失。
    """
    _require_deps()
    if rounds < 1:
        raise ValueError("rounds 必须 >= 1")
    if len(salt) < 8:
        raise ValueError("salt 至少 8 字节")

    keyfile_digest = _keyfile_secret(keyfile)
    material = _kdf_input(password, keyfile_digest)
    out = b""
    for _ in range(rounds):
        out = hash_secret_raw(
            secret=material,
            salt=salt,
            time_cost=time,
            memory_cost=mem,
            parallelism=para,
            hash_len=KEY_LEN,
            type=_Argon2Type.ID,
        )
        # 串行接力：下一轮输入 = H(本轮输出 || keyfile 摘要)。
        material = hashlib.sha256(_ROUND_DOMAIN + out + keyfile_digest).digest()
    return out


def _decoy_salt(salt: bytes) -> bytes:
    """由主盐确定性派生诱饵层的盐，确保两层使用彼此独立的密钥。"""
    return hashlib.sha256(_DECOY_SALT_DOMAIN + salt).digest()


# ---------------------------------------------------------------------------
# 参数对象
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CryptoParams:
    """一次加密所使用的全部可调参数。

    默认值取「中等偏狠」一档：256 MiB / time=3 / para=2 / rounds=2。
    抬高 ``mem`` 与 ``rounds`` 是增加破解者单次尝试成本的唯一有效手段。
    """

    mem: int = 262_144
    time: int = 3
    para: int = 2
    rounds: int = 2
    pow: int = 0
    cipher: Cipher = CIPHER_AESGCM

    def validate(self) -> None:
        """校验参数是否落在允许区间。

        Raises:
            ValueError: 任一参数越界或取值不在白名单内。
        """
        if not MIN_MEM_KIB <= self.mem <= MAX_MEM_KIB:
            raise ValueError(f"mem 必须在 [{MIN_MEM_KIB}, {MAX_MEM_KIB}] KiB 之间")
        if not MIN_TIME <= self.time <= MAX_TIME:
            raise ValueError(f"time 必须在 [{MIN_TIME}, {MAX_TIME}] 之间")
        if not MIN_PARA <= self.para <= MAX_PARA:
            raise ValueError(f"para 必须在 [{MIN_PARA}, {MAX_PARA}] 之间")
        if not MIN_ROUNDS <= self.rounds <= MAX_ROUNDS:
            raise ValueError(f"rounds 必须在 [{MIN_ROUNDS}, {MAX_ROUNDS}] 之间")
        if self.pow not in ALLOWED_POW_BITS:
            raise ValueError(f"pow 必须是 {sorted(ALLOWED_POW_BITS)} 之一")
        if self.cipher not in CIPHERS:
            raise ValueError(f"cipher 必须是 {list(CIPHERS)} 之一")


# ---------------------------------------------------------------------------
# AEAD
# ---------------------------------------------------------------------------


def _usable_ciphers() -> tuple[Cipher, ...]:
    """返回当前环境真正可用的 AEAD 列表。

    ``xchacha20-poly1305`` 只有在 ``cryptography`` 提供了
    ``XChaCha20Poly1305`` 时才算可用；否则这里只返回 AES-256-GCM。
    """
    if _XCHACHA_CLS is not None:
        return (CIPHER_XCHACHA, CIPHER_AESGCM)
    return (CIPHER_AESGCM,)


def _resolve_cipher(requested: Cipher) -> Cipher:
    """把请求的 cipher 解析成当前环境可用的算法。

    契约 5 的白名单允许 AI 输出 ``xchacha20-poly1305``，但截至
    ``cryptography`` 50.x 并没有这个算法。此时**降级到 AES-256-GCM 并告警**，
    而不是让程序崩溃：VERSION = 1 的文件头本来就不记录算法，解密侧靠试解
    识别，因此降级不影响文件的可解密性。

    Args:
        requested: 调用方请求的算法名。

    Returns:
        实际使用的算法名。
    """
    if requested == CIPHER_XCHACHA and _XCHACHA_CLS is None:
        _LOGGER.warning("cryptography 未提供 XChaCha20-Poly1305，已降级为 AES-256-GCM")
        return CIPHER_AESGCM
    return requested


def _aead_encrypt(cipher: Cipher, key: bytes, nonce: bytes, aad: bytes, data: bytes) -> bytes:
    """用指定 AEAD 加密，返回带 16 字节认证标签的密文。

    Raises:
        UsageError: 请求的算法在当前环境不可用。
    """
    _require_deps()
    if cipher == CIPHER_XCHACHA:
        if _XCHACHA_CLS is None:
            raise UsageError("当前 cryptography 不提供 XChaCha20-Poly1305，请改用 aes-256-gcm")
        return _XCHACHA_CLS(key).encrypt(nonce, data, aad)
    if cipher == CIPHER_AESGCM:
        return _aead.AESGCM(key).encrypt(nonce[:GCM_NONCE_LEN], data, aad)
    raise ValueError(f"不支持的 cipher：{cipher}")


def _aead_decrypt(
    cipher: Cipher, key: bytes, nonce: bytes, aad: bytes, data: bytes
) -> bytes | None:
    """用指定 AEAD 解密；认证失败返回 ``None`` 而不抛异常。"""
    _require_deps()
    try:
        if cipher == CIPHER_XCHACHA:
            if _XCHACHA_CLS is None:
                return None
            return _XCHACHA_CLS(key).decrypt(nonce, data, aad)
        if cipher == CIPHER_AESGCM:
            return _aead.AESGCM(key).decrypt(nonce[:GCM_NONCE_LEN], data, aad)
    except InvalidTag:
        return None
    return None


def _aead_open_any(key: bytes, nonce: bytes, aad: bytes, data: bytes) -> bytes | None:
    """依次尝试全部可用 AEAD，返回第一个认证通过的结果。

    VERSION = 1 的文件头没有独立的 cipher 字段（契约 2 未分配该位），
    因此解密侧用尝试法识别算法。AEAD 开销相对 Argon2 可忽略。
    """
    for cipher in _usable_ciphers():
        plaintext = _aead_decrypt(cipher, key, nonce, aad, data)
        if plaintext is not None:
            return plaintext
    return None


# ---------------------------------------------------------------------------
# 文件头
# ---------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Header:
    """解析后的文件头。"""

    flags: int
    mem: int
    time: int
    para: int
    rounds: int
    pow_diff: int
    salt: bytes
    nonce: bytes
    pow_nonce: bytes
    ct_len: int
    raw: bytes = field(repr=False)


def _pack_header(
    *,
    flags: int,
    mem: int,
    time: int,
    para: int,
    rounds: int,
    pow_diff: int,
    salt: bytes,
    nonce: bytes,
    pow_nonce: bytes,
    ct_len: int,
) -> bytes:
    """按契约 2 的顺序序列化文件头（91 字节）。"""
    header = b"".join(
        (
            MAGIC,
            bytes((VERSION,)),
            bytes((flags,)),
            _KDF_STRUCT.pack(mem, time, para, rounds),
            bytes((pow_diff,)),
            salt,
            nonce,
            pow_nonce,
            _U64.pack(ct_len),
        )
    )
    if len(header) != HEADER_LEN:  # pragma: no cover - 防御性断言
        raise TarpitError(f"内部错误：文件头长度 {len(header)} != {HEADER_LEN}")
    return header


def _parse_header(blob: bytes) -> Header:
    """解析并校验文件头。

    这是所有不可信数据的入口：MAGIC / VERSION / FLAGS / KDF 参数 / 长度字段
    必须在进入 Argon2 之前全部校验完毕。

    Raises:
        ValueError: 格式非法、版本不支持、参数越界或长度不自洽。
    """
    if len(blob) < HEADER_LEN:
        raise ValueError(f"文件过短：{len(blob)} 字节，至少需要 {HEADER_LEN} 字节")
    if blob[: len(MAGIC)] != MAGIC:
        raise ValueError("MAGIC 不匹配，这不是 TarpitCrypt 文件")

    offset = len(MAGIC)
    version = blob[offset]
    if version not in SUPPORTED_VERSIONS:
        raise ValueError(f"不支持的 VERSION={version}，本程序支持 {sorted(SUPPORTED_VERSIONS)}")
    offset += 1

    flags = blob[offset]
    if flags & ~KNOWN_FLAGS:
        raise ValueError(f"FLAGS 含未知位：0x{flags:02x}")
    offset += 1

    mem, time, para, rounds = _KDF_STRUCT.unpack_from(blob, offset)
    offset += _KDF_STRUCT.size

    pow_diff = blob[offset]
    offset += 1
    if bool(flags & FLAG_POW) != bool(pow_diff):
        raise ValueError(
            f"FLAGS.POW={bool(flags & FLAG_POW)} 与 POW_DIFF={pow_diff} 不一致"
        )

    salt = blob[offset : offset + SALT_LEN]
    offset += SALT_LEN
    nonce = blob[offset : offset + NONCE_LEN]
    offset += NONCE_LEN
    pow_nonce = blob[offset : offset + POW_NONCE_LEN]
    offset += POW_NONCE_LEN
    ct_len = _U64.unpack_from(blob, offset)[0]
    offset += _U64.size

    try:
        CryptoParams(
            mem=mem,
            time=time,
            para=para,
            rounds=rounds,
            pow=pow_diff,
            cipher=CIPHER_XCHACHA,
        ).validate()
    except ValueError as exc:
        raise ValueError(f"文件头中的 KDF 参数不可接受：{exc}") from exc

    return Header(
        flags=flags,
        mem=mem,
        time=time,
        para=para,
        rounds=rounds,
        pow_diff=pow_diff,
        salt=salt,
        nonce=nonce,
        pow_nonce=pow_nonce,
        ct_len=ct_len,
        raw=blob[:HEADER_LEN],
    )


def _validate_blob_layout(blob: bytes, header: Header) -> tuple[bytes, bytes] | None:
    """校验主密文段与诱饵段的长度，返回诱饵段 ``(nonce, 密文)`` 或 ``None``。

    这是进入 Argon2 之前的最后一道廉价检查：长度字段全部来自不可信文件头，
    任何不自洽都必须在这里以 :class:`ValueError` 结束，绝不能拿畸形文件去
    跑一次完整的 KDF。合法文件（含全部历史版本生成的）在这里必然通过。

    Raises:
        ValueError: 长度字段越界、截断、尾部残留，或装不下认证标签。
    """
    ct_start = HEADER_LEN
    ct_end = ct_start + header.ct_len
    if header.ct_len < TAG_LEN:
        raise ValueError(f"CT_LEN={header.ct_len} 小于认证标签长度 {TAG_LEN}")
    if ct_end > len(blob):
        raise ValueError(
            f"CT_LEN={header.ct_len} 超出文件剩余长度（{len(blob) - ct_start} 字节）"
        )

    if not header.flags & FLAG_DECOY:
        if ct_end != len(blob):
            raise ValueError("主密文之后存在多余字节")
        return None

    rest = blob[ct_end:]
    if len(rest) < DECOY_FIXED_LEN:
        raise ValueError("诱饵段过短")
    d_nonce = rest[:NONCE_LEN]
    d_len = _U64.unpack_from(rest, NONCE_LEN)[0]
    if d_len < TAG_LEN:
        raise ValueError(f"DECOY_LEN={d_len} 小于认证标签长度 {TAG_LEN}")
    d_payload = rest[DECOY_FIXED_LEN:]
    if len(d_payload) != d_len:
        raise ValueError(
            f"DECOY_LEN={d_len} 与实际诱饵密文长度 {len(d_payload)} 不一致"
        )
    return d_nonce, d_payload


# ---------------------------------------------------------------------------
# 加密 / 解密
# ---------------------------------------------------------------------------


def encrypt(
    plaintext: bytes,
    password: bytes,
    *,
    params: CryptoParams,
    keyfile: bytes | None = None,
    decoy_plaintext: bytes | None = None,
    decoy_password: bytes | None = None,
) -> bytes:
    """加密 *plaintext*，返回完整的 ``.tarpit`` 文件字节。

    Args:
        plaintext: 待加密数据。
        password: 主口令字节；空口令会被拒绝。
        params: KDF / PoW / cipher 参数。
        keyfile: keyfile 内容；``None`` 表示不启用。空字节串会被拒绝——
            旧实现把 0 字节 keyfile 当成「没启用」，用户以为多了一道因子，
            实际并没有。
        decoy_plaintext: 诱饵层明文；``None`` 表示不生成诱饵层。
        decoy_password: 诱饵层口令；必须与主口令不同且非空。

    Returns:
        可直接写盘的完整文件字节。

    Raises:
        ValueError: 参数非法、口令为空、keyfile 为空或过大、诱饵参数缺失，
            或诱饵口令与主口令相同。
        EnvironmentSetupError: 密码学依赖缺失。
    """
    _require_deps()
    params.validate()
    if not password:
        raise ValueError("口令不能为空；空口令没有可保护的熵")
    if keyfile is not None and not keyfile:
        raise ValueError("keyfile 不能为空（0 字节等于没有启用 keyfile）")
    if keyfile is not None and len(keyfile) > MAX_KEYFILE_BYTES:
        raise ValueError(f"keyfile 不能超过 {MAX_KEYFILE_BYTES // 1024} KiB")
    if not plaintext:
        raise ValueError("plaintext 不能为空")
    if (decoy_plaintext is None) != (decoy_password is None):
        raise ValueError("decoy_plaintext 与 decoy_password 必须同时提供或同时省略")
    if decoy_password is not None and not decoy_password:
        raise ValueError("诱饵口令不能为空")
    if decoy_password is not None and decoy_password == password:
        raise ValueError("诱饵口令不能与主口令相同，否则诱饵层永远不可达")

    # 当前环境拿不到 XChaCha20 时在这里降级，而不是让程序崩掉。
    cipher = _resolve_cipher(params.cipher)

    keyfile_bytes = keyfile or b""
    flags = FLAG_KEYFILE if keyfile_bytes else 0
    if params.pow:
        flags |= FLAG_POW
    if decoy_plaintext is not None:
        flags |= FLAG_DECOY

    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)

    main_key = _derive(
        password, keyfile_bytes, salt, params.mem, params.time, params.para, params.rounds
    )
    pow_nonce = _grind_pow(main_key, params.pow)

    ct_len = len(plaintext) + TAG_LEN
    header = _pack_header(
        flags=flags,
        mem=params.mem,
        time=params.time,
        para=params.para,
        rounds=params.rounds,
        pow_diff=params.pow,
        salt=salt,
        nonce=nonce,
        pow_nonce=pow_nonce,
        ct_len=ct_len,
    )
    ciphertext = _aead_encrypt(cipher, main_key, nonce, header, plaintext)
    if len(ciphertext) != ct_len:  # pragma: no cover - 防御性断言
        raise TarpitError("内部错误：密文长度与 CT_LEN 不一致")

    parts: list[bytes] = [header, ciphertext]

    if decoy_plaintext is not None:
        assert decoy_password is not None  # 配对检查已保证
        d_nonce = secrets.token_bytes(NONCE_LEN)
        d_key = _derive(
            decoy_password,
            keyfile_bytes,
            _decoy_salt(salt),
            params.mem,
            params.time,
            params.para,
            params.rounds,
        )
        d_ct_len = len(decoy_plaintext) + TAG_LEN
        d_aad = header + d_nonce + _U64.pack(d_ct_len)
        d_ct = _aead_encrypt(cipher, d_key, d_nonce, d_aad, decoy_plaintext)
        parts.extend((d_nonce, _U64.pack(d_ct_len), d_ct))

    return b"".join(parts)


def decrypt(
    blob: bytes,
    password: bytes,
    *,
    keyfile: bytes | None = None,
) -> tuple[bytes, bool]:
    """解密 ``.tarpit`` 文件字节。

    Args:
        blob: 完整文件内容。
        password: 候选口令字节；空口令仍被接受，用于解开历史上用空口令
            加密的文件。
        keyfile: keyfile 内容；``None`` 表示未提供。

    Returns:
        ``(明文, is_decoy)``；命中诱饵层时 ``is_decoy`` 为 ``True``（契约 3）。

    Raises:
        ValueError: 口令 / keyfile 错误、文件被篡改或格式非法。绝不会静默
            返回乱码或 ``None``。
        EnvironmentSetupError: 密码学依赖缺失。
    """
    _require_deps()
    if keyfile is not None and len(keyfile) > MAX_KEYFILE_BYTES:
        raise ValueError(f"keyfile 不能超过 {MAX_KEYFILE_BYTES // 1024} KiB")
    header = _parse_header(blob)
    decoy = _validate_blob_layout(blob, header)
    ciphertext = blob[HEADER_LEN : HEADER_LEN + header.ct_len]

    keyfile_bytes = keyfile or b""

    # 主层：无论 PoW 是否通过，都必须完整跑一遍 _derive。
    # 若在 PoW 处短路返回，诱饵口令会被误判成「不存在」。
    main_key = _derive(
        password,
        keyfile_bytes,
        header.salt,
        header.mem,
        header.time,
        header.para,
        header.rounds,
    )
    if _pow_ok(main_key, header.pow_nonce, header.pow_diff):
        plaintext = _aead_open_any(main_key, header.nonce, header.raw, ciphertext)
        if plaintext is not None:
            return plaintext, False

    if decoy is not None:
        d_nonce, d_payload = decoy
        d_aad = header.raw + d_nonce + _U64.pack(len(d_payload))
        d_key = _derive(
            password,
            keyfile_bytes,
            _decoy_salt(header.salt),
            header.mem,
            header.time,
            header.para,
            header.rounds,
        )
        plaintext = _aead_open_any(d_key, d_nonce, d_aad, d_payload)
        if plaintext is not None:
            return plaintext, True

    raise DecryptError("解密失败：口令或 keyfile 不正确，或文件已被篡改")


# ---------------------------------------------------------------------------
# 只读查看
# ---------------------------------------------------------------------------


def describe(blob: bytes) -> dict[str, Any]:
    """返回文件头与分段的可读描述，无需口令。

    校验规则与 :func:`decrypt` 完全一致：截断、尾部残留或诱饵段不自洽的
    文件会直接抛 :class:`ValueError`，不会再打印一份自相矛盾的元数据。

    Raises:
        ValueError: 格式非法。
    """
    header = _parse_header(blob)
    decoy = _validate_blob_layout(blob, header)
    decoy_len = len(decoy[1]) if decoy is not None else None
    return {
        "version": VERSION,
        "flags": {
            "pow": bool(header.flags & FLAG_POW),
            "keyfile": bool(header.flags & FLAG_KEYFILE),
            "decoy": bool(header.flags & FLAG_DECOY),
        },
        "mem_kib": header.mem,
        "time": header.time,
        "para": header.para,
        "rounds": header.rounds,
        "pow_diff": header.pow_diff,
        "ct_len": header.ct_len,
        "decoy_len": decoy_len,
        "total_len": len(blob),
    }


# ---------------------------------------------------------------------------
# AI 配置白名单（契约 5）
# ---------------------------------------------------------------------------


def sanitize_ai_config(raw: Mapping[str, Any] | Any) -> tuple[dict[str, Any], list[str]]:
    """把 AI 产出的任意 JSON 收敛成白名单内的参数。

    白名单外的键、以及白名单键上的非法值一律丢弃并记录 warning；
    输入不是 mapping 时整体丢弃。**任何情况下都不抛异常。**

    Args:
        raw: AI 返回并 ``json.loads`` 之后的对象。

    Returns:
        ``(clean, warnings)``。``clean`` 只含通过校验的键；
        ``warnings`` 为人类可读的丢弃原因列表（同时写入日志）。
    """
    clean: dict[str, Any] = {}
    issues: list[str] = []

    if not isinstance(raw, Mapping):
        issues.append(f"AI 配置必须是 JSON 对象，收到 {type(raw).__name__}，已整体丢弃")
        for message in issues:
            _LOGGER.warning("%s", message)
        return clean, issues

    for key, value in raw.items():
        allowed = AI_WHITELIST.get(key)
        if allowed is None:
            issues.append(f"未知键 {key!r} 已丢弃")
            continue
        if isinstance(value, bool) or not isinstance(value, (int, str)):
            issues.append(f"键 {key!r} 的值类型非法（{type(value).__name__}），已丢弃")
            continue
        if value not in allowed:
            issues.append(f"键 {key!r} 的值 {value!r} 不在白名单 {sorted(allowed)} 内，已丢弃")
            continue
        clean[key] = value

    for message in issues:
        _LOGGER.warning("AI 配置：%s", message)
    return clean, issues


def load_ai_config(path: str | os.PathLike[str]) -> tuple[dict[str, Any], list[str]]:
    """读取并净化一份 AI 配置文件。

    Raises:
        EnvironmentSetupError: 文件不可读，或内容不是合法 JSON。
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise EnvironmentSetupError(f"无法读取 AI 配置文件：{exc}") from exc
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as exc:
        raise EnvironmentSetupError(f"AI 配置文件不是合法 JSON：{exc}") from exc
    return sanitize_ai_config(raw)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class _Parser(argparse.ArgumentParser):
    """把 argparse 的 usage 错误重定向到契约 4 的退出码 1。

    ``argparse`` 默认用退出码 2 表示参数错误，而契约 4 把 2 保留给
    「诱饵层命中」，两者必须区分开。
    """

    def error(self, message: str) -> None:  # type: ignore[override]
        raise UsageError(message)


def _read_password(prompt: str, *, confirm: bool) -> bytes:
    """交互式读取口令，NFC 规范化后 UTF-8 编码。

    ``confirm=True`` 用于加密 / 设置诱饵口令：此时空口令直接拒绝。
    ``confirm=False`` 用于解密：允许空口令，保证历史上用空口令加密的文件
    仍能打开。

    Raises:
        UsageError: 两次输入不一致，或加密时输入了空口令。
    """
    first = getpass.getpass(prompt)
    if confirm:
        if not first:
            raise UsageError("口令不能为空")
        second = getpass.getpass("再输入一次：")
        if first != second:
            raise UsageError("两次输入的口令不一致")
    return unicodedata.normalize("NFC", first).encode("utf-8")


def _read_password_stdin() -> bytes:
    """从 stdin 读取一行口令（供脚本使用，避免口令出现在进程参数里）。"""
    line = sys.stdin.readline()
    if not line:
        raise UsageError("stdin 未提供口令")
    return unicodedata.normalize("NFC", line.rstrip("\r\n")).encode("utf-8")


def _read_keyfile(path: str | None) -> bytes | None:
    """读取 keyfile；路径为 ``None`` 时返回 ``None``。

    空文件会被拒绝：0 字节 keyfile 在旧实现里会被 ``keyfile or b""`` 当成
    「没启用 keyfile」，用户以为多了一道因子，实际只是主口令。超过
    :data:`MAX_KEYFILE_BYTES` 的文件也拒绝，避免把任意大文件整个读进内存。

    Raises:
        EnvironmentSetupError: 文件不可读、为空或超过上限。
    """
    if path is None:
        return None
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(MAX_KEYFILE_BYTES + 1)
    except OSError as exc:
        raise EnvironmentSetupError(f"无法读取 keyfile：{exc}") from exc
    if not data:
        raise EnvironmentSetupError(
            "keyfile 是空文件（0 字节），等于没有第二个因子；请换一个非空文件"
        )
    if len(data) > MAX_KEYFILE_BYTES:
        raise EnvironmentSetupError(
            f"keyfile 超过 {MAX_KEYFILE_BYTES // 1024} KiB 上限，请换一个小文件"
        )
    return data


def _build_parser() -> argparse.ArgumentParser:
    """构建命令行解析器。"""
    parser = _Parser(
        prog="tarpitcrypt",
        description="TarpitCrypt：让每一次口令猜测都付出完整代价的本地文件加密工具。",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="输出详细日志")
    sub = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)

    enc = sub.add_parser("encrypt", help="加密文件")
    enc.add_argument("input", help="明文文件路径")
    enc.add_argument("output", help="输出 .tarpit 文件路径")
    enc.add_argument("--force", action="store_true", help="覆盖已存在的输出文件")
    enc.add_argument("--keyfile", help="keyfile 路径")
    enc.add_argument("--decoy", help="诱饵层明文的路径")
    enc.add_argument("--password-stdin", action="store_true", help="从 stdin 读取主口令")
    enc.add_argument("--decoy-password-stdin", action="store_true", help="从 stdin 读取诱饵口令")
    enc.add_argument("--mem", type=int, help="Argon2id memory_cost (KiB)")
    enc.add_argument("--time", type=int, help="Argon2id time_cost")
    enc.add_argument("--para", type=int, help="Argon2id parallelism")
    enc.add_argument("--rounds", type=int, help="串行 Argon2id 次数")
    enc.add_argument("--pow", type=int, help="PoW 前导零比特数，取值 0/16/18/20")
    enc.add_argument("--cipher", choices=list(CIPHERS), help="AEAD 算法")
    enc.add_argument("--ai-config", help="AI 生成的参数 JSON（白名单校验后使用）")

    dec = sub.add_parser("decrypt", help="解密文件")
    dec.add_argument("input", help=".tarpit 文件路径")
    dec.add_argument("output", help="明文输出路径")
    dec.add_argument("--force", action="store_true", help="覆盖已存在的输出文件")
    dec.add_argument("--keyfile", help="keyfile 路径")
    dec.add_argument("--password-stdin", action="store_true", help="从 stdin 读取口令")

    info = sub.add_parser("info", help="查看文件头，无需口令")
    info.add_argument("input", help=".tarpit 文件路径")

    keygen = sub.add_parser("keygen", help="生成一个新的 keyfile")
    keygen.add_argument("output", help="keyfile 输出路径")

    check = sub.add_parser("ai-config", help="按契约 5 校验一份 AI 配置 JSON")
    check.add_argument("json_file", help="待校验的 JSON 文件")
    return parser


def _params_from_args(args: argparse.Namespace) -> CryptoParams:
    """把 AI 配置与命令行参数合并成 :class:`CryptoParams`。

    AI 配置先过白名单；命令行显式参数优先级最高。

    Raises:
        ValueError: 参数越界。
    """
    merged: dict[str, Any] = {}
    ai_path = getattr(args, "ai_config", None)
    if ai_path:
        clean, _issues = load_ai_config(ai_path)
        merged.update(clean)

    for name in ("mem", "time", "para", "rounds", "pow", "cipher"):
        value = getattr(args, name, None)
        if value is not None:
            merged[name] = value

    return CryptoParams(**merged)


def _safe_chmod(path: str) -> None:
    """尽力把文件权限收紧到 0600（Windows 上为 best-effort）。"""
    try:
        os.chmod(path, 0o600)
    except OSError:  # pragma: no cover - 部分平台不支持
        pass


def _same_path(left: str | os.PathLike[str], right: str | os.PathLike[str]) -> bool:
    """判断两个路径是否指向同一个文件（跟随符号链接，兼容大小写差异）。"""
    try:
        return os.path.samefile(left, right)
    except OSError:
        left_path = Path(left).resolve()
        right_path = Path(right).resolve()
        return os.path.normcase(str(left_path)) == os.path.normcase(str(right_path))


def _check_output(input_path: Path, output_path: Path, *, force: bool) -> None:
    """在开始 KDF 之前检查输出路径，避免算完才发现写不了。

    Raises:
        UsageError: 输入与输出相同、输出是目录，或输出已存在且没给 ``--force``。
    """
    if _same_path(input_path, output_path):
        raise UsageError(
            "输入与输出是同一个文件；为避免覆盖唯一副本，请换一个输出路径"
        )
    if output_path.is_dir():
        raise UsageError(f"输出路径是目录：{output_path}")
    if output_path.exists() and not force:
        raise UsageError(f"输出文件已存在：{output_path}\n如确认覆盖，请加 --force")


def _fsync_directory(directory: Path) -> None:
    """尽力让目录项落盘（仅 POSIX；失败不影响主流程）。"""
    if os.name != "posix":
        return
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(directory, flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:  # pragma: no cover - 个别文件系统不支持目录 fsync
        pass
    finally:
        os.close(fd)


def _write_output(path: str | os.PathLike[str], data: bytes, *, force: bool) -> None:
    """把 *data* 原子地写到 *path*。

    先写同目录临时文件并 fsync，再 ``os.replace`` 到目标：进程在写入中途
    退出也不会留下半截目标文件，更不会先把已有文件截断。默认拒绝覆盖；
    ``force=True`` 时沿用旧文件的权限位。新文件由 ``mkstemp`` 创建，权限
    为 0600。

    Raises:
        UsageError: 输出是目录，或已存在且没给 ``force``。
        OSError: 磁盘 / 权限等写入失败；目标文件保持原样。
    """
    target = Path(path)
    if target.is_dir():
        raise UsageError(f"输出路径是目录：{target}")
    if target.exists() and not force:
        raise UsageError(f"输出文件已存在：{target}\n如确认覆盖，请加 --force")

    previous_mode: int | None = None
    if target.exists():
        previous_mode = stat.S_IMODE(target.stat().st_mode)

    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=str(target.parent)
    )
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if previous_mode is not None:
            os.chmod(tmp_name, previous_mode)
        os.replace(tmp_name, target)
        _fsync_directory(target.parent)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _run(args: argparse.Namespace) -> int:
    """执行子命令，返回契约 4 的退出码。"""
    if args.verbose:
        logging.basicConfig(level=logging.DEBUG, format="%(levelname)s %(message)s")

    if args.command == "keygen":
        # 独占创建：写第二遍就静默覆盖旧 keyfile，等于亲手弄丢数据。
        try:
            fd = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError as exc:
            raise UsageError(
                f"keyfile 已存在，拒绝覆盖：{args.output}\n"
                f"请换一个路径，或确认旧文件已离线备份后手动删除。"
            ) from exc
        with os.fdopen(fd, "wb") as fh:
            fh.write(secrets.token_bytes(KEYFILE_HINT_LEN))
        _safe_chmod(args.output)
        print(f"已生成 keyfile：{args.output}（{KEYFILE_HINT_LEN} 字节）。请离线备份，丢失即无法解密。")
        return EXIT_OK

    if args.command == "info":
        blob = Path(args.input).read_bytes()
        print(json.dumps(describe(blob), ensure_ascii=False, indent=2))
        return EXIT_OK

    if args.command == "ai-config":
        clean, issues = load_ai_config(args.json_file)
        print(json.dumps({"accepted": clean, "dropped": issues}, ensure_ascii=False, indent=2))
        return EXIT_OK

    if args.command == "encrypt":
        input_path = Path(args.input)
        output_path = Path(args.output)
        _check_output(input_path, output_path, force=args.force)
        if args.keyfile and _same_path(args.keyfile, output_path):
            raise UsageError("输出路径与 keyfile 相同，覆盖会直接弄丢密钥；请换一个输出路径")

        params = _params_from_args(args)
        password = (
            _read_password_stdin()
            if args.password_stdin
            else _read_password("设置口令：", confirm=True)
        )
        keyfile = _read_keyfile(args.keyfile)
        plaintext = input_path.read_bytes()
        decoy_plaintext: bytes | None = None
        decoy_password: bytes | None = None
        if args.decoy:
            decoy_plaintext = Path(args.decoy).read_bytes()
            decoy_password = (
                _read_password_stdin()
                if args.decoy_password_stdin
                else _read_password("设置诱饵口令：", confirm=True)
            )

        blob = encrypt(
            plaintext,
            password,
            params=params,
            keyfile=keyfile,
            decoy_plaintext=decoy_plaintext,
            decoy_password=decoy_password,
        )
        _write_output(output_path, blob, force=args.force)
        print(
            f"已加密：{args.output}（{len(blob)} 字节；mem={params.mem}KiB "
            f"time={params.time} para={params.para} rounds={params.rounds} "
            f"pow={params.pow} cipher={_resolve_cipher(params.cipher)}）"
        )
        if decoy_plaintext is not None:
            print("已写入诱饵层：用诱饵口令可解出另一份明文（退出码 2）。")
        return EXIT_OK

    if args.command == "decrypt":
        input_path = Path(args.input)
        output_path = Path(args.output)
        _check_output(input_path, output_path, force=args.force)
        if args.keyfile and _same_path(args.keyfile, output_path):
            raise UsageError("输出路径与 keyfile 相同，覆盖会直接弄丢密钥；请换一个输出路径")

        password = (
            _read_password_stdin()
            if args.password_stdin
            else _read_password("输入口令：", confirm=False)
        )
        keyfile = _read_keyfile(args.keyfile)
        blob = input_path.read_bytes()
        data, is_decoy = decrypt(blob, password, keyfile=keyfile)
        _write_output(output_path, data, force=args.force)
        if is_decoy:
            print(f"已解密（诱饵层）：{args.output}（{len(data)} 字节）", file=sys.stderr)
            return EXIT_DECOY
        print(f"已解密：{args.output}（{len(data)} 字节）")
        return EXIT_OK

    raise UsageError(f"未知子命令：{args.command}")


def _configure_stdio() -> None:
    """把标准输出/错误切到 UTF-8，避免在 cp1252 之类的控制台上打印中文即崩。

    Python 3.15 起默认启用 UTF-8 模式（PEP 686），本地通常看不到问题；
    但 3.11~3.14 的英文 Windows 控制台仍是 cp1252，一句 ``print("已加密")``
    就会抛 ``UnicodeEncodeError`` 把进程打挂。这里统一自愈，失败也不影响主流程。
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:  # pragma: no cover - 被重定向到非文本流
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):  # pragma: no cover - 个别流不支持重配
            pass


def main(argv: Sequence[str] | None = None) -> int:
    """CLI 入口，返回契约 4 定义的退出码。"""
    _configure_stdio()
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except UsageError as exc:
        print(f"参数错误：{exc}", file=sys.stderr)
        parser.print_usage(sys.stderr)
        return EXIT_USAGE

    try:
        return _run(args)
    except DecryptError as exc:
        print(f"{exc}", file=sys.stderr)
        return EXIT_DECRYPT
    except EnvironmentSetupError as exc:
        print(f"环境错误：{exc}", file=sys.stderr)
        return EXIT_ENV
    except UsageError as exc:
        print(f"参数错误：{exc}", file=sys.stderr)
        return EXIT_USAGE
    except FileNotFoundError as exc:
        print(f"环境错误：文件不存在：{exc}", file=sys.stderr)
        return EXIT_ENV
    except PermissionError as exc:
        print(f"环境错误：权限不足：{exc}", file=sys.stderr)
        return EXIT_ENV
    except OSError as exc:
        print(f"环境错误：{exc}", file=sys.stderr)
        return EXIT_ENV
    except TarpitError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return EXIT_ENV
    except ValueError as exc:
        print(f"参数错误：{exc}", file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
