"""TarpitCrypt 的测试。

覆盖契约 1~5：KDF 签名与串行性、文件格式布局、错误约定、CLI 退出码、
AI 配置白名单。所有用例都用最小 Argon2 参数（8 MiB / time=1 / rounds=1），
以保证整套测试在几秒内跑完。
"""

from __future__ import annotations

import io
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import tarpitcrypt as tc  # noqa: E402

FAST = tc.CryptoParams(mem=8192, time=1, para=1, rounds=1, pow=0)
PASSWORD = b"correct horse battery staple"
DECOY_PASSWORD = b"a different horse entirely"

#: 契约 1 的黄金向量：salt = bytes(range(32))，mem=8192, time=1, para=1。
VECTOR_SALT = bytes(range(32))
VECTOR_ROUNDS1 = bytes.fromhex(
    "5a8e22bdab0cbe66cd93a6d18b620952e90983dea55c6939d44f88063e6fdde9"
)
VECTOR_ROUNDS2 = bytes.fromhex(
    "078d0b5b5b791ec284a88f7dc1609d98827615e51c7122503d7400a0e356259f"
)
VECTOR_KEYFILE = bytes.fromhex(
    "3335dd963cc166b1a2c5e7f7e517202adfc1efb61e9971856ddc3bc70311d6aa"
)


# ---------------------------------------------------------------------------
# 契约 1：KDF
# ---------------------------------------------------------------------------


def test_derive_golden_vector() -> None:
    """_derive 的输出必须逐字节稳定，否则旧文件解不开。"""
    key = tc._derive(b"pw-vector", b"", VECTOR_SALT, 8192, 1, 1, 1)
    assert key == VECTOR_ROUNDS1
    assert len(key) == 32


def test_derive_rounds_are_serial_and_change_output() -> None:
    """rounds 增加必须改变输出，说明它们真的是串行叠加而非重复同一次计算。"""
    key1 = tc._derive(b"pw-vector", b"", VECTOR_SALT, 8192, 1, 1, 1)
    key2 = tc._derive(b"pw-vector", b"", VECTOR_SALT, 8192, 1, 1, 2)
    assert key1 == VECTOR_ROUNDS1
    assert key2 == VECTOR_ROUNDS2
    assert key1 != key2


def test_derive_keyfile_changes_key() -> None:
    """keyfile 必须真的参与派生。"""
    key = tc._derive(b"pw-vector", b"keyfile-bytes", VECTOR_SALT, 8192, 1, 1, 1)
    assert key == VECTOR_KEYFILE
    assert key != VECTOR_ROUNDS1


def test_derive_rejects_zero_rounds() -> None:
    """rounds < 1 必须报错，不能悄悄退化成一次。"""
    with pytest.raises(ValueError):
        tc._derive(b"pw", b"", VECTOR_SALT, 8192, 1, 1, 0)


# ---------------------------------------------------------------------------
# 契约 2：文件格式
# ---------------------------------------------------------------------------


def test_header_layout() -> None:
    """MAGIC / VERSION / FLAGS / KDF 字段必须落在约定的偏移上。"""
    blob = tc.encrypt(b"x" * 10, PASSWORD, params=FAST)
    assert len(blob) == tc.HEADER_LEN + 10 + tc.TAG_LEN
    assert tc.HEADER_LEN == 91
    assert blob[0:8] == b"TARPITCR"
    assert blob[8] == tc.VERSION
    assert blob[9] == 0
    mem, time, para, rounds = struct.unpack_from(">IHBB", blob, 10)
    assert (mem, time, para, rounds) == (8192, 1, 1, 1)
    assert blob[18] == 0  # POW_DIFF
    assert len(blob[19:51]) == 32  # SALT
    assert len(blob[51:75]) == 24  # NONCE
    assert len(blob[75:83]) == 8  # POW_NONCE
    assert struct.unpack_from(">Q", blob, 83)[0] == 10 + tc.TAG_LEN


def test_salt_and_nonce_are_fresh_per_encryption() -> None:
    """同一明文同一口令连加密两次，SALT 与 NONCE 必须不同。"""
    a = tc.encrypt(b"same", PASSWORD, params=FAST)
    b = tc.encrypt(b"same", PASSWORD, params=FAST)
    assert a[19:51] != b[19:51]
    assert a[51:75] != b[51:75]
    assert a != b


def test_keyfile_flag_and_roundtrip() -> None:
    """启用 keyfile 时 FLAGS.bit1 置位，且缺 keyfile 必须解不开。"""
    kf = b"k" * 32
    blob = tc.encrypt(b"secret", PASSWORD, params=FAST, keyfile=kf)
    assert blob[9] & tc.FLAG_KEYFILE
    assert tc.decrypt(blob, PASSWORD, keyfile=kf) == (b"secret", False)
    with pytest.raises(ValueError):
        tc.decrypt(blob, PASSWORD, keyfile=None)
    with pytest.raises(ValueError):
        tc.decrypt(blob, PASSWORD, keyfile=b"wrong-keyfile")


def test_decoy_section_layout() -> None:
    """诱饵段的 DECOY_NONCE / DECOY_LEN / DECOY_CT 必须紧跟在主密文之后。"""
    blob = tc.encrypt(
        b"real",
        PASSWORD,
        params=FAST,
        decoy_plaintext=b"fake",
        decoy_password=DECOY_PASSWORD,
    )
    assert blob[9] & tc.FLAG_DECOY
    ct_len = struct.unpack_from(">Q", blob, 83)[0]
    decoy_start = tc.HEADER_LEN + ct_len
    assert len(blob[decoy_start : decoy_start + 24]) == 24
    assert struct.unpack_from(">Q", blob, decoy_start + 24)[0] == len(b"fake") + tc.TAG_LEN


# ---------------------------------------------------------------------------
# 契约 3：解密错误约定
# ---------------------------------------------------------------------------


def test_roundtrip_returns_plain_and_not_decoy() -> None:
    """正确解密返回 (data, False)。"""
    blob = tc.encrypt(b"payload", PASSWORD, params=FAST)
    data, is_decoy = tc.decrypt(blob, PASSWORD)
    assert data == b"payload"
    assert is_decoy is False


def test_wrong_password_raises_value_error() -> None:
    """契约 3：解密失败必须 raise ValueError，不得返回 None 或乱码。"""
    blob = tc.encrypt(b"payload", PASSWORD, params=FAST)
    with pytest.raises(ValueError):
        tc.decrypt(blob, b"wrong password")


def test_tampered_ciphertext_raises() -> None:
    """翻转密文任意一位都必须被 AEAD 抓到。"""
    blob = bytearray(tc.encrypt(b"payload", PASSWORD, params=FAST))
    blob[-1] ^= 0x01
    with pytest.raises(ValueError):
        tc.decrypt(bytes(blob), PASSWORD)


def test_tampered_header_params_raise() -> None:
    """文件头被绑进 AAD，篡改任何字段都必须导致解密失败。"""
    blob = bytearray(tc.encrypt(b"payload", PASSWORD, params=FAST))
    blob[19] ^= 0xFF  # SALT 首字节
    with pytest.raises(ValueError):
        tc.decrypt(bytes(blob), PASSWORD)


def test_tampered_pow_nonce_raises() -> None:
    """POW_NONCE 同样在 AAD 覆盖范围内。"""
    blob = bytearray(tc.encrypt(b"payload", PASSWORD, params=FAST))
    blob[75] ^= 0xFF
    with pytest.raises(ValueError):
        tc.decrypt(bytes(blob), PASSWORD)


def test_decoy_layer_returns_true() -> None:
    """契约 3：诱饵命中返回 (data, True)，主口令仍返回 (data, False)。"""
    blob = tc.encrypt(
        b"real data",
        PASSWORD,
        params=FAST,
        decoy_plaintext=b"fake data",
        decoy_password=DECOY_PASSWORD,
    )
    assert tc.decrypt(blob, PASSWORD) == (b"real data", False)
    assert tc.decrypt(blob, DECOY_PASSWORD) == (b"fake data", True)


def test_decoy_password_must_differ_from_main() -> None:
    """诱饵口令与主口令相同会让诱饵层永远不可达，必须在加密时就拒绝。"""
    with pytest.raises(ValueError):
        tc.encrypt(
            b"real",
            PASSWORD,
            params=FAST,
            decoy_plaintext=b"fake",
            decoy_password=PASSWORD,
        )


def test_decoy_requires_both_arguments() -> None:
    """只给一半的诱饵参数必须报错。"""
    with pytest.raises(ValueError):
        tc.encrypt(b"real", PASSWORD, params=FAST, decoy_plaintext=b"fake")
    with pytest.raises(ValueError):
        tc.encrypt(b"real", PASSWORD, params=FAST, decoy_password=b"pw")


def test_tampered_decoy_nonce_raises() -> None:
    """诱饵 nonce 也被 AAD 覆盖，改了就解不出诱饵层。"""
    blob = bytearray(
        tc.encrypt(
            b"real",
            PASSWORD,
            params=FAST,
            decoy_plaintext=b"fake",
            decoy_password=DECOY_PASSWORD,
        )
    )
    ct_len = struct.unpack_from(">Q", blob, 83)[0]
    blob[tc.HEADER_LEN + ct_len] ^= 0xFF
    with pytest.raises(ValueError):
        tc.decrypt(bytes(blob), DECOY_PASSWORD)


def test_truncated_and_trailing_bytes_rejected() -> None:
    """截断与尾部多余字节都必须报错。"""
    blob = tc.encrypt(b"payload", PASSWORD, params=FAST)
    with pytest.raises(ValueError):
        tc.decrypt(blob[:-1], PASSWORD)
    with pytest.raises(ValueError):
        tc.decrypt(blob + b"junk", PASSWORD)


def test_bad_magic_rejected() -> None:
    """MAGIC 不对的文件直接拒绝。"""
    blob = bytearray(tc.encrypt(b"payload", PASSWORD, params=FAST))
    blob[0] ^= 0xFF
    with pytest.raises(ValueError, match="MAGIC"):
        tc.decrypt(bytes(blob), PASSWORD)


# ---------------------------------------------------------------------------
# 不可信文件头：参数必须先钳位再进 Argon2
# ---------------------------------------------------------------------------


def test_oversized_kdf_params_rejected_before_argon2() -> None:
    """恶意文件把 mem 调到 4 TiB 时必须在进 Argon2 之前就被拒（DoS 防护）。"""
    blob = bytearray(tc.encrypt(b"payload", PASSWORD, params=FAST))
    struct.pack_into(">I", blob, 10, 0xFFFF_FFFF)
    with pytest.raises(ValueError, match="KDF 参数"):
        tc.decrypt(bytes(blob), PASSWORD)


def test_unknown_flag_bits_rejected() -> None:
    """FLAGS 出现未分配的位必须拒绝，避免未来格式被误读。"""
    blob = bytearray(tc.encrypt(b"payload", PASSWORD, params=FAST))
    blob[9] |= 0x80
    with pytest.raises(ValueError, match="FLAGS"):
        tc.decrypt(bytes(blob), PASSWORD)


def test_unsupported_version_rejected() -> None:
    """VERSION 不认识就停下，绝不猜测着解。"""
    blob = bytearray(tc.encrypt(b"payload", PASSWORD, params=FAST))
    blob[8] = 99
    with pytest.raises(ValueError, match="VERSION"):
        tc.decrypt(bytes(blob), PASSWORD)


# ---------------------------------------------------------------------------
# PoW
# ---------------------------------------------------------------------------


def test_pow_flag_and_roundtrip() -> None:
    """启用 PoW 时 bit0 置位，且 POW_NONCE 真的满足前导零要求。"""
    params = tc.CryptoParams(mem=8192, time=1, para=1, rounds=1, pow=16)
    blob = tc.encrypt(b"pow payload", PASSWORD, params=params)
    assert blob[9] & tc.FLAG_POW
    assert blob[18] == 16
    _mem, _time, _para, _rounds = struct.unpack_from(">IHBB", blob, 10)
    key = tc._derive(PASSWORD, b"", blob[19:51], _mem, _time, _para, _rounds)
    assert tc._pow_ok(key, blob[75:83], 16)
    assert tc.decrypt(blob, PASSWORD) == (b"pow payload", False)


def test_pow_zero_is_always_ok() -> None:
    """pow=0 时任何 key 都通过 PoW 检查。"""
    assert tc._pow_ok(b"whatever", b"12345678", 0) is True


def test_grind_is_deterministic_with_seed() -> None:
    """给固定 seed 时 _grind_pow 必须可复现。"""
    key = b"k" * 32
    a = tc._grind_pow(key, 12, seed=b"\x00" * 8)
    b = tc._grind_pow(key, 12, seed=b"\x00" * 8)
    assert a == b
    assert tc._pow_ok(key, a, 12)


# ---------------------------------------------------------------------------
# 参数校验
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "params",
    [
        tc.CryptoParams(mem=1024, time=1, para=1, rounds=1),
        tc.CryptoParams(mem=8192, time=99, para=1, rounds=1),
        tc.CryptoParams(mem=8192, time=1, para=99, rounds=1),
        tc.CryptoParams(mem=8192, time=1, para=1, rounds=99),
        tc.CryptoParams(mem=8192, time=1, para=1, rounds=1, pow=17),
        tc.CryptoParams(mem=8192, time=1, para=1, rounds=1, cipher="rot13"),
    ],
)
def test_invalid_params_rejected(params: tc.CryptoParams) -> None:
    """越界参数一律在加密前被拒。"""
    with pytest.raises(ValueError):
        tc.encrypt(b"x", PASSWORD, params=params)


def test_empty_plaintext_rejected() -> None:
    """空明文不允许，避免产生只有头部的歧义文件。"""
    with pytest.raises(ValueError):
        tc.encrypt(b"", PASSWORD, params=FAST)


# ---------------------------------------------------------------------------
# 契约 5：AI 配置白名单
# ---------------------------------------------------------------------------


def test_ai_config_accepts_whitelisted_values() -> None:
    """白名单内的键值原样保留。"""
    clean, issues = tc.sanitize_ai_config(
        {"mem": 1048576, "time": 4, "para": 4, "rounds": 3, "pow": 18, "cipher": "aes-256-gcm"}
    )
    assert clean == {
        "mem": 1048576,
        "time": 4,
        "para": 4,
        "rounds": 3,
        "pow": 18,
        "cipher": "aes-256-gcm",
    }
    assert issues == []


def test_ai_config_drops_unknown_keys_and_bad_values() -> None:
    """白名单外的键与值一律丢弃并记录 warning，程序不崩。"""
    clean, issues = tc.sanitize_ai_config(
        {"mem": 999, "time": 4, "evil": "rm -rf /", "rounds": "3", "para": True}
    )
    assert clean == {"time": 4}
    assert len(issues) == 4


def test_ai_config_survives_non_mapping() -> None:
    """AI 返回数组或字符串时整体丢弃，且不抛异常。"""
    for payload in ([], "nope", 42, None):
        clean, issues = tc.sanitize_ai_config(payload)
        assert clean == {}
        assert len(issues) == 1


def test_ai_config_bool_is_not_int() -> None:
    """True 不能被当成 1 混进数字白名单。"""
    clean, _ = tc.sanitize_ai_config({"time": True})
    assert clean == {}


# ---------------------------------------------------------------------------
# 契约 4：CLI 退出码
# ---------------------------------------------------------------------------


def _run_cli(monkeypatch: pytest.MonkeyPatch, args: list[str], stdin: str = "") -> int:
    """把 stdin 换成字符串后执行 main()，返回退出码。"""
    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
    return tc.main(args)


def test_cli_encrypt_then_decrypt(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """正常往返返回 0。"""
    src = tmp_path / "plain.bin"
    enc = tmp_path / "out.tarpit"
    dec = tmp_path / "back.bin"
    src.write_bytes(b"cli payload")

    code = _run_cli(
        monkeypatch,
        ["encrypt", str(src), str(enc), "--password-stdin", "--mem", "8192",
         "--time", "1", "--para", "1", "--rounds", "1"],
        stdin="pw\n",
    )
    assert code == tc.EXIT_OK

    code = _run_cli(monkeypatch, ["decrypt", str(enc), str(dec), "--password-stdin"], stdin="pw\n")
    assert code == tc.EXIT_OK
    assert dec.read_bytes() == b"cli payload"


def test_cli_wrong_password_exits_3(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """口令错误必须返回退出码 3。"""
    src = tmp_path / "plain.bin"
    enc = tmp_path / "out.tarpit"
    src.write_bytes(b"cli payload")
    _run_cli(
        monkeypatch,
        ["encrypt", str(src), str(enc), "--password-stdin", "--mem", "8192",
         "--time", "1", "--para", "1", "--rounds", "1"],
        stdin="pw\n",
    )
    code = _run_cli(
        monkeypatch, ["decrypt", str(enc), str(tmp_path / "x.bin"), "--password-stdin"], stdin="bad\n"
    )
    assert code == tc.EXIT_DECRYPT


def test_cli_decoy_exits_2(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """契约 4：诱饵层命中返回 2，而不是 0 或 3。"""
    src = tmp_path / "real.bin"
    fake = tmp_path / "fake.bin"
    enc = tmp_path / "out.tarpit"
    out = tmp_path / "out.bin"
    src.write_bytes(b"real")
    fake.write_bytes(b"fake")

    code = _run_cli(
        monkeypatch,
        ["encrypt", str(src), str(enc), "--password-stdin", "--decoy", str(fake),
         "--decoy-password-stdin", "--mem", "8192", "--time", "1",
         "--para", "1", "--rounds", "1"],
        stdin="pw\ndecoypw\n",
    )
    assert code == tc.EXIT_OK

    code = _run_cli(monkeypatch, ["decrypt", str(enc), str(out), "--password-stdin"], stdin="decoypw\n")
    assert code == tc.EXIT_DECOY
    assert out.read_bytes() == b"fake"


def test_cli_bad_args_exit_1(monkeypatch: pytest.MonkeyPatch) -> None:
    """参数错误返回 1，不能和「诱饵命中」的 2 混淆。"""
    code = _run_cli(monkeypatch, ["decrypt", "--nonsense"])
    assert code == tc.EXIT_USAGE


def test_cli_missing_file_exit_4(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """文件不存在属于环境错误，返回 4。"""
    code = _run_cli(
        monkeypatch,
        ["decrypt", str(tmp_path / "nope.tarpit"), str(tmp_path / "o.bin"), "--password-stdin"],
        stdin="pw\n",
    )
    assert code == tc.EXIT_ENV


def test_cli_info_works_without_password(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """info 不需要口令，且能看到格式细节。"""
    src = tmp_path / "plain.bin"
    enc = tmp_path / "out.tarpit"
    src.write_bytes(b"payload")
    _run_cli(
        monkeypatch,
        ["encrypt", str(src), str(enc), "--password-stdin", "--mem", "8192",
         "--time", "1", "--para", "1", "--rounds", "1"],
        stdin="pw\n",
    )
    capsys.readouterr()
    assert tc.main(["info", str(enc)]) == tc.EXIT_OK
    captured = capsys.readouterr().out
    assert '"version": 1' in captured
    assert '"mem_kib": 8192' in captured
