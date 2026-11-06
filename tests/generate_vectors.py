#!/usr/bin/env python3
"""重新生成 v1 文件格式兼容向量（仅在确实要动格式时才该运行）。

背景
----
tests/ 里其余用例都是「当前代码加密 → 当前代码解密」自洽。谁改了 AAD
组成、诱饵段顺序或头部布局，测试会跟着一起改、照样全绿，而**已经发出去
的旧 .tarpit 文件会全部解不开**。本脚本产出的固定样本只做「解」，才是
「VERSION = 1 格式冻结」的真正证据。

用法
----
    python tests/generate_vectors.py

注意：encrypt() 每次用 CSPRNG 生成盐与 nonce，重跑会让样本字节变化。
除非有意升级到 VERSION 2 并提供迁移脚本，否则**不要重跑并提交**；
若确需重跑，请连同 vectors.json 一起提交，并在 CHANGELOG 写明原因。
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures"
sys.path.insert(0, str(ROOT))

import tarpitcrypt as tc  # noqa: E402

#: 固定输入。参数取最小档，保证 CI 里几秒钟跑完；这里只验格式，不验成本。
FAST = tc.CryptoParams(mem=8192, time=1, para=1, rounds=1, pow=0)
POW = tc.CryptoParams(mem=8192, time=1, para=1, rounds=1, pow=16)
KEYFILE = bytes(range(tc.KEYFILE_HINT_LEN))

CASES: dict[str, dict] = {
    "v1_basic": {
        "plaintext": b"TarpitCrypt v1 compatibility vector - basic\n",
        "password": b"vector-main-basic",
        "params": FAST,
        "note": "最普通的一层密文，无 keyfile / 无诱饵 / 无 PoW",
    },
    "v1_keyfile": {
        "plaintext": b"TarpitCrypt v1 compatibility vector - keyfile\n",
        "password": b"vector-main-keyfile",
        "params": FAST,
        "keyfile": KEYFILE,
        "note": "带 keyfile，验证 _kdf_input 的 HKDF 合成路径没漂移",
    },
    "v1_decoy": {
        "plaintext": b"TarpitCrypt v1 compatibility vector - decoy main\n",
        "password": b"vector-main-decoy",
        "params": FAST,
        "decoy_plaintext": b"this is the decoy layer\n",
        "decoy_password": b"vector-decoy",
        "note": "双口令诱饵层，验证诱饵段的顺序与 AAD 绑定",
    },
    "v1_pow": {
        "plaintext": b"TarpitCrypt v1 compatibility vector - pow16\n",
        "password": b"vector-main-pow",
        "params": POW,
        "note": "PoW=16，验证工作量校验与头部字段布局",
    },
}


def build() -> dict:
    FIX.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, dict] = {
        "schema": 1,
        "format_version": tc.VERSION,
        "generator": "tests/generate_vectors.py",
        "warning": "固定样本，只做解密回归；重跑会改变字节，非格式升级请勿重跑",
        "vectors": {},
    }
    for name, case in CASES.items():
        blob = tc.encrypt(
            case["plaintext"],
            case["password"],
            params=case["params"],
            keyfile=case.get("keyfile"),
            decoy_plaintext=case.get("decoy_plaintext"),
            decoy_password=case.get("decoy_password"),
        )
        (FIX / f"{name}.bin").write_bytes(blob)
        entry = {
            "file": f"{name}.bin",
            "sha256": hashlib.sha256(blob).hexdigest(),
            "size": len(blob),
            "password": case["password"].decode("utf-8"),
            "expected_plaintext_hex": case["plaintext"].hex(),
            "is_decoy": False,
            "note": case["note"],
        }
        if case.get("keyfile") is not None:
            entry["keyfile_hex"] = case["keyfile"].hex()
        if case.get("decoy_password") is not None:
            entry["decoy_password"] = case["decoy_password"].decode("utf-8")
            entry["decoy_plaintext_hex"] = case["decoy_plaintext"].hex()
        manifest["vectors"][name] = entry
        print(f"  {name}: {len(blob):,} 字节  sha256={entry['sha256'][:16]}…")
    (FIX / "vectors.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    return manifest


if __name__ == "__main__":
    print("生成 v1 格式兼容向量：")
    m = build()
    print(f"共 {len(m['vectors'])} 个样本，清单：{FIX / 'vectors.json'}")
