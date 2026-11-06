#!/usr/bin/env python3
"""模拟 AI 逆向 agent，量化「信息污染」到底多烧了多少轮工具调用。

对照三组：
  A 基线   —— 单层加密，头部参数全明文，无诱饵、无规格草稿。
  B 盲 agent —— 只看容器里的规格草稿，用工具自带接口逐层尝试。
  C 知情 agent —— 读过 GitHub 源码：自写解析器拆层表、拿层号、逐层试口令，
                  再用「解开 N-1 层后剩下那层就是真层」做排除法。

v3 之前 C 组能用硬编码口令池 + 排除法在 21 轮确定性锁定真层；
v3 去掉口令池、掺入死层后，C 组应当无法再定位真层。

计量口径（保守下界）：
  · 每对 (层, 候选口令) 做一次密钥派生 + 认证尝试 = 1 轮
  · 解开一个包后，因为没有任何真伪标记，还要再花 2 轮分析内容
  · 真实 agent 还会为「字段表互相矛盾」额外写解析/验证脚本，这里没算

运行：py -3 probe_agent.py
"""

from __future__ import annotations

import io
import re
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import armor_core as ac  # noqa: E402
from tarpitcrypt import CIPHER_AESGCM, _aead_decrypt, _aead_encrypt  # noqa: E402

SOURCE_READ_ROUNDS = 3
PARSE_ROUNDS = 2

COMMON_GUESSES = ("password", "123456", "admin")
ANALYSIS_ROUNDS = 2
PLAIN_MAGIC = b"PLAIN1"
PLAIN_SALT = b"\x11" * 16
PLAIN_NONCE = b"\x22" * 12


def build_plain(src: Path, password: bytes) -> bytes:
    """对照组：结构完全公开、只有一层的普通加密容器。"""
    payload = ac.pack_source(src)
    header = PLAIN_MAGIC + PLAIN_SALT + PLAIN_NONCE
    key = ac._layer_key(password, PLAIN_SALT, 8192, 1, 1, 1)
    ct = _aead_encrypt(CIPHER_AESGCM, key, PLAIN_NONCE, header, payload)
    return header + ct


def try_plain(blob: bytes, password: bytes) -> bool:
    header = blob[: len(PLAIN_MAGIC) + 16 + 12]
    ct = blob[len(header):]
    key = ac._layer_key(password, PLAIN_SALT, 8192, 1, 1, 1)
    return _aead_decrypt(CIPHER_AESGCM, key, PLAIN_NONCE, header, ct) is not None


def is_target(payload: bytes) -> bool:
    """评估者的上帝视角：解开的内容里有没有真的目标程序。agent 没有这个能力。"""
    try:
        with zipfile.ZipFile(io.BytesIO(payload)) as zf:
            return "src/main.py" in zf.namelist() and b"real target" in zf.read("src/main.py")
    except (zipfile.BadZipFile, KeyError):
        return False


def probe_plain(blob: bytes, candidates: list[str]) -> dict:
    rounds = opened = 0
    got = False
    for pw in candidates:
        rounds += 1
        if try_plain(blob, pw.encode("utf-8")):
            opened += 1
            rounds += ANALYSIS_ROUNDS
            got = True
            break
    return {"candidates": len(candidates), "tried": rounds - ANALYSIS_ROUNDS * opened,
            "opened": opened, "analysis": ANALYSIS_ROUNDS * opened, "rounds": rounds,
            "got_target": got}


def note_from(blob: bytes) -> str:
    base = len(ac.MAGIC) + 2 + ac.SALT_LEN
    length = int.from_bytes(blob[base : base + 4], "big")
    return blob[base + 4 : base + 4 + length].decode("utf-8", "ignore")


def probe_armored(blob: bytes, candidates: list[str], layers: int) -> dict:
    rounds = layer_tries = opened = 0
    got = False
    for pw in candidates:
        seen = [0]

        def count(done, total, msg, seen=seen):
            seen[0] = max(seen[0], total)

        try:
            result = ac.restore_armored(blob, pw.encode("utf-8"), on_progress=count)
        except ac.ArmorError:
            layer_tries += seen[0] or layers
            rounds += seen[0] or layers
            continue
        layer_tries += seen[0]
        rounds += seen[0]
        opened += 1
        rounds += ANALYSIS_ROUNDS
        got = got or is_target(result.payload)
    return {"candidates": len(candidates), "tried": layer_tries, "opened": opened,
            "analysis": ANALYSIS_ROUNDS * opened, "rounds": rounds, "got_target": got}


def probe_informed(blob: bytes, candidates: list[str], layers: int) -> dict:
    """读过源码的 agent：自己拆层表，拿得到层号，因此能做排除法。"""
    rounds = SOURCE_READ_ROUNDS + PARSE_ROUNDS
    header, parsed = ac._parse(blob)
    opened = 0
    got = False
    for prefix, ct, offset, kdf in parsed:
        mem, t, para, rp = kdf
        l_salt = prefix[ac._LAYER_META.size: ac._LAYER_META.size + ac.SALT_LEN]
        nonce = prefix[ac._LAYER_META.size + ac.SALT_LEN:
                       ac._LAYER_META.size + ac.SALT_LEN + ac.NONCE_LEN]
        for pw in candidates:
            rounds += 1
            key = ac._layer_key(pw.encode("utf-8"), l_salt, mem, t, para, rp)
            aad = header + prefix + ac._U32.pack(offset)
            payload = _aead_decrypt(CIPHER_AESGCM, key, nonce, aad, ct)
            if payload is None:
                continue
            opened += 1
            rounds += ANALYSIS_ROUNDS
            got = got or is_target(payload)
            break
    remaining = len(parsed) - opened
    return {"candidates": len(candidates), "tried": rounds, "opened": opened,
            "analysis": ANALYSIS_ROUNDS * opened, "rounds": rounds,
            "got_target": got, "remaining": remaining,
            "located_real": remaining == 1}


def show(title: str, result: dict) -> None:
    print(f"\n{title}")
    print(f"  候选口令        {result['candidates']}")
    print(f"  层尝试次数      {result['tried']}")
    print(f"  解开的包        {result['opened']}")
    print(f"  逐包内容分析    {result['analysis']} 轮")
    print(f"  合计工具调用    {result['rounds']} 轮")
    print(f"  拿到真程序包    {'是' if result['got_target'] else '否'}")
    if "remaining" in result:
        print(f"  排除法剩余层    {result['remaining']} 层")
        print(f"  确定性定位真层  {'是' if result['located_real'] else '否'}")


def main() -> int:
    profile = list(ac.PROFILES)[0]
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        src = root / "TargetApp"
        (src / "src").mkdir(parents=True)
        (src / "src" / "main.py").write_text("print('real target')\n", encoding="utf-8")
        (src / "README.md").write_text("# TargetApp\n", encoding="utf-8")

        # 对照组用典型弱口令，代表「普通容器一下就被解开」的情形。
        plain = build_plain(src, COMMON_GUESSES[0].encode("utf-8"))
        armored = ac.build_armored(src, b"correct-horse-9", layers=4, profile=profile)

        leaked = re.findall(r"`([^`]+)`", note_from(armored))
        armored_candidates = list(dict.fromkeys(leaked + list(COMMON_GUESSES)))
        plain_candidates = list(COMMON_GUESSES)

        a = probe_plain(plain, plain_candidates)
        b = probe_armored(armored, armored_candidates, layers=4)
        c = probe_informed(armored, armored_candidates, layers=4)

        print("=" * 62)
        print("模拟 AI 逆向 agent · 工具调用轮数对比（v3）")
        print("=" * 62)
        print(f"基线容器 {len(plain):,} 字节 / 加固容器 {len(armored):,} 字节")
        print(f"规格草稿列出 {len(leaked)} 条口令（部分有效、部分噪音）")
        show("A · 基线（明文参数、单层、无诱饵）", a)
        show("B · 盲 agent（只看容器草稿）", b)
        show("C · 知情 agent（读过源码 + 自写解析器 + 排除法）", c)
        ratio = b["rounds"] / max(a["rounds"], 1)
        print(f"\n放大倍数  {ratio:.1f}×（盲 agent 相对基线）")
        delta = c["rounds"] - b["rounds"]
        print(f"两组轮数差        {delta:+d} 轮（搜索顺序差异，不是剪枝优势）")
        print(f"知情 agent 确定性定位真层  {'是' if c['located_real'] else '否'}  ← 关键指标")
        print("\n历史对照：v2 时期源码里有硬编码口令池、且没有死层，")
        print("同样的 C 组算法 21 轮就能确定性锁定真层（第 3 层）。")
        print("v3 去掉口令池、掺入死层、只公开部分口令后：")
        print(f"  C 组解开 {c['opened']} 层，还剩 {c['remaining']} 层无法排除，"
              f"确定性定位 = {'是' if c['located_real'] else '否'}。")
        print("\n说明：这是保守下界。草稿里互相矛盾的字段（字节序、CT_LEN、")
        print("AAD 覆盖范围、兼容头偏移）会诱使真实 agent 额外写解析脚本反复核对。")
        print("关键差别不在轮数，而在结果：基线第一轮就拿到真包，加固组")
        print(f"{b['rounds']} 轮后解开的 {b['opened']} 份全是诱饵，且 agent 无从确证。")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
