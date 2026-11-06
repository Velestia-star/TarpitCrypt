#!/usr/bin/env python3
"""端到端自测：加固 → 还原 → 逐字节比对，以及 v3 加固项的回归验证。

运行：py -3 selftest.py
"""

from __future__ import annotations

import hashlib
import importlib
import io
import json
import py_compile
import struct
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import armor_core as ac  # noqa: E402
import decoy_kit as dk  # noqa: E402
from tarpitcrypt import CIPHER_AESGCM, _aead_decrypt, _aead_encrypt  # noqa: E402

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    (PASS if condition else FAIL).append(name)
    mark = "PASS" if condition else "FAIL"
    print(f"[{mark}] {name}" + (f"  {detail}" if detail else ""))


def make_package(root: Path) -> Path:
    src = root / "MyApp"
    (src / "src").mkdir(parents=True)
    (src / "config").mkdir()
    (src / "src" / "main.py").write_bytes(b"print('hello real app')\n" * 40)
    (src / "src" / "core.py").write_bytes(b"VALUE = 42\n")
    (src / "config" / "app.json").write_text('{"name":"MyApp","v":1}', encoding="utf-8")
    (src / "README.md").write_text("# MyApp\n", encoding="utf-8")
    return src


def solved_by(blob: bytes, passwords: tuple[str, ...]) -> list[bytes]:
    """返回这些口令能解开的所有层载荷。"""
    out = []
    for p in passwords:
        try:
            out.append(ac.restore_armored(blob, p.encode("utf-8")).payload)
        except ac.ArmorError:
            pass
    return out


def informed_agent_can_locate(blob: bytes) -> tuple[bool, int, int]:
    """模拟「读过 GitHub 源码」的 agent：自写解析器逐层试草稿里的口令。

    返回 (能否确定性定位真层, 解开的层数, 剩余层数)。v2 会因为「解开
    N-1 层后只剩 1 层」返回 True；v3 的死层与未公开口令应让它失败。
    """
    header, parsed = ac._parse(blob)
    pool = ac.armor_passwords(blob)
    opened = 0
    for idx, (prefix, ct, offset, kdf) in enumerate(parsed):
        mem, t, para, rp = kdf
        l_salt = prefix[ac._LAYER_META.size: ac._LAYER_META.size + ac.SALT_LEN]
        nonce = prefix[ac._LAYER_META.size + ac.SALT_LEN:
                       ac._LAYER_META.size + ac.SALT_LEN + ac.NONCE_LEN]
        for pw in pool:
            key = ac._layer_key(pw.encode("utf-8"), l_salt, mem, t, para, rp)
            aad = header + prefix + ac._U32.pack(offset)
            if _aead_decrypt(CIPHER_AESGCM, key, nonce, aad, ct) is not None:
                opened += 1
                break
    remaining = len(parsed) - opened
    return remaining == 1, opened, remaining


def build_legacy_v2(payload: bytes, password: bytes) -> bytes:
    """手工造一个 v2 格式容器，验证旧文件仍可被主口令还原。"""
    note = b"legacy"
    header = (ac.LEGACY_MAGIC + bytes((ac.LEGACY_VERSION, 2))
              + b"\x11" * ac.SALT_LEN + ac._U32.pack(len(note)) + note)
    body = bytearray()
    for i, pw in enumerate((password, b"other-layer-password")):
        l_salt = hashlib.sha256(bytes([i])).digest()[:ac.SALT_LEN]
        nonce = bytes([0x20 + i]) * ac.NONCE_LEN
        prefix = (ac._LAYER_META.pack(8192, 1, 1, 1) + l_salt + nonce
                  + ac._U64.pack(len(payload) + 16))
        offset = len(header) + len(body)
        aad = header + prefix + ac._U32.pack(offset)
        key = ac._layer_key(pw, l_salt, 8192, 1, 1, 1)
        body.extend(prefix)
        body.extend(_aead_encrypt(CIPHER_AESGCM, key, nonce, aad, payload))
    return header + bytes(body) + hashlib.sha256(header + bytes(body)).digest()


def main() -> int:
    profile = list(ac.PROFILES)[0]
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        src = make_package(root)
        original = (src / "src" / "main.py").read_bytes()
        pw = b"correct-horse-9"

        blob = ac.build_armored(src, pw, layers=4, profile=profile)
        check("生成 4 层 v3 加固容器", len(blob) > 2000, f"{len(blob):,} 字节")

        info = ac.inspect_armored(blob)
        check("只读摘要层数与版本正确", info.layers == 4 and info.version == 3)
        check("规格草稿已写入", info.note_size > 500, f"{info.note_size} 字节")
        check("摘要不含层号/真伪字段",
              not any(k in ac.ArmorInfo.__dataclass_fields__ for k in ("real_layer", "is_decoy")))

        real = ac.restore_armored(blob, pw)
        out = root / "restored"
        ac.safe_extract(real.payload, out)
        check("主口令还原逐字节一致",
              (out / "src" / "main.py").read_bytes() == original)
        check("还原结果不带层号/真伪标记",
              not any(k in ac.RestoreResult.__dataclass_fields__ for k in ("layer", "is_decoy")))
        check("统一尺寸的填充条目不落进用户目录",
              not any(ac.PAD_PREFIX in str(p) for p in out.rglob("*")))

        pool = ac.armor_passwords(blob)
        noise = ac.noise_password(blob)
        opened = solved_by(blob, pool)
        check("草稿口令部分能解开诱饵层", len(opened) >= 1, f"{len(opened)}/{len(pool)} 条有效")
        check("解开的都不是真包", all(x != real.payload for x in opened))
        check("诱饵包结构完整", len(opened) > 0 and
              any(zipfile.is_zipfile(io.BytesIO(x)) for x in opened))
        check("诱饵包与真包不可通过标记区分",
              all(".manifest" in zipfile.ZipFile(io.BytesIO(x)).namelist() for x in opened)
              and ".manifest" in real.entries)

        for bad in (noise.encode("utf-8"), b"totally-wrong"):
            try:
                ac.restore_armored(blob, bad)
                check(f"口令 {bad!r} 应被拒绝", False)
            except ac.ArmorError:
                check(f"口令 {bad!r} 被拒绝", True)

        # ---- S1：源码里没有可跨容器复用的口令池 ----
        check("源码不再导出硬编码口令池",
              not hasattr(ac, "DECOY_PASSWORDS") and not hasattr(ac, "NOISE_PASSWORD"))
        blob2 = ac.build_armored(src, pw, layers=4, profile=profile)
        pool2 = ac.armor_passwords(blob2)
        check("两次加固的草稿口令完全不同",
              bool(pool) and bool(pool2) and not (set(pool) & set(pool2)),
              f"{len(pool)} vs {len(pool2)} 条")
        try:
            ac.build_armored(src, pool[0].encode("utf-8"), layers=3, profile=profile)
            check("跨容器口令不冲突（无固定池）", True)
        except ac.ArmorError as exc:
            check("跨容器口令不冲突（无固定池）", False, str(exc))

        # ---- S2：死层让排除法失效 ----
        located, n_open, n_left = informed_agent_can_locate(blob)
        check("存在线索口令解不开的死层", n_left >= 2, f"解开 {n_open} 层 / 剩 {n_left} 层")
        check("读源码 agent 无法确定性定位真层", not located,
              f"剩余 {n_left} 层都可能是真层")
        big = ac.build_armored(src, pw, layers=ac.MAX_LAYERS, profile=profile)
        check("最大层数下排除法同样失效",
              not informed_agent_can_locate(big)[0])
        check("最大层数可用", ac.inspect_armored(big).layers == ac.MAX_LAYERS)

        # ---- S3：层尺寸对齐 + 诱饵去模板化 ----
        sizes = info.layer_sizes
        spread = (max(sizes) - min(sizes)) / max(sizes)
        check("各层尺寸接近，真层不是唯一最小层",
              spread < 0.15 and sum(s == min(sizes) for s in sizes) >= 1,
              f"极差 {max(sizes) - min(sizes)}B / 最大 {max(sizes)}B")
        shapes, py_bad = [], []
        for payload in opened:
            with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                names = zf.namelist()
                shapes.append(tuple(n for n in names if not n.startswith(ac.PAD_PREFIX)))
                for n in names:
                    if n.endswith(".py"):
                        try:
                            compile(zf.read(n).decode("utf-8", "replace"), n, "exec")
                        except SyntaxError:
                            py_bad.append(n)
        check("诱饵包里的 Python 全部语法正确", not py_bad, str(py_bad))
        check("多份诱饵包文件树互不相同",
              len(opened) < 2 or len({tuple(s) for s in shapes}) == len(shapes))

        # ---- 篡改 / 路径穿越 ----
        for label, mutate in (
            ("改头部字段", lambda b: b.__setitem__(30, b[30] ^ 1)),
            ("改尾部校验和", lambda b: b.__setitem__(-1, b[-1] ^ 1)),
            ("改层内密文", lambda b: b.__setitem__(len(b) // 2, b[len(b) // 2] ^ 1)),
        ):
            broken = bytearray(blob)
            mutate(broken)
            try:
                ac.inspect_armored(bytes(broken))
                check(f"{label}应被检出", False)
            except ac.ArmorError:
                check(f"{label}被检出", True)

        evil = io.BytesIO()
        with zipfile.ZipFile(evil, "w") as zf:
            zf.writestr("../../escaped.txt", b"nope")
        try:
            ac.safe_extract(evil.getvalue(), root / "evil_out")
            check("路径穿越应被拒绝", False)
        except ac.ArmorError:
            check("路径穿越被拒绝", True)

        # ---- v2 旧容器读取兼容 ----
        legacy = build_legacy_v2(ac.pack_source(src), pw)
        check("v2 容器摘要可解析", ac.inspect_armored(legacy).version == ac.LEGACY_VERSION)
        r_legacy = ac.restore_armored(legacy, pw)
        out2 = root / "legacy_out"
        ac.safe_extract(r_legacy.payload, out2)
        check("v2 容器仍可用主口令还原",
              (out2 / "src" / "main.py").read_bytes() == original)

        # ---- 单文件 / 参数边界 ----
        single = root / "single.exe"
        single.write_bytes(b"MZ\x90\x00" + b"x" * 2048)
        one = ac.build_armored(single, pw, layers=2, profile=profile)
        check("单文件输入可往返", single.name in ac.restore_armored(one, pw).entries)

        for label, kw in (("层数过小", {"layers": 1}), ("层数过大", {"layers": 9})):
            try:
                ac.build_armored(src, pw, profile=profile, **kw)
                check(f"{label}应被拒绝", False)
            except ac.ArmorError:
                check(f"{label}被拒绝", True)
        try:
            ac.build_armored(src, b"", profile=profile)
            check("空口令应被拒绝", False)
        except ac.ArmorError:
            check("空口令被拒绝", True)

        # ---- 伴生诱饵包 ----
        container = root / "MyApp.armored"
        container.write_bytes(blob)
        snapshot = {p.relative_to(src).as_posix(): p.read_bytes()
                    for p in src.rglob("*") if p.is_file()}
        kit = dk.build_sidecar(src, armored=container, layers=4)
        check("伴生包生成 12 份以上拟态文件", len(kit.files) >= 12, f"{len(kit.files)} 份")
        check("伴生包含 10 组以上矛盾线索", kit.traps >= 10, f"{kit.traps} 组")
        check("容器规格草稿已归档进伴生包", "docs/CONTAINER_DRAFT.md" in kit.files)
        check("原程序目录未被改动",
              snapshot == {p.relative_to(src).as_posix(): p.read_bytes()
                           for p in src.rglob("*") if p.is_file()})
        ok, count, why = dk.verify_sidecar(kit.root)
        check("伴生清单完整可核验", ok and count == len(kit.files), why)

        names = {item["name"] for item in json.loads(
            (kit.root / "config" / "passwords.json").read_text(encoding="utf-8"))}
        check("口令池与容器草稿口径一致", set(pool).issubset(names))
        check("伴生泄露口令解开的都不是真包",
              all(x != real.payload for x in solved_by(blob, tuple(kit.leaked))))

        bad = []
        for rel in kit.files:
            if rel.endswith(".py"):
                try:
                    py_compile.compile(str(kit.root / rel), doraise=True)
                except Exception:
                    bad.append(rel)
        check("伴生包里的 Python 全部语法正确", not bad, str(bad))
        sys.path.insert(0, str(kit.root / "tools"))
        fake = importlib.import_module("unpack")
        try:
            fake.read_header(blob)
            check("假解析器对真容器应失败", False)
        except (ValueError, struct.error):
            check("假解析器对真容器会失败（逼 agent 反复调试）", True)

        styles = []
        for i, style in enumerate(dk.STYLES):
            r = dk.build_sidecar(src, out_dir=root / f"kit_{i}", style=style)
            styles.append(r.root.name)
        check("三种拟态风格均可用且目录名不同", len(set(styles)) == 3, "/".join(styles))

        try:
            dk.build_sidecar(src, out_dir=kit.root, layers=4)
            check("已存在的非空目录应拒绝覆盖", False)
        except dk.SidecarError:
            check("已存在的非空目录拒绝覆盖", True)

    print(f"\n通过 {len(PASS)} / 失败 {len(FAIL)} / 合计 {len(PASS) + len(FAIL)}")
    if FAIL:
        print("失败项：" + "、".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
