#!/usr/bin/env python3
"""端到端自测：加固 → 还原 → 逐字节比对，以及诱饵/篡改/路径穿越行为。

运行：py -3 selftest.py
"""

from __future__ import annotations

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


def main() -> int:
    profile = list(ac.PROFILES)[0]
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        src = make_package(root)
        original = (src / "src" / "main.py").read_bytes()
        pw = b"correct-horse-9"

        blob = ac.build_armored(src, pw, layers=4, profile=profile)
        check("生成 4 层加固容器", len(blob) > 2000, f"{len(blob):,} 字节")

        info = ac.inspect_armored(blob)
        check("只读摘要层数正确", info.layers == 4)
        check("规格草稿已写入", info.note_size > 500, f"{info.note_size} 字节")
        check("摘要不含层号/真伪字段",
              not any(k in ac.ArmorInfo.__dataclass_fields__ for k in ("real_layer", "is_decoy")))

        real = ac.restore_armored(blob, pw)
        out = root / "restored"
        written = ac.safe_extract(real.payload, out)
        check("主口令还原逐字节一致",
              (out / "src" / "main.py").read_bytes() == original)
        check("还原结果不带层号/真伪标记",
              not any(k in ac.RestoreResult.__dataclass_fields__ for k in ("layer", "is_decoy")))

        leaked = ac.DECOY_PASSWORDS[0].encode("utf-8")
        decoy = ac.restore_armored(blob, leaked)
        check("草稿泄露的口令能解开诱饵层", decoy.payload != real.payload)
        check("诱饵包结构完整", decoy.file_count >= 5, f"{decoy.file_count} 个条目")
        check("诱饵包与真包不可通过标记区分",
              ".manifest" in decoy.entries and ".manifest" in real.entries)

        for bad in (ac.NOISE_PASSWORD.encode(), b"totally-wrong"):
            try:
                ac.restore_armored(blob, bad)
                check(f"口令 {bad!r} 应被拒绝", False)
            except ac.ArmorError:
                check(f"口令 {bad!r} 被拒绝", True)

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
        for name, data in (("路径穿越", evil.getvalue()),):
            try:
                ac.safe_extract(data, root / "evil_out")
                check(f"{name}应被拒绝", False)
            except ac.ArmorError:
                check(f"{name}被拒绝", True)

        single = root / "single.exe"
        single.write_bytes(b"MZ\x90\x00" + b"x" * 2048)
        one = ac.build_armored(single, pw, layers=2, profile=profile)
        r = ac.restore_armored(one, pw)
        check("单文件输入可往返", single.name in r.entries)

        big = ac.build_armored(src, pw, layers=ac.MAX_LAYERS, profile=profile)
        check("最大层数可用", ac.inspect_armored(big).layers == ac.MAX_LAYERS)

        for label, kw in (("层数过小", {"layers": 1}), ("层数过大", {"layers": 9})):
            try:
                ac.build_armored(src, pw, profile=profile, **kw)
                check(f"{label}应被拒绝", False)
            except ac.ArmorError:
                check(f"{label}被拒绝", True)

        try:
            ac.build_armored(src, ac.DECOY_PASSWORDS[0].encode(), profile=profile)
            check("主口令与调试口令冲突应被拒绝", False)
        except ac.ArmorError:
            check("主口令与调试口令冲突被拒绝", True)

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
        check("伴生包含 8 组以上矛盾线索", kit.traps >= 8, f"{kit.traps} 组")
        check("容器规格草稿已归档进伴生包", "docs/CONTAINER_DRAFT.md" in kit.files)
        check("原程序目录未被改动",
              snapshot == {p.relative_to(src).as_posix(): p.read_bytes()
                           for p in src.rglob("*") if p.is_file()})
        ok, count, why = dk.verify_sidecar(kit.root)
        check("伴生清单完整可核验", ok and count == len(kit.files), why)

        pool = json.loads((kit.root / "config" / "passwords.json").read_text(encoding="utf-8"))
        names = {item["name"] for item in pool}
        check("口令池与容器草稿口径一致", set(ac.leaked_passwords(4)).issubset(names))
        check("泄露口令解开的都不是真包",
              all(ac.restore_armored(blob, p.encode("utf-8")).payload != real.payload
                  for p in ac.leaked_passwords(4)))

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
