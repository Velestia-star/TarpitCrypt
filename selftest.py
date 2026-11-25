#!/usr/bin/env python3
"""TarpitCrypt 0.5 端到端自测。运行：python selftest.py"""

from __future__ import annotations

import io
import os
import py_compile
import sys
import tempfile
import time
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import runtime_pack as rp  # noqa: E402
import trap_guard  # noqa: E402

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append(name)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))


def test_compile() -> None:
    for name in ("runtime_pack.py", "runtime_runner.py", "build_runner.py",
                 "drop_target.py", "armor_gui.py", "trap_kit.py", "trap_guard.py"):
        try:
            py_compile.compile(str(HERE / name), doraise=True)
            check(f"编译 {name}", True)
        except Exception as exc:
            check(f"编译 {name}", False, str(exc))


def _demo_source(root: Path) -> Path:
    src = root / "DemoApp"
    src.mkdir()
    (src / "start.bat").write_text("@echo off\necho hi\n", encoding="utf-8")
    (src / "secret.txt").write_text("SENTINEL_PLAIN_9527", encoding="utf-8")
    return src


def test_container() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        src = _demo_source(root)

        started = time.perf_counter()
        blob, stats = rp.build_container(src, decoys=6, farm_mb=1,
                                         trap_profile="标准", guard=True)
        build_seconds = time.perf_counter() - started
        check("陷阱容器构建", blob.startswith(rp.CORE_MAGIC), f"{build_seconds:.2f}s")
        check("包数量 = 1 真 + 6 假 + 1 农场", stats["packs"] == 8, str(stats["packs"]))
        check("反探测开关写入容器", rp.parse_container(blob)["guard"] is True)

        packs = rp.parse_container(blob)["packs"]
        check("所有包宣称高成本 KDF",
              all(p["mem"] == 384 * 1024 and p["time"] == 3 for p in packs))
        check("密文不含原文", b"SENTINEL_PLAIN_9527" not in blob)

        started = time.perf_counter()
        plain, manifest, core = rp.open_core(blob)
        core_seconds = time.perf_counter() - started
        check("正常启动核心解密 < 1s", core_seconds < 1.0,
              f"{core_seconds * 1000:.0f}ms")
        check("正确还原真实程序包", manifest.entry == "start.bat")

        key = rp._core_key(packs)
        opened = [p for p in packs if rp._try_key(key, p) is not None]
        check("核心密钥只能打开真包", len(opened) == 1 and opened[0]["offset"] == core["offset"])

        farms = rp.open_farms(blob)
        check("诱饵农场可解出", len(farms) == 1 and len(farms[0][0]) > 1024)
        out = root / "farm"
        farm_files = rp.safe_extract(farms[0][0], out)
        check("农场含大量假源码", len(farm_files) > 60, str(len(farm_files)))
        text = b"".join(p.read_bytes() for p in farm_files
                        if p.suffix in {".py", ".ts", ".md", ".json"} and p.stat().st_size < 65536)
        check("农场内容为诱饵工程", b"example.invalid" in text or b"license" in text)
        check("农场内含嵌套假包",
              any(p.suffix == ".rpk" for p in farm_files))

        check("容器内有多处伪造 footer", blob.count(rp.FOOTER_MAGIC) >= 3,
              str(blob.count(rp.FOOTER_MAGIC)))

        info = rp.inspect_blob(blob)
        check("inspect 统计正确",
              info["count"] == 8 and info["decoys"] == 6
              and info["farm_packs"] == 1 and info["real_index"] >= 0)

        source = (HERE / "runtime_pack.py").read_text(encoding="utf-8")
        check("源码中无静态密钥常量",
              "_K1" not in source and "hash_secret_raw" not in source)

        tweaked = bytearray(blob)
        other = next(p for p in packs if p["offset"] != core["offset"])
        tweaked[other["offset"] + 17] ^= 0xFF  # 改掉某个假包的 salt
        try:
            rp.open_core(bytes(tweaked))
            check("篡改任一包头导致核心无法解密", False)
        except rp.RuntimePackError:
            check("篡改任一包头导致核心无法解密", True)

        fake = root / "fake.exe"
        fake.write_bytes(b"MZ" + b"\x00" * 100)
        single = root / "single.exe"
        rp.embed(fake, blob, single)
        check("尾部注入读回", rp.read_embedded(single) == blob
              and single.read_bytes().startswith(b"MZ"))

        tampered = bytearray(single.read_bytes())
        tampered[-25] ^= 0xFF
        single.write_bytes(tampered)
        try:
            rp.read_embedded(single)
            check("篡改 exe 被检出", False)
        except rp.RuntimePackError:
            check("篡改 exe 被检出", True)

        evil = io.BytesIO()
        with zipfile.ZipFile(evil, "w") as zf:
            zf.writestr("../../evil.txt", "x")
        try:
            rp.safe_extract(evil.getvalue(), root / "evil")
            check("拒绝 Zip Slip", False)
        except rp.RuntimePackError:
            check("拒绝 Zip Slip", True)

        rp.wipe_dir(out)
        check("退出擦除诱饵目录", not out.exists())

        try:
            rp.parse_container(blob[:24])
            check("截断容器友好报错", False)
        except rp.RuntimePackError:
            check("截断容器友好报错", True)


def test_excludes_entry() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        pkg = root / "Pkg"
        (pkg / "bin").mkdir(parents=True)
        (pkg / ".git").mkdir()
        (pkg / "__pycache__").mkdir()
        (pkg / "node_modules").mkdir()
        (pkg / "start.bat").write_text("@echo off\n", encoding="utf-8")
        (pkg / "data.txt").write_text("d", encoding="utf-8")
        (pkg / ".git" / "config").write_text("g", encoding="utf-8")
        (pkg / "__pycache__" / "x.pyc").write_bytes(b"c")
        (pkg / "app.log").write_text("l", encoding="utf-8")
        (pkg / ".env").write_text("SECRET=1", encoding="utf-8")
        (pkg / "node_modules" / "keep.js").write_text("k", encoding="utf-8")
        (pkg / "node_modules" / "fake.exe").write_bytes(b"MZ")
        (pkg / "bin" / "tool.exe").write_bytes(b"MZ")

        candidates = rp.candidate_entries(pkg)
        check("入口扫描包含根/子目录",
              "start.bat" in candidates and "bin/tool.exe" in candidates)
        check("入口扫描跳过 node_modules",
              all("node_modules" not in c for c in candidates))

        info = rp.scan_package(pkg)
        check("默认排除统计", info["files"] == 5 and info["excluded"] >= 3, str(info))

        blob, stats = rp.build_container(pkg, decoys=0, farm_mb=0)
        check("默认排除后打包 5 个文件",
              stats["included_files"] == 5 and stats["excluded_items"] >= 3,
              str(stats["included_files"]))
        plain, _manifest, _core = rp.open_core(blob)
        out = root / "unpacked"
        rp.safe_extract(plain, out)
        check("排除项未进包",
              not (out / ".git").exists()
              and not (out / "app.log").exists()
              and (out / "node_modules" / "keep.js").exists())

        _blob2, stats2 = rp.build_container(
            pkg, entry="bin/tool.exe", decoys=0, farm_mb=0)
        check("显式子目录入口可用", stats2["entry"] == "bin/tool.exe")

        _blob3, stats3 = rp.build_container(
            pkg, decoys=0, farm_mb=0, excludes=[])
        check("关闭默认排除后文件数增加", stats3["included_files"] == 9,
              str(stats3["included_files"]))

        fake_runner = root / "fake_runner.exe"
        fake_runner.write_bytes(b"MZ" + b"\x00" * 64)
        rp.embed(fake_runner, b"dummy", pkg / "old_protected.exe")
        check("入口扫描跳过已加固 exe",
              "old_protected.exe" not in rp.candidate_entries(pkg))
        check("自动入口跳过已加固 exe",
              rp._detect_entry(pkg, None) == "start.bat")
        _blob4, stats4 = rp.build_container(pkg, decoys=0, farm_mb=0)
        check("已加固 exe 不会被再次打包",
              stats4["included_files"] == 5
              and stats4["excluded_items"] >= 5,
              f"files={stats4['included_files']} excluded={stats4['excluded_items']}")


def test_guard() -> None:
    normal = trap_guard.assess(env={}, parent="explorer.exe", debugger=False)
    check("常规双击判定 normal", normal.level == "normal", str(normal.signals))
    normal_env = trap_guard.assess(env={"OPENAI_API_KEY": "x"},
                                   parent="explorer.exe", debugger=False)
    check("单个环境变量不误伤", normal_env.level == "normal", str(normal_env.signals))
    medium = trap_guard.assess(
        env={"OPENAI_API_KEY": "x"}, parent="python.exe", debugger=False)
    check("AI Agent 双信号命中 medium", medium.level == "medium", str(medium.signals))
    strong = trap_guard.assess(env={}, parent="explorer.exe", debugger=True)
    check("调试器命中 strong", strong.level == "strong")
    check("口令式参数视为破解尝试",
          trap_guard.crack_attempt(["--password", "x"], env={})
          and trap_guard.crack_attempt([], env={"RTPK_PASSWORD": "x"})
          and not trap_guard.crack_attempt([], env={}))


def test_gui_structure() -> None:
    src = (HERE / "armor_gui.py").read_text(encoding="utf-8")
    check("GUI 无口令输入", "simpledialog" not in src and "check_password" not in src)
    check("GUI 暴露陷阱参数",
          all(k in src for k in ("decoys", "farm_mb", "trap_profile", "build_container")))
    check("GUI 支持入口选择与排除",
          all(k in src for k in ("candidate_entries", "entry_combo",
                                 "exclude_defaults", "scan_package")))
    check("GUI 仍为单页", "ttk.Notebook" not in src)


def main() -> int:
    test_compile()
    test_container()
    test_excludes_entry()
    test_guard()
    test_gui_structure()
    print(f"\n通过 {len(PASS)} / 失败 {len(FAIL)} / 合计 {len(PASS) + len(FAIL)}")
    if FAIL:
        print("失败项：" + "、".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
