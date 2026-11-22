#!/usr/bin/env python3
"""运行时加固端到端自测。运行：python selftest.py"""

from __future__ import annotations

import io
import os
import py_compile
import sys
import tempfile
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import runtime_pack as rp  # noqa: E402

PASS: list[str] = []
FAIL: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (PASS if ok else FAIL).append(name)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}" + (f"  {detail}" if detail else ""))


def test_compile() -> None:
    for name in ("runtime_pack.py", "runtime_runner.py", "build_runner.py",
                 "drop_target.py", "armor_gui.py"):
        try:
            py_compile.compile(str(HERE / name), doraise=True)
            check(f"编译 {name}", True)
        except Exception as exc:
            check(f"编译 {name}", False, str(exc))


def test_runtime_pack() -> None:
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        src = root / "DemoApp"
        src.mkdir()
        (src / "start.bat").write_text("@echo off\necho hi\n", encoding="utf-8")
        (src / "secret.txt").write_text("SENTINEL_PLAIN_9527", encoding="utf-8")

        blob = rp.build_pack(src, "S3cure!Pass", profile="轻")
        info = rp.parse_pack(blob)
        check("RTPK 头部与清单", blob.startswith(rp.MAGIC)
              and info["manifest"].entry == "start.bat"
              and info["manifest"].files == 2)
        check("密文不含原文", b"SENTINEL_PLAIN_9527" not in blob)
        check("强度档生效", info["mem"] == 32 * 1024)

        try:
            rp.decrypt_pack(blob, "wrong")
            check("错口令拒绝", False)
        except rp.RuntimePackError:
            check("错口令拒绝", True)

        plain, man = rp.decrypt_pack(blob, "S3cure!Pass")
        out = root / "unpacked"
        rp.safe_extract(plain, out)
        check("正确口令还原原文件",
              (out / "secret.txt").read_text(encoding="utf-8") == "SENTINEL_PLAIN_9527")

        evil = io.BytesIO()
        with zipfile.ZipFile(evil, "w") as zf:
            zf.writestr("../../evil.txt", "x")
        try:
            rp.safe_extract(evil.getvalue(), root / "evil")
            check("拒绝 Zip Slip", False)
        except rp.RuntimePackError:
            check("拒绝 Zip Slip", True)

        rp.wipe_dir(out)
        check("退出擦除临时目录", not out.exists())

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


def test_password() -> None:
    ok, _ = rp.check_password("Tr0ub4dor&3-CorrectHorse")
    bad, _ = rp.check_password("123")
    check("口令强度检查", ok and not bad)


def test_gui_structure() -> None:
    src = (HERE / "armor_gui.py").read_text(encoding="utf-8")
    check("GUI 为极简单页（无 Notebook 页签）", "ttk.Notebook" not in src)
    check("GUI 仅保留运行时加固入口",
          all(k in src for k in ("_go", "build_pack", "embed"))
          and all(k not in src for k in ("_tab_armor", "_tab_restore", "_tab_kit")))


def test_drop() -> None:
    src = (HERE / "drop_target.py").read_text(encoding="utf-8")
    check("拖放覆盖整棵 HWND 树",
          "EnumChildWindows" in src and "def refresh(" in src)
    check("拖放消息只入队列不碰 Tcl",
          "_queue.put" in src and "after" not in src)
    check("WNDPROC 以整数地址注册（防 ArgumentError）",
          "ctypes.cast(self._proc_ref" in src
          and "GWL_WNDPROC, self._proc_addr" in src)

    if os.name == "nt":
        try:
            import tkinter as tk
            from drop_target import NativeDrop
            root = tk.Tk(); root.withdraw(); root.update()
            drop = NativeDrop(root, lambda _p: None)
            check("NativeDrop 实例化成功", drop.ok, drop.error)
            if drop.ok:
                drop.refresh()  # 复现旧 bug 的调用路径
                check("refresh 重复调用不抛异常", True)
            root.destroy()
        except Exception as exc:
            check("NativeDrop 实例化成功", False, str(exc))


def main() -> int:
    test_compile()
    test_runtime_pack()
    test_password()
    test_gui_structure()
    test_drop()
    print(f"\n通过 {len(PASS)} / 失败 {len(FAIL)} / 合计 {len(PASS)+len(FAIL)}")
    if FAIL:
        print("失败项：" + "、".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
