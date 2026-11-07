"""还原保真度与可运行性验证矩阵。

这个模块回答一个问题：**程序加固再还原之后，还能不能原样跑起来？**

字节一致不等于能跑。可执行位丢了、只读配置变可写、CRLF 被改写、相对导入
断链、符号链接变实体文件 —— 这些都不会让「还原成功」报错，却会让程序
的行为悄悄变掉。加密容器的价值全押在「还原出来的东西和原来一样」上，
所以这一层必须有硬验证，不能靠肉眼看。

两种用法：

    python -m armor.runtime_check              # 跑内置样例矩阵
    python -m armor.runtime_check <目录>       # 验证一个真实程序包
    python -m armor.runtime_check <目录> --run "python main.py"

真实程序包模式下会做逐字节 + 权限 + 目录结构三方比对，并可选执行入口
命令，比对退出码与标准输出。

安全边界：全程离线，不联网；只在临时目录里操作副本，**原目录一个字节都不改**。
"""

from __future__ import annotations

import argparse
import filecmp
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from console_utf8 import ensure  # noqa: E402

ensure()
import armor_core as ac  # noqa: E402

IS_WINDOWS = os.name == "nt"

#: 内置矩阵用的口令。测试专用，真实使用请另设。
TEST_PASSWORD = "runtime-matrix-pw-9271"


@dataclass
class CheckResult:
    """一条验证项的结果。"""

    name: str
    ok: bool
    detail: str = ""


@dataclass
class Report:
    results: list[CheckResult] = field(default_factory=list)

    def add(self, name: str, ok: bool, detail: str = "") -> None:
        self.results.append(CheckResult(name, ok, detail))

    @property
    def failed(self) -> list[CheckResult]:
        return [r for r in self.results if not r.ok]

    def render(self) -> str:
        lines = []
        for r in self.results:
            mark = "PASS" if r.ok else "FAIL"
            lines.append(f"[{mark}] {r.name}" + (f"  {r.detail}" if r.detail else ""))
        total = len(self.results)
        bad = len(self.failed)
        lines.append("")
        lines.append(f"通过 {total - bad} / 失败 {bad} / 合计 {total}")
        if bad:
            lines.append("失败项：" + "、".join(r.name for r in self.failed))
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# 清理工具：只读文件会让 rmtree 失败
# ---------------------------------------------------------------------------
def _force_rmtree(path: Path) -> None:
    """删目录树，遇到只读文件先恢复可写再删。

    Python 3.12 起 shutil.rmtree 的 onerror 已弃用、3.13 改用 onexc，
    这里两个都兼容。
    """

    def _fix(func, p, _exc):
        try:
            os.chmod(p, stat.S_IWRITE | stat.S_IREAD)
            func(p)
        except OSError:
            pass

    try:
        shutil.rmtree(path, onexc=_fix)
    except TypeError:  # Python < 3.12
        shutil.rmtree(path, onerror=_fix)
    except FileNotFoundError:
        pass


# ---------------------------------------------------------------------------
# 打包 → 还原 → 还原出来的程序跑起来
# ---------------------------------------------------------------------------
def roundtrip(src: Path, work: Path, password: str = TEST_PASSWORD,
              layers: int = 3) -> tuple[Path, bytes]:
    """走完整链路加固→还原→解包，返回（还原目录, 还原出的载荷）。"""
    blob = ac.build_armored(src, password.encode("utf-8"), layers=layers,
                            profile="轻（秒级）")
    payload = ac.restore_armored(blob, password.encode("utf-8")).payload
    out = work / "restored"
    ac.safe_extract(payload, out)
    return out, payload


def archive_modes(payload: bytes) -> dict[str, int]:
    """取归档内各条目的权限位（供跨平台断言用）。"""
    import io
    import zipfile
    out: dict[str, int] = {}
    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            out[info.filename] = (info.external_attr >> 16) & 0o777
    return out


def _is_cache_path(rel: str) -> bool:
    """这条路径是不是「字节码缓存」？

    缓存**不保证往返**：有源码的字节码会被刻意排除（它绑定了编译机器与
    原始路径，换机必然失效）。所以比对时要忽略它们，否则测试自己跑一次
    程序生成的 __pycache__ 就会造成假失败。
    """
    return ("__pycache__" in rel.split("/")
            or rel.endswith((".pyc", ".pyo")))


def compare_trees(original: Path, restored: Path) -> list[str]:
    """逐字节 + 权限 + 结构三方比对，返回差异描述列表。"""
    problems: list[str] = []

    orig_files = {p.relative_to(original).as_posix()
                  for p in original.rglob("*")
                  if p.is_file() and not p.is_symlink()
                  and not _is_cache_path(p.relative_to(original).as_posix())}
    rest_files = {p.relative_to(restored).as_posix()
                  for p in restored.rglob("*") if p.is_file()
                  and not _is_cache_path(p.relative_to(restored).as_posix())}
    missing = orig_files - rest_files
    extra = rest_files - orig_files
    if missing:
        problems.append(f"缺失文件：{sorted(missing)[:5]}")
    if extra:
        problems.append(f"多出文件：{sorted(extra)[:5]}")

    orig_dirs = {p.relative_to(original).as_posix()
                 for p in original.rglob("*")
                 if p.is_dir() and p.name != "__pycache__"}
    rest_dirs = {p.relative_to(restored).as_posix()
                 for p in restored.rglob("*")
                 if p.is_dir() and p.name != "__pycache__"}
    if orig_dirs - rest_dirs:
        problems.append(f"缺失目录：{sorted(orig_dirs - rest_dirs)[:5]}")

    for rel in sorted(orig_files & rest_files):
        a, b = original / rel, restored / rel
        if not filecmp.cmp(a, b, shallow=False):
            problems.append(f"内容不一致：{rel}")
            continue
        am = stat.S_IMODE(a.stat().st_mode)
        bm = stat.S_IMODE(b.stat().st_mode)
        # Windows 上只有只读位有意义，执行位恒等于 0 —— 只比「是否只读」。
        if IS_WINDOWS:
            if bool(am & 0o200) != bool(bm & 0o200):
                problems.append(f"只读属性不一致：{rel}")
        elif am != bm:
            # 带 shebang 的入口脚本会被主动补上执行位（兼容旧容器），
            # 这种「只多不减」不算差异。
            if not (bm & 0o111 and not (am & 0o111)
                    and a.read_bytes()[:2] == b"#!"):
                problems.append(f"权限不一致：{rel}（{am:o} → {bm:o}）")
    return problems


# ---------------------------------------------------------------------------
# 内置样例矩阵
# ---------------------------------------------------------------------------
def build_sample_app(root: Path) -> Path:
    """构造一个「像真程序」的程序包，覆盖各种容易在往返中出问题的形态。"""
    app = root / "SampleApp"
    (app / "pkg" / "sub").mkdir(parents=True)
    (app / "data").mkdir()
    (app / "empty_dir").mkdir()

    # 入口：相对导入 + 读同目录资源 + 中文输出 + 写文件
    (app / "pkg" / "helper.py").write_text(
        "GREETING = '你好，加密容器'\n"
        "def twice(n):\n"
        "    return n * 2\n",
        encoding="utf-8")
    (app / "pkg" / "__init__.py").write_text("", encoding="utf-8")
    (app / "pkg" / "sub" / "data.bin").write_bytes(bytes(range(256)))
    (app / "pkg" / "main.py").write_text(
        "import sys, os\n"
        "from helper import GREETING, twice\n"
        "here = os.path.dirname(os.path.abspath(__file__))\n"
        "blob = open(os.path.join(here, 'sub', 'data.bin'), 'rb').read()\n"
        "print(GREETING, twice(21))\n"
        "print('BIN-SUM', sum(blob) % 251)\n"
        "print('CWD-FILES', len(os.listdir(here)))\n"
        "sys.exit(0 if len(blob) == 256 else 3)\n",
        encoding="utf-8")
    # CRLF 行尾的文本
    (app / "data" / "windows.txt").write_bytes(b"line1\r\nline2\r\n")
    # 带 BOM 的 UTF-8
    (app / "data" / "bom.txt").write_bytes("﻿带 BOM 的配置\n".encode("utf-8"))
    # 空文件
    (app / "data" / "empty.bin").write_bytes(b"")
    # 中文名 + 空格
    (app / "data" / "中文 名.txt").write_text("名字带空格与中文\n", encoding="utf-8")
    # 只读配置
    ro = app / "data" / "readonly.cfg"
    ro.write_text("[config]\nvalue = 1\n", encoding="utf-8")
    os.chmod(ro, 0o444)
    # 可执行脚本（POSIX 才有执行位；Windows 上靠扩展名）
    if not IS_WINDOWS:
        sh = app / "run.sh"
        sh.write_text("#!/bin/sh\necho SH-OK\n", encoding="utf-8")
        os.chmod(sh, 0o755)
    else:
        bat = app / "run.bat"
        bat.write_bytes(b"@echo off\r\necho BAT-OK\r\n")
    # 稍大一点的文件，验证流式读写
    (app / "data" / "big.bin").write_bytes(bytes(range(256)) * 4096)
    return app


def run_builtin_matrix(rep: Report, work: Path) -> None:
    """跑内置样例矩阵。"""
    app = build_sample_app(work)

    # --- 先测原始程序自身跑得通 ---
    baseline = subprocess.run([sys.executable, "pkg/main.py"], cwd=app,
                              capture_output=True, text=True, timeout=120)
    rep.add("原始样例程序自身可运行", baseline.returncode == 0,
            f"退出码 {baseline.returncode} / {baseline.stderr.strip()[:120]}")

    restored, payload = roundtrip(app, work)

    # --- 内容与结构保真 ---
    problems = compare_trees(app, restored)
    rep.add("往返后内容/权限/结构完全一致", not problems,
            "；".join(problems[:4]))

    # --- 归档内权限位正确（跨平台可验证：Windows 没有执行位，但归档里
    #     必须记着 755，否则还原到 Linux 上程序就跑不起来） ---
    modes = archive_modes(payload)
    if IS_WINDOWS:
        rep.add("归档内记录了源文件权限位",
                modes.get("data/readonly.cfg") == 0o444,
                f"readonly.cfg={modes.get('data/readonly.cfg'):o}"
                if modes.get("data/readonly.cfg") is not None else "条目缺失")
    else:
        rep.add("归档内记录了源文件权限位",
                modes.get("run.sh") == 0o755
                and modes.get("data/readonly.cfg") == 0o444,
                f"run.sh={modes.get('run.sh'):o} "
                f"readonly.cfg={modes.get('data/readonly.cfg'):o}")

    # --- 还原后的程序真的能跑，且输出一致 ---
    run = subprocess.run([sys.executable, "pkg/main.py"], cwd=restored,
                         capture_output=True, text=True, timeout=120)
    rep.add("还原后程序输出与退出码与原始一致",
            run.stdout == baseline.stdout and run.returncode == baseline.returncode,
            f"原始 {baseline.stdout.strip()[:80]!r} / 还原 {run.stdout.strip()[:80]!r} "
            f"退出码 {run.returncode}")

    # --- 只读属性保留 ---
    ro_o = app / "data" / "readonly.cfg"
    ro_r = restored / "data" / "readonly.cfg"
    if IS_WINDOWS:
        same = bool(os.stat(ro_o).st_mode & 0o200) == bool(os.stat(ro_r).st_mode & 0o200)
        rep.add("只读文件的只读属性保留", same,
                f"原始 {stat.S_IMODE(os.stat(ro_o).st_mode):o} / "
                f"还原 {stat.S_IMODE(os.stat(ro_r).st_mode):o}")
    else:
        same = stat.S_IMODE(ro_o.stat().st_mode) == stat.S_IMODE(ro_r.stat().st_mode)
        rep.add("只读文件的权限位保留", same,
                f"原始 {stat.S_IMODE(ro_o.stat().st_mode):o} / "
                f"还原 {stat.S_IMODE(ro_r.stat().st_mode):o}")

    # --- 可执行位保留 + 直接执行成功 ---
    if IS_WINDOWS:
        r = subprocess.run(["cmd", "/c", "run.bat"], cwd=restored,
                           capture_output=True, text=True, timeout=120)
        rep.add("还原后的 .bat 可直接执行", r.returncode == 0 and "BAT-OK" in r.stdout,
                r.stdout.strip()[:60] or r.stderr.strip()[:60])
    else:
        sh_r = restored / "run.sh"
        exec_bit = bool(stat.S_IMODE(sh_r.stat().st_mode) & 0o111)
        rep.add("可执行脚本的执行位保留", exec_bit,
                f"权限 {stat.S_IMODE(sh_r.stat().st_mode):o}")
        r = subprocess.run(["./run.sh"], cwd=restored,
                           capture_output=True, text=True, timeout=120)
        rep.add("还原后的 .sh 可直接执行", r.returncode == 0 and "SH-OK" in r.stdout,
                r.stdout.strip()[:60] or r.stderr.strip()[:60])

    # --- 行尾 / BOM 不被改写 ---
    crlf = (restored / "data" / "windows.txt").read_bytes()
    rep.add("CRLF 行尾不被改写", crlf == b"line1\r\nline2\r\n", repr(crlf[:24]))
    bom = (restored / "data" / "bom.txt").read_bytes()
    rep.add("UTF-8 BOM 被保留", bom.startswith(b"\xef\xbb\xbf"), repr(bom[:12]))

    # --- 空文件 / 空目录 / 中文名 ---
    rep.add("空文件还原后仍为 0 字节",
            (restored / "data" / "empty.bin").stat().st_size == 0)
    rep.add("空目录还原后仍存在", (restored / "empty_dir").is_dir())
    rep.add("中文与空格文件名可访问",
            (restored / "data" / "中文 名.txt").is_file())

    # --- 大文件一致 ---
    big_o = (app / "data" / "big.bin").read_bytes()
    big_r = (restored / "data" / "big.bin").read_bytes()
    rep.add("大文件逐字节一致", big_o == big_r, f"{len(big_r)} 字节")

    # --- 旧格式容器兼容：v0.3.8 之前所有条目一律记 644 ---
    #     那种容器还原出来的入口脚本没有执行位，程序直接跑不起来。
    #     这里手工构造一份「旧格式」zip 验证补救逻辑生效。
    legacy_zip = work / "legacy.zip"
    with zipfile.ZipFile(legacy_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        info = zipfile.ZipInfo("legacy_entry.sh")
        info.external_attr = 0o644 << 16
        zf.writestr(info, b"#!/bin/sh\necho LEGACY-OK\n")
    legacy_out = work / "legacy_out"
    ac.safe_extract(legacy_zip.read_bytes(), legacy_out)
    legacy_file = legacy_out / "legacy_entry.sh"
    if IS_WINDOWS:
        rep.add("旧格式容器的 shebang 脚本内容完好",
                legacy_file.read_bytes().startswith(b"#!"), "")
    else:
        has_exec = bool(stat.S_IMODE(legacy_file.stat().st_mode) & 0o111)
        r = subprocess.run(["./legacy_entry.sh"], cwd=legacy_out,
                           capture_output=True, text=True, timeout=120)
        rep.add("旧格式容器的 shebang 入口脚本仍可执行",
                has_exec and r.returncode == 0 and "LEGACY-OK" in r.stdout,
                f"权限 {stat.S_IMODE(legacy_file.stat().st_mode):o} / "
                f"输出 {r.stdout.strip()[:40]!r}")

    # --- 字节码：可再生的缓存不进包，pyc-only 部署必须完整保留 ---
    #     有源码的字节码绑定编译机器与原始路径，换机必然失效，带进去
    #     还泄露部署路径；但「只有字节码没有源码」的生产部署，字节码
    #     就是唯一的代码，丢了程序直接 import 失败。
    cache_app = work / "CacheApp"
    (cache_app / "__pycache__").mkdir(parents=True)
    (cache_app / "with_src.py").write_text("X = 1\n", encoding="utf-8")
    (cache_app / "__pycache__" / "with_src.cpython-313.pyc").write_bytes(
        b"\x00\x00\x00\x00" + b"path-leak" * 8)
    (cache_app / "__pycache__" / "lonely.cpython-313.pyc").write_bytes(
        b"\x00\x00\x00\x01" + b"only-code" * 8)
    cache_out, cache_payload = roundtrip(cache_app, work / "cache")
    cache_modes = archive_modes(cache_payload)
    rep.add("有源码的字节码不进容器",
            not any(n.endswith(".pyc") and "with_src" in n for n in cache_modes),
            str([n for n in cache_modes
                 if n.endswith(".pyc") and "with_src" in n]))
    rep.add("无源码的字节码（pyc-only 部署）完整保留",
            (cache_out / "__pycache__" / "lonely.cpython-313.pyc").is_file()
            and (cache_out / "__pycache__"
                 / "lonely.cpython-313.pyc").read_bytes()
            == (cache_app / "__pycache__" / "lonely.cpython-313.pyc").read_bytes())

    # --- 还原目录可写（程序要能落盘） ---
    probe = restored / "data" / "_write_probe.tmp"
    try:
        probe.write_text("x", encoding="utf-8")
        probe.unlink()
        writable = True
    except OSError as exc:
        writable = False
        detail = str(exc)
    rep.add("还原目录可写（程序能落盘）", writable,
            "" if writable else detail)

    # --- 符号链接：包内跟随、包外拒绝 ---
    if not IS_WINDOWS:
        os.symlink(app / "pkg" / "helper.py", app / "link_helper.py")
        try:
            out2, _ = roundtrip(app, work / "sym")
            target = out2 / "link_helper.py"
            rep.add("包内符号链接还原后内容可用",
                    target.is_file()
                    and target.read_text(encoding="utf-8") == (app / "pkg" / "helper.py").read_text(encoding="utf-8"))
        except ac.ArmorError as exc:
            rep.add("包内符号链接还原后内容可用", False, str(exc))

        outside = work / "outside.txt"
        outside.write_text("secret\n", encoding="utf-8")
        try:
            os.symlink(outside, app / "link_outside.txt")
        except OSError:
            pass
        else:
            try:
                roundtrip(app, work / "sym_out")
                rep.add("指向包外的符号链接被拒绝加固", False, "竟然构建成功了")
            except ac.ArmorError:
                rep.add("指向包外的符号链接被拒绝加固", True)


def run_real_package(rep: Report, src: Path, work: Path,
                      command: str | None) -> None:
    """验证一个真实程序包。"""
    restored = roundtrip(src, work)
    problems = compare_trees(src, restored)
    rep.add("往返后内容/权限/结构完全一致", not problems, "；".join(problems[:6]))

    if command:
        cmd = command.split()
        base = subprocess.run(cmd, cwd=src, capture_output=True,
                              text=True, timeout=300)
        after = subprocess.run(cmd, cwd=restored, capture_output=True,
                              text=True, timeout=300)
        rep.add("入口命令输出与退出码一致",
                base.stdout == after.stdout and base.returncode == after.returncode,
                f"原始退出码 {base.returncode} / 还原退出码 {after.returncode}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="加固→还原 的保真度与可运行性验证")
    ap.add_argument("path", nargs="?", help="要验证的程序包目录（不给则跑内置矩阵）")
    ap.add_argument("--run", dest="command",
                    help="入口命令，如 \"python main.py\"；给了就比对运行结果")
    ap.add_argument("--layers", type=int, default=3, help="加密层数（默认 3）")
    args = ap.parse_args(argv)

    rep = Report()
    work = Path(tempfile.mkdtemp(prefix="tarpit-runtime-"))
    try:
        if args.path:
            src = Path(args.path)
            if not src.exists():
                print(f"路径不存在：{src}")
                return 2
            run_real_package(rep, src, work, args.command)
        else:
            run_builtin_matrix(rep, work)
    finally:
        _force_rmtree(work)

    print(rep.render())
    return 0 if not rep.failed else 1


if __name__ == "__main__":
    raise SystemExit(main())
