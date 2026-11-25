#!/usr/bin/env python3
"""TarpitCrypt · 正常双击即用 + 反 AI 逆向成本陷阱。

流程：拖入程序包 → 设置假包 / 诱饵 → 选启动器 → 生成 exe。
分发后双击直接运行（无口令）；调试器或自动化破解工具才会撞进陷阱。

依赖：Python 3.11+ / tkinter / argon2-cffi / cryptography；
构建原生启动器需 Go 1.22+（缺失时回退 PyInstaller）。
"""

from __future__ import annotations

import ctypes
import os
import queue
import subprocess
import sys
import threading
import tkinter as tk
import traceback
from pathlib import Path
from tkinter import filedialog, font, messagebox, scrolledtext, ttk

try:
    import runtime_pack as rpk
except ImportError:
    rpk = None  # main() 给出友好提示

APP_TITLE = "TarpitCrypt · 正常运行 + 反 AI 逆向陷阱"
ACCENT = "#185FA5"


def _open_dir(path: Path) -> None:
    if os.name == "nt":
        os.startfile(str(path))  # noqa: S606
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


def _enable_dpi() -> None:
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        _enable_dpi()
        self.title(APP_TITLE)
        self.geometry("900x760")
        self.minsize(800, 680)
        try:
            ttk.Style().theme_use("clam")
        except tk.TclError:
            pass
        font.nametofont("TkDefaultFont").configure(size=10)

        self.q: queue.Queue = queue.Queue()
        self.busy = False
        self.src = tk.StringVar()
        self.out = tk.StringVar()
        self.entry = tk.StringVar()
        self.exclude_defaults = tk.BooleanVar(value=True)
        self.pkg_info = tk.StringVar()
        self.decoys = tk.StringVar(value="12")
        self.farm_mb = tk.StringVar(value="8")
        self.trap_profile = tk.StringVar(value="标准")
        self.guard = tk.BooleanVar(value=True)
        self.native = tk.BooleanVar(value=True)
        self.runner = tk.StringVar()
        self.status = tk.StringVar(value="就绪")
        self.hint = tk.StringVar()

        self._build()
        self._update_hint()
        self.after(150, self._poll_drop)

    # ---------------- UI ----------------
    def _build(self) -> None:
        s = ttk.Style()
        s.configure("Accent.TButton", foreground="#ffffff", background=ACCENT,
                    bordercolor=ACCENT, padding=(16, 10),
                    font=("TkDefaultFont", 11, "bold"))
        s.map("Accent.TButton", background=[("active", "#0C447C"),
                                            ("disabled", "#9aa0a6")])
        s.configure("Drop.TLabel", foreground=ACCENT,
                    font=("TkDefaultFont", 13))
        s.configure("Hint.TLabel", foreground="#666666")

        root = ttk.Frame(self, padding=18)
        root.pack(fill="both", expand=True)

        drop = ttk.LabelFrame(root, text=" 拖放区 ", padding=14)
        drop.pack(fill="x")
        inner = ttk.Frame(drop, height=80)
        inner.pack(fill="x")
        inner.pack_propagate(False)
        ttk.Label(inner,
                  text="把要保护的程序包（文件或整个文件夹）拖进窗口任意位置",
                  style="Drop.TLabel", anchor="center", justify="center").pack(
                      expand=True, fill="both")
        pick = ttk.Frame(drop)
        pick.pack(fill="x", pady=(8, 0))
        ttk.Button(pick, text="选择文件",
                   command=lambda: self._pick(False)).pack(side="left")
        ttk.Button(pick, text="选择文件夹",
                   command=lambda: self._pick(True)).pack(side="left", padx=6)
        ttk.Label(pick, textvariable=self.src, style="Hint.TLabel",
                  wraplength=600).pack(side="left", padx=10)

        pkg = ttk.LabelFrame(root, text=" 程序包 ", padding=12)
        pkg.pack(fill="x", pady=(14, 0))
        prow = ttk.Frame(pkg)
        prow.pack(fill="x")
        ttk.Label(prow, text="入口程序：").pack(side="left")
        self.entry_combo = ttk.Combobox(
            prow, textvariable=self.entry, width=46, state="readonly", values=[])
        self.entry_combo.pack(side="left")
        ttk.Button(prow, text="重新扫描",
                   command=self._refresh_entries).pack(side="left", padx=6)
        ttk.Checkbutton(prow, text="排除 .git / 缓存 / 日志 / .env",
                        variable=self.exclude_defaults,
                        command=self._update_pkg_info).pack(side="left", padx=(12, 0))
        ttk.Label(pkg, textvariable=self.pkg_info, style="Hint.TLabel",
                  wraplength=840).pack(fill="x", pady=(8, 0))

        opts = ttk.LabelFrame(root, text=" 陷阱设置（正常使用零打扰） ", padding=12)
        opts.pack(fill="x", pady=(14, 0))
        row = ttk.Frame(opts)
        row.pack(fill="x")
        ttk.Label(row, text="假包数量：").pack(side="left")
        ttk.Spinbox(row, from_=0, to=64, width=5, textvariable=self.decoys,
                    command=self._update_hint).pack(side="left")
        ttk.Label(row, text=" 个   诱饵源码：", style="Hint.TLabel").pack(side="left")
        ttk.Spinbox(row, from_=0, to=64, width=5, textvariable=self.farm_mb,
                    command=self._update_hint).pack(side="left")
        ttk.Label(row, text=" MB   陷阱强度：", style="Hint.TLabel").pack(side="left")
        ttk.Combobox(row, textvariable=self.trap_profile, width=6,
                     state="readonly", values=["标准", "激进"],
                     ).pack(side="left")

        row2 = ttk.Frame(opts)
        row2.pack(fill="x", pady=(10, 0))
        ttk.Checkbutton(row2, text="反调试 / 分析环境诱饵",
                        variable=self.guard).pack(side="left")
        ttk.Checkbutton(row2, text="每次构建独立原生启动器（推荐）",
                        variable=self.native).pack(side="left", padx=(12, 0))
        ttk.Label(row2, text="   通用启动器：",
                  style="Hint.TLabel").pack(side="left")
        ttk.Entry(row2, textvariable=self.runner, width=40).pack(side="left")
        ttk.Button(row2, text="选择",
                   command=self._pick_runner).pack(side="left", padx=4)
        ttk.Button(row2, text="构建启动器",
                   command=self._build_runner).pack(side="left")

        ttk.Label(opts, textvariable=self.hint, style="Hint.TLabel",
                  wraplength=820).pack(fill="x", pady=(8, 0))

        out = ttk.Frame(root)
        out.pack(fill="x", pady=(14, 0))
        ttk.Label(out, text="输出 exe：").pack(side="left")
        ttk.Entry(out, textvariable=self.out, width=68).pack(side="left")

        bar = ttk.Frame(root)
        bar.pack(fill="x", pady=(16, 0))
        self.go_btn = ttk.Button(bar, text="生成加固 exe",
                                 style="Accent.TButton", command=self._go)
        self.go_btn.pack(side="left")
        ttk.Button(bar, text="打开输出目录",
                   command=self._open_out).pack(side="left", padx=10)
        ttk.Label(bar, text="分发只需这个 exe：双击直接运行，不弹口令",
                  style="Hint.TLabel").pack(side="left")

        box = ttk.LabelFrame(root, text=" 运行日志 ", padding=8)
        box.pack(fill="both", expand=True, pady=(14, 0))
        self.logw = scrolledtext.ScrolledText(
            box, height=8, wrap="word", font=("Consolas", 9), state="disabled")
        self.logw.pack(fill="both", expand=True)

        statusbar = ttk.Frame(self, padding=(14, 6))
        statusbar.pack(fill="x", side="bottom")
        ttk.Label(statusbar, textvariable=self.status,
                  style="Hint.TLabel").pack(side="left")
        ttk.Label(statusbar,
                  text="只放大逆向成本，不联网、不破坏主机、不碰第三方",
                  style="Hint.TLabel").pack(side="right")

    # ---------------- 交互 ----------------
    def _pick(self, folder: bool) -> None:
        if folder:
            p = filedialog.askdirectory(title="选择程序包文件夹")
        else:
            p = filedialog.askopenfilename(title="选择程序包文件")
        if p:
            self._set_src(Path(p))

    def _set_src(self, path: Path) -> None:
        self.src.set(str(path))
        self.out.set(str(path.with_name(path.name + "_protected.exe")))
        self.status.set(f"已载入：{path.name}")
        self.entry.set("")
        self._refresh_entries()

    def _excludes(self) -> list[str]:
        if rpk is None:
            return []
        return list(rpk.DEFAULT_EXCLUDES) if self.exclude_defaults.get() else []

    def _refresh_entries(self) -> None:
        raw = self.src.get()
        if not raw or rpk is None:
            return
        path = Path(raw)
        if not path.exists():
            return
        if path.is_file():
            self.entry_combo.configure(values=[path.name], state="disabled")
            self.entry.set(path.name)
            self._update_pkg_info()
            return
        try:
            candidates = rpk.candidate_entries(path)
        except Exception as exc:
            candidates = []
            self._log(f"扫描入口失败：{exc}")
        self.entry_combo.configure(values=candidates, state="readonly")
        preferred = ""
        for suffix in rpk.EXEC_SUFFIXES:
            matches = [c for c in candidates
                       if "/" not in c and c.lower().endswith(suffix)]
            if len(matches) == 1:
                preferred = matches[0]
                break
        current = self.entry.get()
        if len(candidates) == 1:
            self.entry.set(candidates[0])
        elif preferred:
            self.entry.set(preferred)
        elif current in candidates:
            self.entry.set(current)
        else:
            self.entry.set("")
        if not candidates:
            self.status.set("未找到入口程序，请检查文件夹")
        elif len(candidates) > 1 and not self.entry.get():
            self.status.set(f"检测到 {len(candidates)} 个入口，请在「入口程序」中选择")
        else:
            self.status.set(f"入口：{self.entry.get()}")
        self._update_pkg_info()

    def _update_pkg_info(self) -> None:
        raw = self.src.get()
        if not raw or rpk is None:
            self.pkg_info.set("")
            return
        path = Path(raw)
        try:
            info = rpk.scan_package(path, self._excludes(), self.out.get() or None)
        except Exception as exc:
            self.pkg_info.set(f"扫描失败：{exc}")
            return
        size_mb = info["bytes"] / 1048576
        entry = self.entry.get()
        prefix = (f"将打包 {info['files']} 个文件 / {size_mb:.1f} MB；"
                  f"排除 {info['excluded']} 项")
        if path.is_dir() and not entry:
            self.pkg_info.set(f"{prefix}；请选择入口程序")
        else:
            self.pkg_info.set(f"{prefix}；入口：{entry or path.name}")

    def _pick_runner(self) -> None:
        p = filedialog.askopenfilename(
            title="选择通用启动器 RTPK_Runner.exe",
            filetypes=[("启动器", "*.exe"), ("全部", "*.*")])
        if p:
            self.runner.set(p)

    def _build_runner(self) -> None:
        if self.busy:
            return
        self.busy = True
        self.go_btn.configure(state="disabled")
        self.status.set("正在构建通用启动器（首次约 30 秒）…")
        self._log("正在构建通用启动器，请稍候…")

        def finish(rc: int, err: str) -> None:
            self.busy = False
            self.go_btn.configure(state="normal")
            target = Path(__file__).resolve().parent / "dist" / "RTPK_Runner.exe"
            if rc == 0 and target.is_file():
                self.runner.set(str(target))
                self._log(f"启动器就绪：{target}")
                self.status.set("启动器就绪")
            else:
                self._log(f"构建失败（{rc}）：{err}")
                self.status.set("启动器构建失败")

        def worker() -> None:
            try:
                import build_runner
                rc = build_runner.main()
                self.after(0, lambda: finish(rc, ""))
            except Exception as exc:
                self.after(0, lambda: finish(-1, str(exc)))

        threading.Thread(target=worker, daemon=True).start()

    def _open_out(self) -> None:
        raw = self.out.get()
        if not raw:
            messagebox.showinfo(APP_TITLE, "还没有生成加固 exe")
            return
        target = Path(raw).parent
        if target.exists():
            _open_dir(target)
        else:
            messagebox.showinfo(APP_TITLE, f"输出目录不存在：{target}")

    def _update_hint(self) -> None:
        profile = self.trap_profile.get() or "标准"
        try:
            decoys = int(self.decoys.get())
            farm_mb = int(self.farm_mb.get())
        except ValueError:
            decoys, farm_mb = 12, 8
        mem, time_cost, _ = (rpk.TRAP_PROFILES.get(profile)
                             if rpk else (384 * 1024, 3, 2))
        per_pack = mem / 1048576.0 * time_cost * 1.2
        total = per_pack * (decoys + 1 + (2 if farm_mb >= 4 else (1 if farm_mb else 0)))
        self.hint.set(
            f"正常启动约 <1 秒、无口令；每个假包宣称 Argon2 {mem // 1024} MiB × {time_cost}，"
            f"估算单包 ≈ {per_pack:.1f} 秒、全量 ≈ {total:.0f} 秒（诱饵源码另计 token）。")

    def _go(self) -> None:
        if rpk is None:
            messagebox.showerror(APP_TITLE, "缺少 runtime_pack.py，请检查安装目录")
            return
        raw = self.src.get()
        if not raw or not Path(raw).exists():
            messagebox.showwarning(APP_TITLE, "请先选择程序包")
            return
        native = self.native.get()
        runner = self.runner.get()
        if not native and (not runner or not Path(runner).is_file()):
            messagebox.showwarning(APP_TITLE,
                                   "请先选择或构建通用启动器 RTPK_Runner.exe")
            return
        try:
            decoys = max(0, min(64, int(self.decoys.get())))
            farm_mb = max(0, min(64, int(self.farm_mb.get())))
        except ValueError:
            messagebox.showwarning(APP_TITLE, "假包数量 / 诱饵体积必须是整数")
            return

        src = Path(raw)
        out = Path(self.out.get() or str(src.with_name(src.name + "_protected.exe")))
        profile = self.trap_profile.get() or "标准"
        guard = self.guard.get()
        excludes = self._excludes()
        entry = self.entry.get().strip()
        if src.is_dir() and not entry:
            messagebox.showwarning(APP_TITLE, "请先在「入口程序」中选择一个入口")
            return
        try:
            if entry:
                entry = rpk.validate_entry(src, entry)
        except rpk.RuntimePackError as exc:
            messagebox.showwarning(APP_TITLE, str(exc))
            return

        def job(progress, emit):
            emit("log", f"打包：{src.name}｜入口 {entry or src.name}｜"
                        f"假包 {decoys}｜诱饵 {farm_mb}MB｜"
                        f"强度 {profile}｜反探测 {'开' if guard else '关'}｜"
                        f"{'原生多态' if native else '通用启动器'}")
            if native:
                stats = rpk.build_native_exe(
                    src, out, entry=entry or None, decoys=decoys,
                    farm_mb=farm_mb, trap_profile=profile, guard=guard,
                    excludes=excludes, cb=progress)
                emit("log", f"完成：{out}（{out.stat().st_size:,} 字节）")
            else:
                blob, stats = rpk.build_container(
                    src, entry=entry or None, decoys=decoys, farm_mb=farm_mb,
                    trap_profile=profile, guard=guard,
                    excludes=excludes, out_path=out, cb=progress)
                emit("log", f"容器 {len(blob):,} 字节，正在写入启动器…")
                rpk.embed(runner, blob, out)
                emit("log", f"完成：{out}（{out.stat().st_size:,} 字节）")
            emit("log", f"打包文件 {stats['included_files']} 个 / "
                        f"{stats['included_bytes']:,} 字节；"
                        f"排除 {stats['excluded_items']} 项")
            emit("log", f"真包分片 {stats['core_parts']}｜假包 {stats['decoys']}｜"
                        f"农场包 {stats['farm_packs']}｜"
                        f"单包尝试 ≈ {stats['attack_seconds_per_pack']:.1f}s｜"
                        f"全量 ≈ {stats['attack_seconds_full_pass']:.0f}s")
            emit("log", "双击直接运行，无口令；调试器 / AI Agent 才会进入陷阱。")
            return f"已生成：{out}"

        self._run_async(job)

    # ---------------- 后台与工具 ----------------
    def _log(self, text: str) -> None:
        self.logw.configure(state="normal")
        self.logw.insert("end", text + "\n")
        self.logw.see("end")
        self.logw.configure(state="disabled")

    def _run_async(self, job) -> None:
        if self.busy:
            return
        self.busy = True
        self.go_btn.configure(state="disabled")

        def emit(kind, *args):
            self.q.put((kind, args))

        def progress(done, total, msg):
            emit("progress", done, total, msg)

        def worker() -> None:
            try:
                result = job(progress, emit)
                emit("done", result)
            except Exception as exc:
                emit("error", str(exc), traceback.format_exc())

        threading.Thread(target=worker, daemon=True).start()
        self.after(80, self._poll)

    def _poll(self) -> None:
        try:
            while True:
                kind, args = self.q.get_nowait()
                if kind == "log":
                    self._log(args[0])
                elif kind == "progress":
                    done, total, msg = args
                    self.status.set(f"{msg} ({done}/{total})")
                elif kind == "done":
                    self._log(args[0])
                    self.status.set("完成")
                    self.busy = False
                    self.go_btn.configure(state="normal")
                elif kind == "error":
                    self._log(f"错误：{args[0]}")
                    self.status.set("失败")
                    self.busy = False
                    self.go_btn.configure(state="normal")
                    messagebox.showerror(APP_TITLE, args[0])
        except queue.Empty:
            pass
        if self.busy:
            self.after(80, self._poll)

    def _poll_drop(self) -> None:
        drop = getattr(self, "_drop", None)
        if drop:
            drop.refresh()
            drop.consume()
        self.after(120, self._poll_drop)

    def _on_drop(self, paths: list[str]) -> None:
        paths = [p for p in paths if p and Path(p).exists()]
        if not paths:
            return
        if len(paths) > 1:
            self._log(f"拖入 {len(paths)} 项，仅处理第一项：{paths[0]}")
        self._set_src(Path(paths[0]))


def main() -> None:
    app = App()
    try:
        from drop_target import NativeDrop
        app._drop = NativeDrop(app, app._on_drop)
        if not app._drop.ok:
            app._log(f"拖放不可用（{app._drop.error}）；请用选择按钮")
    except Exception as exc:
        app._log(f"拖放初始化失败：{exc}")
    app.mainloop()


if __name__ == "__main__":
    main()
