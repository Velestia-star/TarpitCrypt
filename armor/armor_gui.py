#!/usr/bin/env python3
"""TarpitCrypt Armor · 极简单页 GUI。

唯一功能：把程序包加密成「双击即可运行」的单文件 exe。

流程：拖入程序包 → 填口令 → 选启动器 → 生成加密 exe。
运行端：双击 exe → 口令框 → 内存解密 → 临时目录运行 → 退出擦除。

依赖：Python 3.11+ / tkinter / argon2-cffi / cryptography / PyInstaller（仅构建启动器时）。
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

APP_TITLE = "TarpitCrypt Armor · 加密后直接运行"
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
        self.geometry("840x640")
        self.minsize(740, 560)
        try:
            ttk.Style().theme_use("clam")
        except tk.TclError:
            pass
        font.nametofont("TkDefaultFont").configure(size=10)

        self.q: queue.Queue = queue.Queue()
        self.busy = False
        self.src = tk.StringVar()
        self.out = tk.StringVar()
        self.pw = tk.StringVar()
        self.pw2 = tk.StringVar()
        self.profile = tk.StringVar(value="中")
        self.nopass = tk.BooleanVar(value=False)
        self.runner = tk.StringVar()
        self.status = tk.StringVar(value="就绪")

        self._build()
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

        # 拖放区
        drop = ttk.LabelFrame(root, text=" 拖放区 ", padding=14)
        drop.pack(fill="x")
        inner = ttk.Frame(drop, height=86)
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
                  wraplength=580).pack(side="left", padx=10)

        # 加密选项
        opts = ttk.LabelFrame(root, text=" 加密选项 ", padding=12)
        opts.pack(fill="x", pady=(14, 0))
        row = ttk.Frame(opts); row.pack(fill="x")
        ttk.Label(row, text="运行口令：").pack(side="left")
        self.pw_entry = ttk.Entry(row, textvariable=self.pw, show="*", width=24)
        self.pw_entry.pack(side="left")
        ttk.Label(row, text="  确认：").pack(side="left")
        self.pw2_entry = ttk.Entry(row, textvariable=self.pw2, show="*", width=24)
        self.pw2_entry.pack(side="left")
        ttk.Label(row, text="  强度：", style="Hint.TLabel").pack(side="left")
        ttk.Combobox(row, textvariable=self.profile, width=6, state="readonly",
                     values=["轻", "中", "狠"]).pack(side="left")

        row2 = ttk.Frame(opts); row2.pack(fill="x", pady=(10, 0))
        ttk.Checkbutton(row2, text="免密（仅混淆，保护极弱）",
                        variable=self.nopass,
                        command=self._toggle_nopass).pack(side="left")
        ttk.Label(row2, text="   通用启动器：",
                  style="Hint.TLabel").pack(side="left")
        ttk.Entry(row2, textvariable=self.runner, width=32).pack(side="left")
        ttk.Button(row2, text="选择",
                   command=self._pick_runner).pack(side="left", padx=4)
        ttk.Button(row2, text="构建启动器",
                   command=self._build_runner).pack(side="left")

        # 输出
        out = ttk.Frame(root); out.pack(fill="x", pady=(14, 0))
        ttk.Label(out, text="输出 exe：").pack(side="left")
        ttk.Entry(out, textvariable=self.out, width=64).pack(side="left")

        # 主按钮
        bar = ttk.Frame(root); bar.pack(fill="x", pady=(16, 0))
        self.go_btn = ttk.Button(bar, text="生成加密 exe",
                                 style="Accent.TButton", command=self._go)
        self.go_btn.pack(side="left")
        ttk.Button(bar, text="打开输出目录",
                   command=self._open_out).pack(side="left", padx=10)
        ttk.Label(bar, text="分发只需这个 exe；双击输口令即可运行原程序",
                  style="Hint.TLabel").pack(side="left")

        # 日志
        box = ttk.LabelFrame(root, text=" 运行日志 ", padding=8)
        box.pack(fill="both", expand=True, pady=(14, 0))
        self.logw = scrolledtext.ScrolledText(
            box, height=8, wrap="word", font=("Consolas", 9), state="disabled")
        self.logw.pack(fill="both", expand=True)

        # 状态栏
        statusbar = ttk.Frame(self, padding=(14, 6))
        statusbar.pack(fill="x", side="bottom")
        ttk.Label(statusbar, textvariable=self.status,
                  style="Hint.TLabel").pack(side="left")
        ttk.Label(statusbar,
                  text="明文运行时进内存，无法绝对防 dump；不做免杀 / 注入",
                  style="Hint.TLabel").pack(side="right")

    # ---------------- 交互 ----------------
    def _toggle_nopass(self) -> None:
        state = "disabled" if self.nopass.get() else "normal"
        self.pw_entry.configure(state=state)
        self.pw2_entry.configure(state=state)
        self.status.set("免密模式：密钥内嵌，仅混淆，保护极弱"
                        if self.nopass.get() else "就绪")

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
            messagebox.showinfo(APP_TITLE, "还没有生成加密 exe")
            return
        p = Path(raw)
        target = p.parent
        if target.exists():
            _open_dir(target)
        else:
            messagebox.showinfo(APP_TITLE, f"输出目录不存在：{target}")

    def _go(self) -> None:
        if rpk is None:
            messagebox.showerror(APP_TITLE, "缺少 runtime_pack.py，请检查安装目录")
            return
        raw = self.src.get()
        if not raw or not Path(raw).exists():
            messagebox.showwarning(APP_TITLE, "请先选择程序包")
            return
        runner = self.runner.get()
        if not runner or not Path(runner).is_file():
            messagebox.showwarning(APP_TITLE,
                                   "请先选择或构建通用启动器 RTPK_Runner.exe")
            return

        nopass = self.nopass.get()
        pw = "" if nopass else self.pw.get()
        if not nopass:
            if not pw or pw != self.pw2.get():
                messagebox.showwarning(APP_TITLE, "两次运行口令不一致或为空")
                return
            ok, hint = rpk.check_password(pw)
            if not ok and not messagebox.askyesno(
                    APP_TITLE, f"口令偏弱：{hint}\n仍要继续？"):
                return

        src = Path(raw)
        out = Path(self.out.get() or str(src.with_name(src.name + "_protected.exe")))
        profile = self.profile.get() or "中"

        def job(progress, emit):
            emit("log", f"加密：{src.name} / 强度 {profile} / "
                        f"{'免密（弱）' if nopass else '口令保护'}")
            blob = rpk.build_pack(src, pw or None, profile=profile,
                                  no_password=nopass, cb=progress)
            rpk.embed(runner, blob, out)
            emit("log", f"完成：{out}（{out.stat().st_size:,} 字节）")
            emit("log", "分发只需这个 exe。双击输口令 → 解密运行 → 退出擦除。")
            emit("log", "局限：运行时明文在内存中，本工具不防调试器 dump / 内存取证。")
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
