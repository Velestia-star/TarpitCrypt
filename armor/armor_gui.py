#!/usr/bin/env python3
"""TarpitCrypt Armor 图形界面。

把程序包（文件或整个文件夹）拖进窗口即可完成加固；还原同样拖入即可。
拖放走 Windows 原生 WM_DROPFILES，不需要 tkinterdnd2 之类的第三方库；
万一子类化失败，界面会自动降级为「选择文件 / 选择文件夹」按钮。

依赖：Python 3.11+、argon2-cffi、cryptography、tkinter（标准库）。
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
from ctypes import wintypes
from pathlib import Path
from tkinter import filedialog, font, messagebox, scrolledtext, ttk

from armor_metrics import Metrics, Stopwatch

APP_TITLE = "TarpitCrypt Armor · 程序包加固"
ACCENT = "#185FA5"


def _open_path(path: Path) -> None:
    """跨平台打开目录。Windows 用资源管理器，其余交给系统默认程序。"""
    if os.name == "nt":
        os.startfile(str(path))  # noqa: S606 - 仅打开本工具生成的目录
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


def _enable_dpi() -> None:
    """150% 缩放下别让界面糊掉。"""
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(2)
    except Exception:
        try:
            ctypes.windll.user32.SetProcessDPIAware()
        except Exception:
            pass


class NativeDrop:
    """给 Tk 顶层窗口挂上系统拖放（WM_DROPFILES）。"""

    WM_DROPFILES = 0x0233
    GWL_WNDPROC = -4

    def __init__(self, root: tk.Tk, callback) -> None:
        self.ok = False
        self._root = root
        self._callback = callback
        if os.name != "nt":
            return
        try:
            self._user32 = ctypes.windll.user32
            self._shell32 = ctypes.windll.shell32
            LRESULT = ctypes.c_ssize_t
            self._WNDPROC = ctypes.WINFUNCTYPE(
                LRESULT, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
            )
            self._shell32.DragQueryFileW.argtypes = [
                wintypes.HDROP, wintypes.UINT, wintypes.LPWSTR, wintypes.UINT
            ]
            self._shell32.DragQueryFileW.restype = wintypes.UINT
            self._shell32.DragAcceptFiles.argtypes = [wintypes.HWND, wintypes.BOOL]
            self._shell32.DragFinish.argtypes = [wintypes.HDROP]
            self._user32.CallWindowProcW.argtypes = [
                ctypes.c_void_p, wintypes.HWND, wintypes.UINT,
                wintypes.WPARAM, wintypes.LPARAM,
            ]
            self._user32.CallWindowProcW.restype = LRESULT
            setter = getattr(self._user32, "SetWindowLongPtrW", None) or self._user32.SetWindowLongW
            setter.argtypes = [wintypes.HWND, ctypes.c_int, self._WNDPROC]
            setter.restype = ctypes.c_void_p

            root.update_idletasks()
            hwnd = int(root.frame(), 16)
            proc = self._WNDPROC(self._wndproc)
            self._proc_ref = proc  # 防 GC
            self._old = setter(hwnd, self.GWL_WNDPROC, proc)
            if not self._old:
                raise OSError("无法替换窗口过程")
            self._shell32.DragAcceptFiles(hwnd, True)
            self.ok = True
        except Exception:
            self.ok = False

    def _paths(self, lparam: int) -> list[str]:
        hdrop = ctypes.c_void_p(lparam)
        count = self._shell32.DragQueryFileW(hdrop, 0xFFFFFFFF, None, 0)
        result = []
        buf = ctypes.create_unicode_buffer(4096)
        for i in range(count):
            self._shell32.DragQueryFileW(hdrop, i, buf, len(buf))
            if buf.value:
                result.append(buf.value)
        self._shell32.DragFinish(hdrop)
        return result

    def _wndproc(self, hwnd, msg, wparam, lparam):
        if msg == self.WM_DROPFILES:
            try:
                paths = self._paths(lparam)
            except Exception:
                paths = []
            if paths:
                self._root.after(0, self._callback, paths)
            return 0
        return self._user32.CallWindowProcW(self._old, hwnd, msg, wparam, lparam)


class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.geometry("960x720")
        self.minsize(820, 600)
        try:
            ttk.Style().theme_use("clam")
        except tk.TclError:
            pass
        default = font.nametofont("TkDefaultFont")
        default.configure(size=10)

        self.q: queue.Queue = queue.Queue()
        self.busy = False
        self.src = tk.StringVar()
        self.armored = tk.StringVar()
        self.enc_pw = tk.StringVar()
        self.enc_pw2 = tk.StringVar()
        self.dec_pw = tk.StringVar()
        self.layers = tk.IntVar(value=4)
        self.profile = tk.StringVar()
        self.out_armored = tk.StringVar()
        self.out_dir = tk.StringVar()
        self.sidecar_on = tk.BooleanVar(value=True)
        self.kit_style = tk.StringVar()
        self.kit_src = tk.StringVar()
        self.kit_out = tk.StringVar()
        self.kit_root: Path | None = None
        self.status = tk.StringVar(value="就绪")
        self.metrics = Metrics()
        self.poison = tk.StringVar()
        self.parallel = tk.BooleanVar(value=False)

        import armor_core as core
        import decoy_kit as dk
        self.title(f"{APP_TITLE}  v{core.__version__}")
        self.kit_style.set(dk.DEFAULT_STYLE)
        self.poison.set(dk.DEFAULT_POISON)
        # 风格在「加固」页和「伴生诱饵」页共用一个变量，改动时同步刷新输出路径。
        self.kit_style.trace_add("write", lambda *_args: self._refresh_kit_out())
        self._build()
        self._drop = NativeDrop(self, self._on_drop)
        if not self._drop.ok:
            self.status.set("拖放不可用，请用「选择文件 / 选择文件夹」按钮")

    # ------------------------------------------------------------------
    # 界面
    # ------------------------------------------------------------------
    def _build(self) -> None:
        style = ttk.Style()
        style.configure("Accent.TButton", foreground="#ffffff", background=ACCENT,
                        bordercolor=ACCENT, padding=(14, 8))
        style.map("Accent.TButton", background=[("active", "#0C447C"), ("disabled", "#9aa0a6")])
        style.configure("Drop.TLabel", foreground=ACCENT, font=("TkDefaultFont", 12))
        style.configure("Hint.TLabel", foreground="#666666")

        root = ttk.Frame(self, padding=14)
        root.pack(fill="both", expand=True)
        self.nb = ttk.Notebook(root)
        self.nb.pack(fill="both", expand=True)
        self.nb.add(self._tab_armor(), text="  加固  ")
        self.nb.add(self._tab_restore(), text="  还原  ")
        self.nb.add(self._tab_kit(), text="  伴生诱饵  ")
        self.nb.add(self._tab_report(), text="  运行报告  ")
        self.nb.add(self._tab_about(), text="  说明  ")

        bar = ttk.Frame(root)
        bar.pack(fill="x", pady=(10, 0))
        ttk.Label(bar, textvariable=self.status, style="Hint.TLabel").pack(side="left")
        ttk.Label(bar, text="仅用于加固你自己拥有的程序包", style="Hint.TLabel").pack(side="right")

    def _drop_zone(self, parent, text: str) -> ttk.Frame:
        box = ttk.LabelFrame(parent, text=" 拖放区 ", padding=12)
        box.pack(fill="x", pady=(0, 10))
        inner = ttk.Frame(box, height=76)
        inner.pack(fill="x")
        inner.pack_propagate(False)
        ttk.Label(inner, text=text, style="Drop.TLabel", anchor="center",
                  justify="center").pack(expand=True, fill="both")
        return box

    def _log_box(self, parent) -> scrolledtext.ScrolledText:
        box = ttk.LabelFrame(parent, text=" 运行日志 ", padding=6)
        box.pack(fill="both", expand=True, pady=(8, 0))
        widget = scrolledtext.ScrolledText(box, height=9, wrap="word",
                                           font=("Consolas", 9), state="disabled")
        widget.pack(fill="both", expand=True)
        return widget

    def _tab_armor(self) -> ttk.Frame:
        f = ttk.Frame(self.nb, padding=14)
        self._drop_zone(f, "把程序包（文件或整个文件夹）拖进窗口任意位置")

        pick = ttk.Frame(f)
        pick.pack(fill="x")
        ttk.Button(pick, text="选择文件", command=lambda: self._pick(False)).pack(side="left")
        ttk.Button(pick, text="选择文件夹", command=lambda: self._pick(True)).pack(side="left", padx=6)
        ttk.Label(pick, textvariable=self.src, style="Hint.TLabel",
                  wraplength=620).pack(side="left", padx=10)

        form = ttk.LabelFrame(f, text=" 加固参数 ", padding=12)
        form.pack(fill="x", pady=12)
        form.columnconfigure(1, weight=1)

        ttk.Label(form, text="主口令").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=self.enc_pw, show="•", width=38).grid(
            row=0, column=1, sticky="we", pady=4)
        ttk.Label(form, text="确认口令").grid(row=1, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=self.enc_pw2, show="•", width=38).grid(
            row=1, column=1, sticky="we", pady=4)
        ttk.Label(form, text="诱饵层数").grid(row=2, column=0, sticky="w", pady=4)
        row2 = ttk.Frame(form)
        row2.grid(row=2, column=1, sticky="w", pady=4)
        ttk.Spinbox(row2, from_=2, to=8, textvariable=self.layers, width=6).pack(side="left")
        ttk.Label(row2, text="  层越多，逆向方要验证的分支越多",
                  style="Hint.TLabel").pack(side="left")
        ttk.Label(form, text="加固强度").grid(row=3, column=0, sticky="w", pady=4)
        self.profile_cb = ttk.Combobox(form, textvariable=self.profile, state="readonly", width=24)
        self.profile_cb.grid(row=3, column=1, sticky="w", pady=4)
        import armor_core as core
        import decoy_kit as dk
        profiles = list(core.PROFILES)
        self.profile_cb["values"] = profiles
        self.profile.set(profiles[0])
        ttk.Label(form, text="输出到").grid(row=4, column=0, sticky="w", pady=4)
        outrow = ttk.Frame(form)
        outrow.grid(row=4, column=1, sticky="we", pady=4)
        ttk.Label(outrow, textvariable=self.out_armored, style="Hint.TLabel",
                  wraplength=520).pack(side="left", fill="x", expand=True)
        ttk.Button(outrow, text="另存为", command=self._pick_output).pack(side="right")

        ttk.Label(form, text="伴生诱饵").grid(row=5, column=0, sticky="w", pady=4)
        side = ttk.Frame(form)
        side.grid(row=5, column=1, sticky="w", pady=4)
        ttk.Checkbutton(side, text="同时生成假规格 / 假源码（原目录一个字节都不改）",
                        variable=self.sidecar_on).pack(side="left")
        ttk.Combobox(side, textvariable=self.kit_style, state="readonly", width=14,
                     values=list(dk.STYLES)).pack(side="left", padx=10)

        ttk.Label(form, text="投毒侧重").grid(row=6, column=0, sticky="w", pady=4)
        prow = ttk.Frame(form)
        prow.grid(row=6, column=1, sticky="w", pady=4)
        ttk.Combobox(prow, textvariable=self.poison, state="readonly", width=16,
                     values=list(dk.POISON_PROFILES)).pack(side="left")
        ttk.Label(prow, text="  针对「先读文档 / 先跑脚本」的逆向习惯调整线索组合",
                  style="Hint.TLabel").pack(side="left", padx=8)

        actions = ttk.Frame(f)
        actions.pack(fill="x")
        self.armor_btn = ttk.Button(actions, text="开始加固", style="Accent.TButton",
                                    command=self._do_armor)
        self.armor_btn.pack(side="left")
        self.pb = ttk.Progressbar(actions, mode="determinate", length=260)
        self.pb.pack(side="left", padx=14)

        self.enc_log = self._log_box(f)
        return f

    def _tab_restore(self) -> ttk.Frame:
        f = ttk.Frame(self.nb, padding=14)
        self._drop_zone(f, "把 .armored 容器拖进窗口任意位置")

        pick = ttk.Frame(f)
        pick.pack(fill="x")
        ttk.Button(pick, text="选择容器", command=self._pick_armored).pack(side="left")
        ttk.Label(pick, textvariable=self.armored, style="Hint.TLabel",
                  wraplength=640).pack(side="left", padx=10)
        ttk.Button(pick, text="查看摘要", command=self._do_inspect).pack(side="right")

        form = ttk.LabelFrame(f, text=" 还原参数 ", padding=12)
        form.pack(fill="x", pady=12)
        form.columnconfigure(1, weight=1)
        ttk.Label(form, text="口令").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Entry(form, textvariable=self.dec_pw, show="•", width=38).grid(
            row=0, column=1, sticky="we", pady=4)
        ttk.Label(form, text="解压到").grid(row=1, column=0, sticky="w", pady=4)
        outrow = ttk.Frame(form)
        outrow.grid(row=1, column=1, sticky="we", pady=4)
        ttk.Label(outrow, textvariable=self.out_dir, style="Hint.TLabel",
                  wraplength=520).pack(side="left", fill="x", expand=True)
        ttk.Button(outrow, text="选择目录", command=self._pick_outdir).pack(side="right")

        actions = ttk.Frame(f)
        actions.pack(fill="x")
        self.restore_btn = ttk.Button(actions, text="还原", style="Accent.TButton",
                                      command=self._do_restore)
        self.restore_btn.pack(side="left")
        ttk.Checkbutton(actions, text="并行尝试各层", variable=self.parallel).pack(
            side="left", padx=10)
        ttk.Label(actions, text="  低内存档生效，最多 4 线程；还原结果不标注层号与真伪",
                  style="Hint.TLabel").pack(side="left")

        self.dec_log = self._log_box(f)
        return f

    def _tab_kit(self) -> ttk.Frame:
        import decoy_kit as dk

        f = ttk.Frame(self.nb, padding=14)
        self._drop_zone(f, "在本页把程序包拖进窗口，会直接作为伴生诱饵的源")

        pick = ttk.Frame(f)
        pick.pack(fill="x")
        ttk.Button(pick, text="选择文件", command=lambda: self._pick_kit_src(False)).pack(side="left")
        ttk.Button(pick, text="选择文件夹", command=lambda: self._pick_kit_src(True)).pack(side="left", padx=6)
        ttk.Button(pick, text="用加固页的源", command=self._use_armor_src).pack(side="left", padx=6)
        ttk.Label(pick, textvariable=self.kit_src, style="Hint.TLabel",
                  wraplength=430).pack(side="left", padx=10)

        form = ttk.LabelFrame(f, text=" 伴生参数 ", padding=12)
        form.pack(fill="x", pady=12)
        form.columnconfigure(1, weight=1)
        ttk.Label(form, text="拟态风格").grid(row=0, column=0, sticky="w", pady=4)
        ttk.Combobox(form, textvariable=self.kit_style, state="readonly", width=20,
                     values=list(dk.STYLES)).grid(
                         row=0, column=1, sticky="w", pady=4)
        ttk.Label(form, text="层数").grid(row=1, column=0, sticky="w", pady=4)
        lrow = ttk.Frame(form)
        lrow.grid(row=1, column=1, sticky="w", pady=4)
        ttk.Spinbox(lrow, from_=2, to=8, textvariable=self.layers, width=6).pack(side="left")
        ttk.Label(lrow, text="  与加固页共用；决定口令池里放几条调试口令",
                  style="Hint.TLabel").pack(side="left")
        ttk.Label(form, text="投毒侧重").grid(row=2, column=0, sticky="w", pady=4)
        ttk.Combobox(form, textvariable=self.poison, state="readonly", width=16,
                     values=list(dk.POISON_PROFILES)).grid(
                         row=2, column=1, sticky="w", pady=4)
        ttk.Label(form, text="输出到").grid(row=3, column=0, sticky="w", pady=4)
        ttk.Label(form, textvariable=self.kit_out, style="Hint.TLabel",
                  wraplength=560).grid(row=3, column=1, sticky="w", pady=4)

        actions = ttk.Frame(f)
        actions.pack(fill="x")
        self.kit_btn = ttk.Button(actions, text="生成伴生诱饵包", style="Accent.TButton",
                                  command=self._do_kit)
        self.kit_btn.pack(side="left")
        ttk.Button(actions, text="打开输出目录", command=self._open_kit_dir).pack(side="left", padx=8)
        ttk.Label(actions, text="  同名非空目录会拒绝覆盖",
                  style="Hint.TLabel").pack(side="left")

        self.kit_log = self._log_box(f)
        return f

    def _tab_report(self) -> ttk.Frame:
        f = ttk.Frame(self.nb, padding=14)
        ttk.Label(f, text="本地运行报告 · 只统计本机操作，不写进容器，不记录口令",
                  style="Hint.TLabel").pack(anchor="w", pady=(0, 8))
        self.report_text = scrolledtext.ScrolledText(
            f, wrap="word", font=("Consolas", 9), state="disabled", height=16)
        self.report_text.pack(fill="both", expand=True)

        bar = ttk.Frame(f)
        bar.pack(fill="x", pady=(8, 0))
        ttk.Button(bar, text="刷新", command=self._refresh_report).pack(side="left")
        ttk.Button(bar, text="导出 CSV", command=lambda: self._export_report("csv")).pack(
            side="left", padx=6)
        ttk.Button(bar, text="导出 Markdown",
                   command=lambda: self._export_report("md")).pack(side="left")
        ttk.Button(bar, text="清空记录", command=self._clear_report).pack(side="right")
        ttk.Label(bar, text="  token 为量级估算，不是真实 LLM 计费",
                  style="Hint.TLabel").pack(side="left", padx=10)
        self._refresh_report()
        return f

    def _refresh_report(self) -> None:
        self.report_text.configure(state="normal")
        self.report_text.delete("1.0", "end")
        summary = self.metrics.summary()
        self.report_text.insert("end", "汇总\n" + "=" * 56 + "\n")
        for key, value in summary.items():
            self.report_text.insert("end", f"  {key:<24} {value}\n")
        self.report_text.insert("end", "\n明细（只记文件名，不记口令）\n" + "=" * 56 + "\n")
        if not self.metrics.attempts:
            self.report_text.insert("end", "  本次会话还没有记录。做一次加固或还原即可。\n")
        for i, a in enumerate(self.metrics.attempts, 1):
            self.report_text.insert(
                "end",
                f"  {i:>2}. {a.ts}  {a.action:<8} {a.label[:28]:<28} "
                f"{'成功' if a.ok else '失败'}  层尝试 {a.layers_tried:<3} "
                f"耗时 {a.seconds:>7.3f}s  估算 {a.est_tokens:,} tokens\n"
                + (f"      {a.note}\n" if a.note else ""),
            )
        self.report_text.configure(state="disabled")

    def _export_report(self, kind: str) -> None:
        if kind == "csv":
            path = filedialog.asksaveasfilename(
                defaultextension=".csv", filetypes=[("CSV 表格", "*.csv")],
                initialfile="tarpit_report.csv")
            if path:
                self.metrics.to_csv(path)
        else:
            path = filedialog.asksaveasfilename(
                defaultextension=".md", filetypes=[("Markdown", "*.md")],
                initialfile="tarpit_report.md")
            if path:
                Path(path).write_text(self.metrics.to_markdown(), encoding="utf-8")
        if path:
            self.status.set(f"报告已导出：{path}")

    def _clear_report(self) -> None:
        self.metrics.attempts.clear()
        self._refresh_report()
        self.status.set("本地记录已清空")

    def _tab_about(self) -> ttk.Frame:
        f = ttk.Frame(self.nb, padding=16)
        text = scrolledtext.ScrolledText(f, wrap="word", font=("TkDefaultFont", 10),
                                         padx=14, pady=14)
        text.pack(fill="both", expand=True)
        text.insert("1.0", """TarpitCrypt Armor · 反 AI 逆向加固工具

【这个工具做什么】
把你想保护的程序包（单个文件或整个文件夹）拖进来，填一个主口令，
它会生成一个 .armored 容器。原程序一个字节都不改，完整保存在容器里；
"还原"页输入主口令即可逐字节取回。

【它怎么"惩罚"逆向者】
容器里有 N 个结构完全一致的层：一层装真包、若干层装自动生成的
高仿真诱饵包（README、配置、源码、清单齐全，语法正确、不执行任何东西），
还有若干层是任何线索口令都解不开的「死层」。三类的数量与位置每次随机，
读源码也推不出本容器的分布，所以「解开 N-1 层后剩下那层就是真层」
这条排除法不成立。

调试口令每个容器单独随机生成，源码里没有可复用的口令池；线索只写在
本容器的规格草稿和伴生资料里。诱饵包的文件树、命名、时间戳按种子随机，
所有层补齐到同一尺寸，按大小挑真层也没用。

容器不标记哪层是真的，还原成功也不报层号、不说是诱饵。容器里还有一份
明文"内部规格草稿"，故意写了互相矛盾的字段说明和几条调试口令——其中
部分真能解开诱饵层、部分是噪音、还有故意不公开的缺项。逆向 agent 会顺着
「找到线索 → 解开一层 → 分析内容 → 怀疑 → 再试」反复打转，
每一轮都在烧上下文和 token。

【为什么不给"这是诱饵"的提示】
任何明确的成功/失败标记都是给逆向方的免费剪枝信号，会让它少跑好几轮。
所以连界面都只显示内容摘要（SHA-256、条目数），不判断真伪。
用你自己的主口令，只会解开真层。

【边界】
只做信息误导。诱饵包是纯文本，不执行、不注入、不感染、不修改原程序，
也不接触第三方系统。请只加固你自己拥有的程序包。
本工具不是反调试、免杀或软件保护产品，也没有这些能力。

【伴生诱饵：污染「还没拿到容器」的那一轮】
AI 逆向通常先列目录、读 README 和规格文档。勾选加固页的「同时生成伴生诱饵」
（默认开启），会在原程序同级生成一组拟态的内部构建资料：三份互相矛盾的
规格文档、可运行但常量全错的解析脚本、口令池、假的层映射与构建日志。
文档之间还互相指定「以对方为准」，形成循环引用。

口令池直接抄本容器的草稿，其中几条能解开诱饵层 —— 这会让 agent 误判自己
已经得手，继续往下烧轮数；单独生成伴生包时则用一次性假口令。
原目录一个字节都不改，不需要时把伴生目录整份删掉
即可；同名非空目录会拒绝覆盖。「伴生诱饵」页可以单独生成，也能换拟态风格。

【参数怎么选】
层数 2~8：越多分支越多，加密和还原都会相应变慢（每层都要派生一次密钥）。
强度档只影响 Argon2id 的内存与迭代成本，默认「轻」适合秒级交互。
「投毒侧重」按目标 agent 的习惯换线索组合：先读文档的多给互相矛盾的
规格，先跑脚本的多给能 import 但常量全错的解析器；拿容器后会去扫字符串
的选「IOC蜜罐」，会把项目文档喂进 RAG/知识库的选「RAG投毒」，想要勾着
agent 与它主人持续投入、永不收敛的选「进度幻觉」，想要让 agent 把假结论
摄入自己的知识库/报告、污染其后续分析能力的选「认知污染」，会直接采信
capa/YARA/Semgrep/沙箱/CI 安全门这类机器可读产出的选「工具污染」，会
自动读项目指令文件（AGENTS.md / CLAUDE.md）的选「代理记忆」；不确定就选
「均衡」。
还原页的「并行尝试各层」只对低内存档生效（最多 4 线程），狠档会自动
退回串行，避免 Argon2 的峰值内存翻倍。

【运行报告】
「运行报告」页统计本机会话里的加固 / 还原次数、层尝试、耗时与 token
量级估算，可导出 CSV 或 Markdown。记录只在内存里，不写进容器，不记口令，
点「导出」才落盘。token 是按每轮固定开销的粗估，不是真实 LLM 计费；
真实 agent 实测方法见仓库 docs/AGENT_BENCHMARK.md。

【跨平台】
拖放用 Windows 原生消息；macOS / Linux 上拖放不可用，但「选择文件 /
选择文件夹」按钮全平台可用，功能一项不少。单个源文件默认上限 256 MiB，
大程序包可设环境变量 TARPIT_MAX_SOURCE_BYTES 放宽（全部内容会驻留内存）。

【文件格式】
MAGIC "TPARMOR3" / VERSION 3 / 层数 / 全局盐 / 明文规格草稿 /
N 条等长结构的层记录（KDF 参数 + 盐 + nonce + 密文）/ 尾部 SHA-256。
每层 AAD 绑定头部、层前缀和层偏移，改动字段、换序、互换密文都会失败。
v2 旧容器按同一布局读取，仍可用主口令还原；v1 文件格式未改动。

【命令行自测】
python selftest.py        验证加固→还原逐字节一致、诱饵与篡改行为
python probe_agent.py     模拟逆向 agent，三组工具调用轮数对照
python agent_eval.py --runs 5 --out report.md   多轮取样 + 评估报告

【依赖】
Python 3.11+ / argon2-cffi / cryptography / tkinter
pip install argon2-cffi cryptography
""")
        text.configure(state="disabled")
        return f

    # ------------------------------------------------------------------
    # 交互
    # ------------------------------------------------------------------
    def log(self, widget: scrolledtext.ScrolledText, msg: str) -> None:
        widget.configure(state="normal")
        widget.insert("end", msg + "\n")
        widget.see("end")
        widget.configure(state="disabled")

    def _on_drop(self, paths: list[str]) -> None:
        path = Path(paths[0])
        if self.nb.index(self.nb.select()) == 2 and path.suffix.lower() != ".armored":
            self._set_kit_src(path)
            return
        if path.suffix.lower() == ".armored":
            self.nb.select(1)
            self._set_armored(path)
        else:
            self.nb.select(0)
            self._set_src(path)
        if len(paths) > 1:
            self.status.set(f"只处理第一个：{path.name}（一次拖一个）")

    def _set_src(self, path: Path) -> None:
        self.src.set(str(path))
        self.out_armored.set(str(path.with_name(path.name + ".armored")))
        size = self._describe(path)
        self.status.set(f"已载入：{path.name} · {size}")
        self.log(self.enc_log, f"待加固：{path}")
        self.log(self.enc_log, f"  {size}；输出：{self.out_armored.get()}")

    def _set_armored(self, path: Path) -> None:
        self.armored.set(str(path))
        self.out_dir.set(str(path.with_name(path.stem + "_还原")))
        self.log(self.dec_log, f"待还原：{path}")
        self._do_inspect()

    @staticmethod
    def _describe(path: Path) -> str:
        if path.is_file():
            return f"单文件 {path.stat().st_size:,} 字节"
        files = [p for p in path.rglob("*") if p.is_file()]
        total = sum(p.stat().st_size for p in files)
        return f"目录 {len(files)} 个文件 / {total:,} 字节"

    def _pick(self, folder: bool) -> None:
        path = filedialog.askdirectory() if folder else filedialog.askopenfilename()
        if path:
            self._set_src(Path(path))

    def _pick_armored(self) -> None:
        path = filedialog.askopenfilename(filetypes=[("加固容器", "*.armored"), ("所有文件", "*.*")])
        if path:
            self._set_armored(Path(path))

    def _pick_output(self) -> None:
        path = filedialog.asksaveasfilename(defaultextension=".armored",
                                            filetypes=[("加固容器", "*.armored")])
        if path:
            self.out_armored.set(path)

    def _pick_outdir(self) -> None:
        path = filedialog.askdirectory()
        if path:
            self.out_dir.set(path)

    def _do_inspect(self) -> None:
        import armor_core as ac
        path = self.armored.get()
        if not path or not Path(path).is_file():
            return
        try:
            info = ac.inspect_armored(Path(path).read_bytes())
            self.log(self.dec_log,
                     f"只读摘要：版本 {info.version} / {info.layers} 层 / "
                     f"规格草稿 {info.note_size} 字节 / 容器 {info.total_size:,} 字节")
            self.log(self.dec_log, "  （摘要刻意不含任何层号或真伪信息）")
        except Exception as exc:
            self.log(self.dec_log, f"读取失败：{exc}")

    # ------------------------------------------------------------------
    # 伴生诱饵
    # ------------------------------------------------------------------
    def _refresh_kit_out(self) -> None:
        import decoy_kit as dk
        raw = self.kit_src.get()
        if not raw:
            self.kit_out.set("（先选程序包）")
            return
        path = Path(raw)
        suffix = dk.STYLES.get(self.kit_style.get(), dk.STYLES[dk.DEFAULT_STYLE])[0]
        self.kit_out.set(str(path.parent / (path.stem + suffix)))

    def _set_kit_src(self, path: Path) -> None:
        self.kit_src.set(str(path))
        self._refresh_kit_out()
        self.log(self.kit_log, f"伴生源：{path}")
        self.log(self.kit_log, "  生成物写在同级目录，原目录一个字节都不改。")

    def _pick_kit_src(self, folder: bool) -> None:
        path = filedialog.askdirectory() if folder else filedialog.askopenfilename()
        if path:
            self._set_kit_src(Path(path))

    def _use_armor_src(self) -> None:
        if self.src.get() and Path(self.src.get()).exists():
            self._set_kit_src(Path(self.src.get()))
        else:
            messagebox.showwarning(APP_TITLE, "加固页还没有载入程序包")

    def _open_kit_dir(self) -> None:
        raw = self.kit_out.get()
        target = Path(raw) if raw and not raw.startswith("（") else None
        if target and target.is_dir():
            try:
                _open_path(target)
            except Exception as exc:
                self.log(self.kit_log, f"打开失败：{exc}")
        else:
            messagebox.showinfo(APP_TITLE, "还没有生成伴生目录")

    def _do_kit(self) -> None:
        import decoy_kit as dk

        raw = self.kit_src.get()
        if not raw or not Path(raw).exists():
            messagebox.showwarning(APP_TITLE, "请先选择程序包（文件或文件夹）")
            return
        src = Path(raw)
        style = self.kit_style.get() or dk.DEFAULT_STYLE
        poison = self.poison.get() or dk.DEFAULT_POISON
        layers = self.layers.get()
        container = Path(self.armored.get()) if (
            self.armored.get() and Path(self.armored.get()).is_file()
        ) else None
        suffix = dk.STYLES[style][0]
        self.kit_root = src.parent / (src.stem + suffix)

        def job(progress, emit):
            emit("log", f"生成伴生诱饵：{src.name} / {style} / {poison} / {layers} 层")
            with Stopwatch() as sw:
                result = dk.build_sidecar(src, armored=container, layers=layers,
                                          style=style, poison=poison,
                                          on_progress=progress)
            emit("record", dict(action="伴生", label=src.name, ok=True,
                                layers_tried=0, seconds=sw.elapsed,
                                note=f"{len(result.files)} 份文件 / {result.traps} 组线索 / {poison}"))
            emit("log", f"输出目录：{result.root}")
            for rel in result.files:
                emit("log", f"  + {rel}")
            emit("log", f"共 {len(result.files)} 份拟态文件 / "
                        f"{result.traps} 组互相矛盾的字段线索")
            emit("log", "口令池与容器草稿一致：能解开诱饵层，解不开真层。")
            emit("log", "文档互相指定「以对方为准」，tools/ 里的解析器常量全错。")
            emit("log", "原目录未改动；不需要时整目录删掉即可。")
            return "伴生诱饵包生成完成。"

        self._run_async(job, self.kit_log, [self.kit_btn])

    # ------------------------------------------------------------------
    # 后台任务
    # ------------------------------------------------------------------
    def _run_async(self, job, log_widget, buttons: list[ttk.Button]) -> None:
        if self.busy:
            return
        self.busy = True
        for b in buttons:
            b.configure(state="disabled")
        self.pb.configure(value=0)

        def emit(kind, *payload):
            self.q.put((kind, payload, log_widget))

        def progress(done, total, msg):
            emit("progress", done, total, msg)

        def worker():
            try:
                result = job(progress, emit)
                emit("done", result)
            except Exception as exc:
                emit("error", str(exc), traceback.format_exc())

        threading.Thread(target=worker, daemon=True).start()
        self.after(80, self._poll, buttons)

    def _poll(self, buttons: list[ttk.Button]) -> None:
        try:
            while True:
                kind, payload, widget = self.q.get_nowait()
                if kind == "log":
                    self.log(widget, payload[0])
                elif kind == "progress":
                    done, total, msg = payload
                    self.pb.configure(maximum=max(total, 1), value=done)
                    self.status.set(msg)
                elif kind == "done":
                    self.log(widget, payload[0])
                    self.status.set("完成")
                    for b in buttons:
                        b.configure(state="normal")
                    self.busy = False
                    self.pb.configure(value=self.pb.cget("maximum"))
                    return
                elif kind == "record":
                    self.metrics.record(**payload[0])
                    self._refresh_report()
                elif kind == "error":
                    self.log(widget, f"失败：{payload[0]}")
                    self.status.set(f"失败：{payload[0]}")
                    messagebox.showerror(APP_TITLE, payload[0])
                    for b in buttons:
                        b.configure(state="normal")
                    self.busy = False
                    return
        except queue.Empty:
            pass
        if self.busy:
            self.after(80, self._poll, buttons)

    def _do_armor(self) -> None:
        import armor_core as ac
        src = Path(self.src.get())
        out = Path(self.out_armored.get())
        pw, pw2 = self.enc_pw.get(), self.enc_pw2.get()
        layers, profile = self.layers.get(), self.profile.get()
        want_kit = self.sidecar_on.get()
        kit_style = self.kit_style.get()
        poison = self.poison.get()
        if not src.exists():
            messagebox.showwarning(APP_TITLE, "请先拖入或选择程序包")
            return
        if not pw or pw != pw2:
            messagebox.showwarning(APP_TITLE, "两次口令不一致，或口令为空")
            return
        strong, hint = ac.check_password_strength(pw)
        force_weak = False
        if not strong and not messagebox.askyesno(
            APP_TITLE, f"口令偏弱：{hint}\n\n弱口令会让加固形同虚设，仍要继续吗？"
        ):
            return
        if not strong:
            # 用户已明确确认过风险，需要把 API 层的强制校验一并放行，
            # 否则确认框形同虚设、加固会在异步任务里抛错。
            force_weak = True
        if out.exists() and not messagebox.askyesno(
            APP_TITLE, f"输出文件已存在，确定覆盖吗？\n\n{out}"
        ):
            return

        def job(progress, emit):
            emit("log", f"开始加固：{src.name} / {layers} 层 / {profile} / {poison}")
            with Stopwatch() as sw:
                blob = ac.build_armored(src, pw.encode("utf-8"), layers=layers,
                                        profile=profile, on_progress=progress,
                                        strict=not force_weak)
                out.write_bytes(blob)
            emit("record", dict(action="加固", label=out.name, ok=True,
                                layers_tried=layers, seconds=sw.elapsed,
                                note=f"{profile} / {len(blob):,} 字节 / {poison}"))
            info = ac.inspect_armored(blob)
            emit("log", f"已写出：{out}")
            emit("log", f"容器 {len(blob):,} 字节 / {info.layers} 层 / "
                        f"规格草稿 {info.note_size} 字节")
            emit("log", "原程序未改动，真层与诱饵层在容器内不可区分。")
            if want_kit:
                try:
                    import decoy_kit as dk
                    kit = dk.build_sidecar(src, armored=out, layers=layers,
                                           style=kit_style, poison=poison,
                                           on_progress=progress)
                    emit("log", f"伴生诱饵：{kit.root}")
                    emit("log", f"  {len(kit.files)} 份拟态文件 / "
                                f"{kit.traps} 组互相矛盾的字段线索")
                    emit("log", "  原目录未改动，口令池只能解开诱饵层。")
                except Exception as exc:
                    emit("log", f"伴生诱饵未生成：{exc}")
                    emit("log", "  容器已写出，可到「伴生诱饵」页单独生成。")
            return "加固完成。"

        self._run_async(job, self.enc_log, [self.armor_btn])

    def _do_restore(self) -> None:
        import armor_core as ac
        src = Path(self.armored.get())
        out = Path(self.out_dir.get())
        pw = self.dec_pw.get()
        parallel = self.parallel.get()
        if not src.is_file():
            messagebox.showwarning(APP_TITLE, "请先拖入或选择 .armored 容器")
            return
        if not pw:
            messagebox.showwarning(APP_TITLE, "请输入口令")
            return
        if out.is_dir() and any(out.iterdir()) and not messagebox.askyesno(
            APP_TITLE, f"输出目录已有文件，同名文件会被覆盖，继续吗？\n\n{out}"
        ):
            return

        def job(progress, emit):
            seen = [0]

            def track(done, total, msg):
                seen[0] = max(seen[0], total)
                progress(done, total, msg)

            emit("log", "开始还原……" + ("（并行）" if parallel else ""))
            with Stopwatch() as sw:
                try:
                    result = ac.restore_armored(src.read_bytes(), pw.encode("utf-8"),
                                                on_progress=track, parallel=parallel)
                except ac.ArmorError:
                    emit("record", dict(action="还原", label=src.name, ok=False,
                                        layers_tried=seen[0], seconds=sw.elapsed,
                                        note="口令未解开任何层（错误口令同样计入成本）"))
                    raise
                # 用户已在上一步明确确认「同名文件会被覆盖」，这里放行。
                written = ac.safe_extract(result.payload, out, overwrite=True)
            emit("record", dict(action="还原", label=src.name, ok=True,
                                layers_tried=seen[0], seconds=sw.elapsed,
                                note=f"写出 {len(written)} 个文件"))
            emit("log", f"内容 SHA-256：{result.sha256}")
            emit("log", f"条目 {result.file_count} 个，已写出 {len(written)} 个文件")
            emit("log", f"输出目录：{out}")
            emit("log", "（不显示层号与真伪标记：任何提示都会帮逆向方剪枝）")
            return "还原完成。"

        self._run_async(job, self.dec_log, [self.restore_btn])


def main() -> None:
    _enable_dpi()
    try:
        import argon2  # noqa: F401
        import cryptography  # noqa: F401
        import armor_core  # noqa: F401
        import decoy_kit  # noqa: F401
    except ImportError as exc:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror(
            APP_TITLE,
            f"缺少依赖：{exc}\n\n请在命令行执行：\n"
            f"pip install argon2-cffi cryptography",
        )
        return
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
