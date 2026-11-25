#!/usr/bin/env python3
"""启动器侧的陷阱守卫：反调试 / 反沙箱 / 反 AI Agent 探测 + 慢速迷宫。

判定分级
--------
- strong：调试器已附加，或命令行/环境变量明显在尝试"口令式提取"。
          → 进入慢速迷宫：只投放诱饵、烧 CPU，永不启动真实程序。
- medium：同时命中两个弱信号（AI Agent 环境变量、可疑父进程、虚拟机）。
          → 正常启动真实程序，额外在临时目录里投放诱饵源码供 dump。
- normal：双击等常规场景，零延迟。

所有动作都是本地的：不联网、不写注册表、不碰第三方进程、不破坏主机。
"""

from __future__ import annotations

import ctypes
import os
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

AI_ENV_PREFIXES = (
    "CLAUDE_CODE", "CLAUDE_", "CURSOR_", "TRAE_", "OPENAI_", "ANTHROPIC_",
    "AIDER_", "GEMINI_", "CODEX_", "CONTINUE_", "WINDSURF_", "COPILOT_",
    "CODEIUM_", "OLLAMA_", "DEEPSEEK_", "QWEN_",
)
SUSPECT_PARENTS = {
    "python.exe", "pythonw.exe", "node.exe", "node", "deno.exe",
    "code.exe", "cursor.exe", "windsurf.exe", "claude.exe", "aider.exe",
    "pycharm64.exe", "idea64.exe", "devenv.exe", "gdb.exe", "x64dbg.exe",
    "ollydbg.exe", "ida64.exe", "ida.exe", "windbg.exe",
}
CRACK_ARGS = {
    "--password", "--pass", "-p", "--decrypt", "--unpack", "--extract",
    "--dump", "--key", "--license", "--bypass", "--crack", "--serial",
}

TARPIT_SECONDS = 75


@dataclass
class Assessment:
    level: str = "normal"
    signals: list[str] = field(default_factory=list)
    debugger: bool = False
    parent: str = ""


# ---------------------------------------------------------------- 探测


def _debugger_present() -> bool:
    if sys.platform != "win32":
        return False
    try:
        k = ctypes.windll.kernel32
        if k.IsDebuggerPresent():
            return True
        flag = ctypes.c_int(0)
        if k.CheckRemoteDebuggerPresent(k.GetCurrentProcess(), ctypes.byref(flag)):
            return bool(flag.value)
    except Exception:
        pass
    return False


class _PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", ctypes.c_ulong),
        ("cntUsage", ctypes.c_ulong),
        ("th32ProcessID", ctypes.c_ulong),
        ("th32DefaultHeapID", ctypes.c_void_p),
        ("th32ModuleID", ctypes.c_ulong),
        ("cntThreads", ctypes.c_ulong),
        ("th32ParentProcessID", ctypes.c_ulong),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", ctypes.c_ulong),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


def _parent_process_name() -> str:
    if sys.platform != "win32":
        return ""
    try:
        k = ctypes.windll.kernel32
        k.CreateToolhelp32Snapshot.argtypes = [ctypes.c_ulong, ctypes.c_ulong]
        k.CreateToolhelp32Snapshot.restype = ctypes.c_void_p
        k.Process32FirstW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_PROCESSENTRY32W)]
        k.Process32FirstW.restype = ctypes.c_int
        k.Process32NextW.argtypes = [ctypes.c_void_p, ctypes.POINTER(_PROCESSENTRY32W)]
        k.Process32NextW.restype = ctypes.c_int
        k.CloseHandle.argtypes = [ctypes.c_void_p]
        k.CloseHandle.restype = ctypes.c_int
        snap = k.CreateToolhelp32Snapshot(0x00000002, 0)
        if not snap or snap == ctypes.c_void_p(-1).value:
            return ""
        try:
            entry = _PROCESSENTRY32W()
            entry.dwSize = ctypes.sizeof(_PROCESSENTRY32W)
            table: dict[int, tuple[int, str]] = {}
            if k.Process32FirstW(snap, ctypes.byref(entry)):
                while True:
                    table[int(entry.th32ProcessID)] = (
                        int(entry.th32ParentProcessID), entry.szExeFile.lower())
                    if not k.Process32NextW(snap, ctypes.byref(entry)):
                        break
            me = int(k.GetCurrentProcessId())
            parent_pid = table.get(me, (0, ""))[0]
            return table.get(parent_pid, (0, ""))[1]
        finally:
            k.CloseHandle(ctypes.c_void_p(snap))
    except Exception:
        return ""


def _vm_signals() -> list[str]:
    if sys.platform != "win32":
        return []
    signals: list[str] = []
    try:
        import winreg

        with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"HARDWARE\DESCRIPTION\System\BIOS") as key:
            for name in ("SystemManufacturer", "SystemProductName", "BIOSVendor"):
                try:
                    value = str(winreg.QueryValueEx(key, name)[0]).lower()
                except OSError:
                    continue
                if any(tag in value for tag in (
                        "vmware", "virtualbox", "qemu", "xen", "parallels",
                        "virtual machine", "bochs", "innotek")):
                    signals.append(f"vm:{name}")
    except OSError:
        pass
    return signals


def assess(env: dict | None = None, parent: str | None = None,
           debugger: bool | None = None) -> Assessment:
    """可注入参数的判定入口，便于自测。"""
    debugger = _debugger_present() if debugger is None else bool(debugger)
    source = dict(os.environ if env is None else env)
    upper = {k.upper(): v for k, v in source.items()}
    signals: list[str] = []
    if debugger:
        signals.append("debugger")
    for prefix in AI_ENV_PREFIXES:
        if any(k.startswith(prefix) for k in upper):
            signals.append(f"env:{prefix}")
            break
    pname = (_parent_process_name() if parent is None else parent) or ""
    if pname.lower() in SUSPECT_PARENTS:
        signals.append(f"parent:{pname.lower()}")
    signals.extend(_vm_signals())

    if debugger:
        level = "strong"
    elif len(signals) >= 2:
        level = "medium"
    else:
        level = "normal"
    return Assessment(level=level, signals=signals,
                      debugger=debugger, parent=pname)


def crack_attempt(argv: list[str] | None = None,
                  env: dict | None = None) -> bool:
    """自动化工具常用的"口令 / 解包"参数与旧环境变量，命中即视为破解尝试。"""
    args = {a.lower() for a in (sys.argv[1:] if argv is None else argv)}
    if args & CRACK_ARGS:
        return True
    source = os.environ if env is None else env
    return "RTPK_PASSWORD" in source


# ---------------------------------------------------------------- 诱饵投放


def deploy_decoys(blob: bytes, dest: Path) -> int:
    """把容器里的诱饵农场解到临时目录，供动态 dump 的探针"发现"。"""
    import runtime_pack as rp

    count = 0
    try:
        farms = rp.open_farms(blob)
    except Exception:
        return 0
    for i, (zip_bytes, _manifest) in enumerate(farms):
        try:
            count += len(rp.safe_extract(zip_bytes, Path(dest) / f"pkg_{i:02d}"))
        except Exception:
            continue
    return count


# ---------------------------------------------------------------- 慢速迷宫


def _burn_once() -> None:
    from argon2.low_level import Type, hash_secret_raw

    hash_secret_raw(
        secret=os.urandom(16),
        salt=os.urandom(16),
        time_cost=2,
        memory_cost=128 * 1024,
        parallelism=2,
        hash_len=32,
        type=Type.ID,
    )


def _native_message(text: str, title: str) -> bool:
    if sys.platform != "win32":
        return False
    try:
        u = ctypes.windll.user32
        u.MessageBoxW.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                  ctypes.c_wchar_p, ctypes.c_uint]
        u.MessageBoxW.restype = ctypes.c_int
        u.MessageBoxW(0, text, title, 0x00000010)
        return True
    except Exception:
        return False


def _msgbox(text: str, title: str = "无法启动") -> None:
    """用原生 MessageBox，避免把 Tk 拖进启动器（缩小体积、加快启动）。"""
    if _native_message(text, title):
        return
    print(f"{title}：{text}", file=sys.stderr)


def _burn(seconds: int) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        _burn_once()


def _show_failure() -> None:
    """非模态报错窗，6 秒后随进程退出自动关闭，避免挂死自动化工具。"""
    text = ("环境校验失败（0x8007）。\n"
            "请确认系统时间与授权状态后重试。\n"
            "错误码：0x8007 / E_LICENSE_ENV")
    if sys.platform == "win32":
        try:
            import threading

            threading.Thread(
                target=lambda: _native_message(text, "启动失败"),
                daemon=True,
            ).start()
            time.sleep(6)
            return
        except Exception:
            pass
    print(text, file=sys.stderr)


def run_tarpit(blob: bytes, reason: str = "", seconds: int = TARPIT_SECONDS) -> int:
    """进入慢速迷宫：投放诱饵、烧算力、返回伪造的校验失败。"""
    import runtime_pack as rp

    tmp = Path(tempfile.mkdtemp(prefix="rtpk_"))
    try:
        deploy_decoys(blob, tmp / "modules")
        _burn(max(5, int(seconds)))
        _show_failure()
        return 5
    finally:
        rp.wipe_dir(tmp)
