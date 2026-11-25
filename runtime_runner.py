#!/usr/bin/env python3
"""TarpitCrypt 启动器：双击即用，无口令；只对分析行为降级。

正常流程（< 1 秒）
------------------
1. 从自身尾部读出陷阱容器
2. 用低成本派生的核心密钥扫出真实包（假包只会付出一次失败校验）
3. 解压到临时目录，启动入口程序，等待退出
4. 覆写擦除临时目录

降级流程
--------
- 调试器 / 口令式破解参数 → 慢速迷宫（诱饵 + 烧算力 + 伪造报错）
- 两个弱信号（AI Agent 环境变量、可疑父进程、虚拟机）→ 正常启动，
  同时往临时目录投放诱饵源码，供动态 dump 的探针捡走

边界：无口令意味着能读码的人最终仍可还原；这里抬高的是 AI 与自动化
工具的时间 / token / 算力成本，不联网、不破坏主机。
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import runtime_pack as rp  # noqa: E402
import trap_guard  # noqa: E402


def _fatal(text: str) -> None:
    trap_guard._msgbox(text)


def main() -> int:
    try:
        exe = Path(sys.executable if getattr(sys, "frozen", False) else __file__)
        blob = rp.read_embedded(exe)
        container = rp.parse_container(blob)
    except rp.RuntimePackError as exc:
        _fatal(str(exc))
        return 2
    except Exception as exc:
        _fatal(f"启动器异常：{exc}")
        return 3

    if container["guard"]:
        if trap_guard.crack_attempt():
            return trap_guard.run_tarpit(blob, reason="crack-args")
        assessment = trap_guard.assess()
        if assessment.level == "strong":
            return trap_guard.run_tarpit(blob, reason="debugger")
        level = assessment.level
    else:
        level = "normal"

    try:
        plain, manifest, _core = rp.open_core(blob)
    except rp.RuntimePackError as exc:
        _fatal(str(exc))
        return 2
    except Exception as exc:
        _fatal(f"启动器异常：{exc}")
        return 3

    tmp = Path(tempfile.mkdtemp(prefix="rtpk_"))
    try:
        rp.safe_extract(plain, tmp)
        if level == "medium":
            try:
                trap_guard.deploy_decoys(blob, tmp / ".syscache")
            except Exception:
                pass
        entry = tmp / manifest.entry
        if not entry.exists():
            raise rp.RuntimePackError(f"入口文件缺失：{manifest.entry}")
        proc = subprocess.Popen([str(entry)], cwd=str(entry.parent))
        return proc.wait()
    except Exception as exc:
        _fatal(f"运行失败：{exc}")
        return 4
    finally:
        rp.wipe_dir(tmp)


if __name__ == "__main__":
    raise SystemExit(main())
