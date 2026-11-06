#!/usr/bin/env python3
"""本地运行报告：统计「逆向方要付多少轮」，只在内存里，导出由用户决定。

设计边界
--------
* 只记录次数、耗时、层尝试数和文件名，**绝不记录口令、明文或容器内容**；
* 数据不写进 .armored 容器 —— 写进去就是给逆向方的免费剪枝信号；
* 不自动落盘。点「导出报告」才写 CSV / Markdown，路径由用户选。

估算口径
--------
`TOKENS_PER_ROUND` 是「一次工具调用 + 上下文重放」的保守估计值，用来把
轮数换算成量级，**不是真实 LLM 的 token 计数**。真实实测请填
docs/AGENT_BENCHMARK.md 里的表，并把估算值替换掉。
"""

from __future__ import annotations

import csv
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path

#: 每轮工具调用的粗估上下文开销。仅用于换算量级，可按需调整。
TOKENS_PER_ROUND = 800

__all__ = ["Attempt", "Metrics", "TOKENS_PER_ROUND"]


@dataclass(frozen=True, slots=True)
class Attempt:
    """一次操作的记录。label 只放文件名，不放路径全名以外的敏感信息。"""

    ts: str
    action: str
    label: str
    ok: bool
    layers_tried: int
    seconds: float
    est_tokens: int
    note: str = ""


@dataclass(slots=True)
class Metrics:
    """一个会话内的事件集合。线程安全由调用方保证（GUI 只在主线程读写）。"""

    attempts: list[Attempt] = field(default_factory=list)

    @property
    def rounds(self) -> int:
        """累计工具调用轮数：一次层尝试算一轮，一次内容分析再算两轮。"""
        return sum(a.layers_tried + (2 if a.ok else 0) for a in self.attempts)

    @property
    def failures(self) -> int:
        return sum(1 for a in self.attempts if not a.ok)

    @property
    def est_tokens(self) -> int:
        return sum(a.est_tokens for a in self.attempts)

    def record(
        self,
        action: str,
        label: str,
        *,
        ok: bool,
        layers_tried: int,
        seconds: float,
        note: str = "",
    ) -> Attempt:
        rounds = max(0, layers_tried) + (2 if ok else 0)
        item = Attempt(
            ts=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            action=action,
            label=Path(label).name,
            ok=bool(ok),
            layers_tried=max(0, layers_tried),
            seconds=round(max(0.0, seconds), 3),
            est_tokens=rounds * TOKENS_PER_ROUND,
            note=note,
        )
        self.attempts.append(item)
        return item

    def summary(self) -> dict[str, object]:
        return {
            "记录条数": len(self.attempts),
            "错误口令 / 失败次数": self.failures,
            "累计层尝试": sum(a.layers_tried for a in self.attempts),
            "估算工具调用轮数": self.rounds,
            "估算 token（非实测）": self.est_tokens,
            "累计耗时（秒）": round(sum(a.seconds for a in self.attempts), 3),
        }

    def to_csv(self, path: str | Path) -> Path:
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", encoding="utf-8-sig", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(Attempt.__dataclass_fields__))
            writer.writeheader()
            for item in self.attempts:
                writer.writerow(asdict(item))
        return out

    def to_markdown(self) -> str:
        lines = ["# TarpitCrypt 本地运行报告", ""]
        lines.append(f"> 生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("> 估算值不是真实 LLM token 计数；数据只来自本机界面操作，不含口令。")
        lines += ["", "## 汇总", "", "| 指标 | 值 |", "| --- | --- |"]
        for key, value in self.summary().items():
            lines.append(f"| {key} | {value} |")
        lines += ["", "## 明细", "",
                  "| 时间 | 操作 | 对象 | 结果 | 层尝试 | 耗时(s) | 估算轮数 | 备注 |",
                  "| --- | --- | --- | --- | --- | --- | --- | --- |"]
        for a in self.attempts:
            lines.append(
                f"| {a.ts} | {a.action} | {a.label} | {'成功' if a.ok else '失败'} | "
                f"{a.layers_tried} | {a.seconds} | {a.layers_tried + (2 if a.ok else 0)} | "
                f"{a.note} |"
            )
        if not self.attempts:
            lines.append("| — | — | — | — | — | — | — | 本次会话还没有记录 |")
        return "\n".join(lines) + "\n"


class Stopwatch:
    """给 with 语句用的计时器。"""

    def __init__(self) -> None:
        self.start = 0.0
        self.elapsed = 0.0

    def __enter__(self) -> "Stopwatch":
        self.start = time.perf_counter()
        return self

    def __exit__(self, *_exc) -> None:
        self.elapsed = time.perf_counter() - self.start
