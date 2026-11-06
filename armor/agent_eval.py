#!/usr/bin/env python3
"""可复现的「烧轮数」评估：多轮取样 + token 量级换算 + 报告导出。

与 probe_agent.py 的分工
------------------------
* probe_agent.py 是单次演示，给人看结论；
* 本脚本跑 N 次取中位数与区间，避免把口令随机分布带来的波动当成效果，
  并输出 Markdown 报告，可直接贴进 PR / 答辩材料。

诚实边界
--------
本脚本驱动的是**规则式模拟 agent**，不是真实 LLM。token 数按
armor_metrics.TOKENS_PER_ROUND 粗估，只代表量级，不能当实测数据引用。
真实 agent 的实测方法与记录表见仓库 docs/AGENT_BENCHMARK.md。

运行：py -3 agent_eval.py [--runs 5] [--out report.md]
"""

from __future__ import annotations

import argparse
import re
import statistics
import sys
import tempfile
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from console_utf8 import ensure  # noqa: E402

ensure()
import armor_core as ac  # noqa: E402
import probe_agent as pa  # noqa: E402
from armor_metrics import TOKENS_PER_ROUND  # noqa: E402

LAYERS = 4


def one_run(root: Path) -> dict:
    src = root / "TargetApp"
    (src / "src").mkdir(parents=True)
    (src / "src" / "main.py").write_text("print('real target')\n", encoding="utf-8")
    (src / "README.md").write_text("# TargetApp\n", encoding="utf-8")

    plain = pa.build_plain(src, pa.COMMON_GUESSES[0].encode("utf-8"))
    armored = ac.build_armored(src, b"correct-horse-9", layers=LAYERS,
                               profile=list(ac.PROFILES)[0])
    leaked = re.findall(r"`([^`]+)`", pa.note_from(armored))
    armed_candidates = list(dict.fromkeys(leaked + list(pa.COMMON_GUESSES)))

    a = pa.probe_plain(plain, list(pa.COMMON_GUESSES))
    b = pa.probe_armored(armored, armed_candidates, LAYERS)
    c = pa.probe_informed(armored, armed_candidates, LAYERS)
    return {
        "plain_rounds": a["rounds"], "blind_rounds": b["rounds"],
        "informed_rounds": c["rounds"],
        "blind_got": b["got_target"],
        "located_real": c["located_real"],
        "remaining": c["remaining"],
        "note_bytes": ac.inspect_armored(armored).note_size,
        "container_bytes": len(armored),
        "candidates": len(armed_candidates),
    }


def report(runs: list[dict]) -> str:
    def col(key: str) -> list[float]:
        return [float(r[key]) for r in runs]

    def stat(key: str) -> str:
        vals = col(key)
        return (f"{statistics.median(vals):.0f} "
                f"（{min(vals):.0f}~{max(vals):.0f}）")

    plain = statistics.median(col("plain_rounds"))
    blind = statistics.median(col("blind_rounds"))
    informed = statistics.median(col("informed_rounds"))
    located = sum(1 for r in runs if r["located_real"])
    got = sum(1 for r in runs if r["blind_got"])

    lines = [
        "# TarpitCrypt 信息污染效果评估", "",
        f"- 生成时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"- 工具版本：`{ac.__version__}`；容器格式 v{ac.VERSION}",
        f"- 取样次数：{len(runs)}；层数：{LAYERS}；强度档：{list(ac.PROFILES)[0]}",
        f"- 环境：Python {sys.version.split()[0]} / argon2-cffi / cryptography", "",
        "> **口径声明**：下表来自规则式模拟 agent，不是真实 LLM 调用。",
        f"> token 按每轮 {TOKENS_PER_ROUND} 估算，只表示量级；真实实测请见",
        "> `docs/AGENT_BENCHMARK.md`，拿到实测数据后应替换本节。", "",
        "## 结果", "",
        "| 指标 | 中位数（区间） |", "| --- | --- |",
        f"| 基线容器工具调用轮数 | {stat('plain_rounds')} |",
        f"| 盲 agent 工具调用轮数 | {stat('blind_rounds')} |",
        f"| 读源码 agent 工具调用轮数 | {stat('informed_rounds')} |",
        f"| 放大倍数（盲 agent / 基线） | {blind / max(plain, 1):.1f}× |",
        f"| 盲 agent 估算 token | {blind * TOKENS_PER_ROUND:,.0f} |",
        f"| 读源码 agent 估算 token | {informed * TOKENS_PER_ROUND:,.0f} |",
        f"| 基线估算 token | {plain * TOKENS_PER_ROUND:,.0f} |",
        f"| 候选口令条数 | {stat('candidates')} |",
        f"| 规格草稿大小 | {stat('note_bytes')} B |",
        f"| 容器大小 | {stat('container_bytes')} B |", "",
        "## 关键判据：确定性", "",
        f"- 读源码 agent **{len(runs) - located}/{len(runs)}** 次无法确定性定位真层",
        f"  （排除法平均剩 {statistics.mean(col('remaining')):.1f} 层）。",
        f"- 盲 agent 在 {len(runs) - got}/{len(runs)} 次里没有拿到真程序包。",
        "- 历史对照：v2 容器（硬编码口令池 + 无死层）同样的知情 agent 算法",
        "  21 轮即确定性锁定真层。v3 的关键收益是**判据消失**，不是轮数变大。", "",
        "## 局限", "",
        "1. 规则式 agent 不会因矛盾规格而临时写解析脚本，真实轮数应更高；",
        "2. 口令与层分布每次随机，轮数区间会浮动，不要当固定承诺；",
        "3. 未计入上下文截断、重试、误判后回滚带来的额外消耗；",
        "4. token 是估算，不是账单；真实计费需接 API usage 字段。", "",
        "## 复现", "",
        "```bash",
        "pip install argon2-cffi cryptography",
        "python agent_eval.py --runs 5 --out report.md",
        "python probe_agent.py   # 单次三组对照",
        "```", "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="信息污染效果评估")
    ap.add_argument("--runs", type=int, default=5, help="取样次数（默认 5）")
    ap.add_argument("--out", type=str, default="", help="可选：把 Markdown 报告写到文件")
    args = ap.parse_args(argv)
    if args.runs < 1:
        ap.error("--runs 至少为 1")

    runs: list[dict] = []
    for i in range(args.runs):
        with tempfile.TemporaryDirectory() as td:
            runs.append(one_run(Path(td)))
        print(f"  第 {i + 1}/{args.runs} 次取样完成", file=sys.stderr)

    text = report(runs)
    print(text)
    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"报告已写出：{out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
