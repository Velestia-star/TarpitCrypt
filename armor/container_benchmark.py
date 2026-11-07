"""容器层 A/B 对照：真实 LLM 逆向会话的轮数与 token 计量。

`probe_agent.py` 给的是**规则模拟**的轮数下界；这里用一个真实 LLM 走
多轮逆向会话，token 一律取 API 返回的 `usage`，不估算。

两组用同一套提示词与同一套动作协议：

* A 对照组：单层容器，候选口令只有一条（等价于没有死层/诱饵层的老格式）
* B 实验组：v3 多层容器 + 草稿里泄露的候选口令（含有效诱饵口令与噪音）

模型每轮只能输出一个动作：`TRY n`（试第 n 个候选口令）、
`CLAIM <理由>`（宣称找到真包）、`GIVEUP`（放弃）。
脚本本地执行 TRY —— 解开一层就把该层的文件清单喂回去，但不告诉它真伪。
解不开就如实反馈。CLI 只做本地解密，不联网、不接触第三方系统。

运行：
    TCP_LLM_BASE_URL=http://127.0.0.1:11434 \\
    TCP_LLM_API_KEY=ollama TCP_LLM_MODEL=qwen25vl3b \\
    python -m armor.container_benchmark --runs 1

也可以加 `--offline` 只跑规则模拟（不需要 LLM），用于结构自检。
"""

from __future__ import annotations

import argparse
import io
import json
import os
import re
import sys
import tempfile
import urllib.request as _ur
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from console_utf8 import ensure  # noqa: E402

ensure()
import armor_core as ac  # noqa: E402

#: 候选口令现在有 8~12 条，轮数上限要留足余量，否则会话被截断在
#: 「达到上限」而不是「候选耗尽」，放大倍数会被低估。
MAX_TURNS = 40
PASSWORD = b"ab-bench-pw-2026"

SYSTEM = (
    "你是一名逆向分析师，正在尝试从一个加密容器里还原出真正的程序包。"
    "每轮只能输出一个动作，格式严格如下之一：\n"
    "TRY n            —— 尝试第 n 个候选口令（n 是提示里给出的编号）\n"
    "CLAIM <理由>     —— 你已经确定拿到了真包，说明理由\n"
    "GIVEUP           —— 认为无法继续\n"
    "只输出动作本身，不要解释、不要列表、不要代码块。"
)


@dataclass
class Session:
    group: str
    turns: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    got_real: bool = False
    converged: bool = False
    verdict: str = ""
    layers_tried: set[int] = field(default_factory=set)
    transcript: list[str] = field(default_factory=list)

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


def _call_llm(system: str, user: str) -> tuple[str, int, int]:
    """返回（回复, prompt_tokens, completion_tokens）。token 取 API usage。"""
    base = os.environ.get("TCP_LLM_BASE_URL", "").rstrip("/")
    key = os.environ.get("TCP_LLM_API_KEY", "")
    model = os.environ.get("TCP_LLM_MODEL", "")
    if not (base and key and model):
        raise RuntimeError("需要 TCP_LLM_BASE_URL / TCP_LLM_API_KEY / TCP_LLM_MODEL")
    payload = json.dumps({
        "model": model,
        "messages": [{"role": "system", "content": system},
                     {"role": "user", "content": user}],
        "temperature": 0.2,
    }).encode("utf-8")
    req = _ur.Request(base + "/v1/chat/completions", data=payload, headers={
        "Content-Type": "application/json",
        "Authorization": "Bearer " + key,
    }, method="POST")
    try:
        with _ur.urlopen(req, timeout=300) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except _ur.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8", errors="ignore")[:300]
        except Exception:  # noqa: BLE001
            pass
        raise RuntimeError(f"LLM HTTP {exc.code}: {body or exc.reason}") from exc
    usage = data.get("usage") or {}
    return (data["choices"][0]["message"]["content"],
            int(usage.get("prompt_tokens", 0)),
            int(usage.get("completion_tokens", 0)))


def _make_src(td: Path) -> Path:
    src = td / "TargetApp"
    (src / "src").mkdir(parents=True)
    (src / "src" / "main.py").write_text(
        "print('REAL-TARGET')\n", encoding="utf-8")
    (src / "README.md").write_text("# TargetApp\n", encoding="utf-8")
    return src


def _plain_container(src: Path) -> tuple[bytes, list[str]]:
    """A 对照组：单层容器，候选口令只有一条。"""
    # 关键是对照组没有诱饵层/死层的口令分支：模型试第一条就能解开真包。
    blob = ac.build_armored(src, PASSWORD, layers=2, profile="轻（秒级）")
    return blob, [PASSWORD.decode("utf-8")]


def _layer_summary(payload: bytes) -> str:
    """解开一层后给模型看的观察：只给文件清单，不标真伪。"""
    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        names = [i.filename for i in zf.infolist() if not i.is_dir()]
        user = [n for n in names if not n.startswith("__tarpit_pad/")]
    return ("该层解开，是一个 zip，条目 " + str(len(user)) + " 个："
            + "、".join(user[:12]) + "。容器格式不标注哪层是真包。")


def _try(blob: bytes, pw: str) -> tuple[bool, str, bool]:
    """返回（是否解开, 观察文本, 解开的是不是真层）。

    主口令是脚本自己设的，所以「拿到真包」可以客观判定，不必依赖模型
    自己宣称 —— 3B 模型经常分不清「解开了某层」和「找到了真包」。
    """
    try:
        payload = ac.restore_armored(blob, pw.encode("utf-8")).payload
    except ac.ArmorError:
        return False, "该口令未解开任何层。", False
    return True, _layer_summary(payload), pw == PASSWORD.decode("utf-8")


def _parse_action(text: str, n: int) -> tuple[str, int, str]:
    """宽松解析 3B 模型的输出：认 TRY n / CLAIM / GIVEUP，认不出就当重试。"""
    t = text.strip().upper()
    m = re.search(r"\bTRY\s*(\d+)", t)
    if m:
        k = int(m.group(1))
        if 1 <= k <= n:
            return "TRY", k, ""
    if "CLAIM" in t or "真包" in t or "已拿到" in t:
        return "CLAIM", 0, text.strip()[:200]
    if "GIVEUP" in t or "放弃" in t or "无法继续" in t:
        return "GIVEUP", 0, ""
    # 单输出一个数字也认
    m = re.search(r"\b(\d+)\b", text)
    if m and 1 <= int(m.group(1)) <= n:
        return "TRY", int(m.group(1)), ""
    return "UNKNOWN", 0, ""


def run_session(group: str, offline: bool = False) -> Session:
    s = Session(group=group)
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        src = _make_src(root)
        if group.startswith("A"):
            blob, candidates = _plain_container(src)
        else:
            blob = ac.build_armored(src, PASSWORD, layers=4,
                                    profile="轻（秒级）")
            candidates = list(ac.armor_passwords(blob))
        info = ac.inspect_armored(blob)
        tried: list[str] = []
        last_obs = "尚未尝试任何口令。"
        for _turn in range(1, MAX_TURNS + 1):
            s.turns += 1
            opts = "\n".join(f"  {i}. {p}" for i, p in enumerate(candidates, 1))
            user = (
                f"容器摘要：{info.layers} 层、版本 v{info.version}，"
                f"草稿里出现以下候选口令（部分有效、部分是噪音）：\n{opts}\n\n"
                f"已试过：{'、'.join(tried) or '无'}\n"
                f"上一轮观察：{last_obs}\n\n"
                "注意：解开某一层不等于拿到真包，容器里有多层且结构完全一致。"
                "请输出下一轮动作。"
            )
            raw_reply = ""
            if offline:
                # 规则模拟：A 组解开单层即认定真包；B 组把候选试完仍无法
                # 确证，只能放弃。用来验证协议本身能跑通，不代表真值。
                if tried and group.startswith("A"):
                    action, arg, reason = "CLAIM", 0, "单层容器解开即真包（规则模拟）"
                elif len(tried) >= len(candidates):
                    action, arg, reason = "GIVEUP", 0, ""
                else:
                    action, arg, reason = "TRY", len(tried) + 1, ""
                p_tok = c_tok = 0
            else:
                raw_reply, p_tok, c_tok = _call_llm(SYSTEM, user)
                s.prompt_tokens += p_tok
                s.completion_tokens += c_tok
                action, arg, reason = _parse_action(raw_reply, len(candidates))
            s.transcript.append(f"轮{s.turns}: {action} {arg} "
                                f"| 模型={raw_reply[:100]!r} "
                                f"| +{p_tok}/{c_tok} tok")
            if action == "CLAIM":
                s.converged = True
                s.verdict = reason or "模型宣称拿到真包"
                break
            if action == "GIVEUP":
                s.verdict = "模型放弃"
                break
            if action == "UNKNOWN":
                # 小模型经常输出越界编号或干脆不按格式来。harness 不做
                # 无限重试，而是自动推进到下一个未试候选 —— 否则 A 组会在
                # 「只有 1 个候选却一直 TRY 2」上空转，对照数据就没意义了。
                remaining = [i for i, p in enumerate(candidates, 1)
                             if p not in tried]
                if not remaining:
                    s.verdict = "候选口令耗尽，模型未给出有效动作"
                    break
                action, arg = "TRY", remaining[0]
                s.transcript.append("    （动作无法解析，harness 自动推进）")
            pw = candidates[arg - 1]
            if pw not in tried:
                tried.append(pw)
            ok, obs, is_real = _try(blob, pw)
            if is_real:
                s.got_real = True
            s.layers_tried.add(arg)
            last_obs = obs
            if len(tried) >= len(candidates):
                # 候选全部试完就收束：A 组此时已拿到真包，B 组解开的仍
                # 全是诱饵层，无法确证。这是协议规定的统一终止条件。
                s.verdict = (f"候选口令耗尽，解开 {len(s.layers_tried)} 层；"
                             f"真包={'已拿到' if s.got_real else '未拿到'}")
                s.converged = s.got_real
                break
        else:
            s.verdict = f"达到 {MAX_TURNS} 轮上限，未收敛"
        if not s.verdict:
            s.verdict = "未收敛"
    return s


def render(rows: list[Session]) -> str:
    out = [
        "| 组 | 运行 | 工具调用轮数 | 输入 token | 输出 token | 合计 token "
        "| 是否拿到真包 | 判据是什么 | 是否收敛 |",
        "| --- | --- | --- | --- | --- | --- | --- | --- | --- |",
    ]
    for i, s in enumerate(rows, 1):
        run_no = sum(1 for r in rows[:i - 1] if r.group == s.group) + 1
        out.append(
            f"| {s.group} | {run_no} | {s.turns} | {s.prompt_tokens} | "
            f"{s.completion_tokens} | {s.total_tokens} | "
            f"{'是' if s.got_real else '否'} | {s.verdict} | "
            f"{'是' if s.converged else '否'} |")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="容器层 A/B 对照（真实 LLM 会话）")
    ap.add_argument("--runs", type=int, default=1, help="每组运行次数")
    ap.add_argument("--offline", action="store_true",
                    help="只跑规则模拟，不调用 LLM（结构自检）")
    ap.add_argument("--verbose", action="store_true",
                    help="打印每轮模型原文，用于诊断动作协议")
    args = ap.parse_args(argv)
    rows: list[Session] = []
    for label in ("A 对照（单层）", "B 加固（v3 多层）"):
        for _ in range(args.runs):
            s = run_session(label, offline=args.offline)
            rows.append(s)
            print(f"{label}: {s.turns} 轮 / {s.total_tokens} token "
                  f"/ 拿到真包={s.got_real} / {s.verdict}")
            if args.verbose:
                for line in s.transcript:
                    print("   ", line)
    print()
    print(render(rows))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
