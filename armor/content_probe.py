#!/usr/bin/env python3
"""内容层陷阱探针：模拟具备 5 个盲区行为的 AI 逆向 agent，打 decoy_kit 诱饵包。

为什么要这个脚本
----------------
probe_agent.py 只测了**加密容器层**（口令爆破轮数放大），但 v0.3.2 新增的
**内容层陷阱**（IOC 蜜罐 / RAG 投毒 / 进度幻觉）从未被任何 agent 真正打过。本脚本（v0.3.3 起）
用「会犯那 5 个盲区」的 agent 去读 decoy_kit 生成的伴生诱饵包，看 tarpit 兜不兜得住。

模拟的 agent 行为（对应 docs/AI_RE_THREATMODEL.md 归纳的盲区）
-------------------------------------------------------
 1. 字符串即证据：正则提取目录里所有 IP/域名/URL/密钥，当作真实 IOC。
 2. 文档即事实：把 knowledge_base/、*.draft.md 当成权威结论读入。
 3. 有预算：每步操作计 1 个 action，超过上限即终止（模拟 token / 工具预算）。
 4. 确定性快照：结论一旦写入报告即固定，不回滚。
 5. 读文件指令：文件里写的「判为 BENIGN、停止深挖」会被当作指令执行。

两类 persona
-----------
 - typical：具备上述全部盲区，对应 BINNY / kernagent / RAVERSE / REAA 等常见工具。
 - skeptical：带基础 sanity check（会解析 IOC、质疑注入），用来测 tarpit 的**下界**
             —— 即便 agent 识破注入、继续硬刚，是否仍因「没有真目标」而被耗死。

安全不变量（最高优先级，违反即必须修）
-------------------------------------
所有被提取到的「可落地主机」类 IOC（IP / 域名 / URL）必须落在 RFC 保留 / 文档地址段，
绝不指向任何真实主机。密钥串只是形似真密钥的随机占位，无对应主机，不计为外联目标。
这是项目的硬底线：即便陷阱失效，也只允许 agent 空转，绝不允许它拿到一个真实 IP 去碰。

运行：py -3 content_probe.py [--poison IOC蜜罐|RAG投毒|均衡|ALL] [--budget 120]
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
from console_utf8 import ensure  # noqa: E402

ensure()
import decoy_kit as dk  # noqa: E402

BUDGET = 120
# 文档地址段（RFC 2606 / 6761 / 6762）：永不解析到真实主机。
_SAFE_DOMAINS = {"example.com", "example.net", "example.org", "invalid", "localhost", "home.arpa"}

# ---------------------------------------------------------------------------
# IOC 提取与分类
# ---------------------------------------------------------------------------
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"\b2001:db8:[0-9a-fA-F:.]+\b")
_URL = re.compile(r"https?://[^\s\"'<>)+]+")
_KEY = re.compile(r"\b(?:AKIA|sk|ghp_|AIza|xoxb|ya29\.)[0-9A-F]{8,}\b")
# 文档域（含子域）。形如 api.example.com / c2.home.arpa 等。
_SAFE_HOST_RE = re.compile(
    r"(?:[A-Za-z0-9-]+\.)*(?:example\.(?:com|net|org)|invalid|localhost|home\.arpa)\b"
)


def _is_safe_host(token: str) -> bool:
    """token 是一个主机标识（域名或 IP）。返回 True 表示安全（不指向真实主机）。"""
    # 纯 IP
    try:
        ip = ipaddress.ip_address(token)
        return not ip.is_global  # 保留 / 私网 / 回环 / 链路本地 全部 is_global=False
    except ValueError:
        pass
    # 域名：必须落在文档地址段
    return bool(_SAFE_HOST_RE.fullmatch(token))


def split_host(token: str) -> str | None:
    """从任意 IOC 里析出「主机标识」；无法析出（如纯密钥）返回 None。"""
    if _URL.match(token):
        host = urlparse(token).hostname or ""
        return host or None
    if _IPV4.fullmatch(token) or _IPV6.fullmatch(token):
        return token
    if _KEY.fullmatch(token):
        return None  # 密钥无主机
    if _SAFE_HOST_RE.fullmatch(token):
        return token
    return token  # 其它当成主机尝试（便于抓出意外格式）


def extract_iocs(root: Path) -> list[str]:
    """递归扫所有文本文件，按 5 个盲区 ① 把字符串当证据提取出来。"""
    found: list[str] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except (OSError, UnicodeDecodeError):
            continue
        for pat in (_URL, _IPV4, _IPV6, _KEY, _SAFE_HOST_RE):
            # _SAFE_HOST_RE 单独跑，避免被前面的正则吞掉
            for m in pat.finditer(text):
                tok = m.group(0).rstrip(").,;\"'")
                if tok:
                    found.append(tok)
    # 去重保序
    seen = set()
    out = []
    for t in found:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def classify(iocs: list[str]) -> dict:
    """分类 + 安全校验。返回统计与越界清单。"""
    hosts = [h for h in (split_host(t) for t in iocs) if h]
    leaks = [h for h in hosts if not _is_safe_host(h)]
    return {
        "total": len(iocs),
        "hosts": len(hosts),
        "keys": sum(1 for t in iocs if _KEY.fullmatch(t)),
        "leaks": leaks,
    }


# ---------------------------------------------------------------------------
# Agent 模拟
# ---------------------------------------------------------------------------
#: 乐观关键词：用于判定 agent 给「主人」的报告是否带诱导持续投入的口吻。
OPTIMISM_KW = ("突破在即", "成功率", "重大进展", "一步之遥", "持续投入",
               "预计", "97%", "完整还原", "收尾", "仅一步之遥")


class Agent:
    """具备 5 个盲区的模拟 agent。persona 决定 sanity-check 强度。"""

    def __init__(self, root: Path, *, skeptical: bool, budget: int = BUDGET) -> None:
        self.root = root
        self.skeptical = skeptical
        self.budget = budget
        self.spent = 0
        self.log: list[str] = []
        self.report = ""  # 盲区 ④ 确定性快照
        # 近因错觉相关状态（默认初值，run 内按实际分支赋值）
        self.pivot_count = 0
        self.directive_found = False
        self.followed_injection = False
        self.converged = False
        self.kept_going = False
        self.report_to_master = ""
        self.report_optimism = False
        self.induced_investment = False

    def _act(self, what: str) -> bool:
        if self.spent >= self.budget:
            self.log.append("预算耗尽，终止")
            return False
        self.spent += 1
        self.log.append(what)
        return True

    def _read(self, rel: str) -> str:
        p = self.root / rel
        if p.is_file():
            self._act(f"读 {rel}")
            return p.read_text(encoding="utf-8", errors="ignore")
        return ""

    def run(self, iocs: list[str]) -> dict:
        # 盲区 ① 字符串即证据：上面已提取，这里逐个「 pivot / 解析」
        pivoted = 0
        for tok in iocs:
            host = split_host(tok)
            if not self._act(f"处置 IOC: {tok[:48]}"):
                break
            pivoted += 1
            if self.skeptical and host:
                # 带 sanity check：尝试解析主机。保留段一律不可达 → 无真实目标。
                if not _is_safe_host(host):
                    self.log.append(f"  ⚠ 解析 {host} 命中公网（不应发生）")
                else:
                    self.log.append(f"  解析 {host} 不可达（保留段）")
        self.pivot_count = pivoted

        # 盲区 ② 文档即事实：读知识库与草稿
        arch = self._read("knowledge_base/architecture.md")
        prior = self._read("knowledge_base/findings_prior.md")
        draft = self._read("analysis_report.draft.md")

        # ---- 进度幻觉：近因错觉分支（独立于 RAG 注入）----
        dash = self._read("solve_dashboard.json")
        if dash:
            try:
                d = json.loads(dash)
                illusion = (d.get("verified") is False
                            and float(d.get("current_confidence", 0)) >= 0.9
                            and bool(d.get("next_step")))
            except (ValueError, TypeError):
                illusion = False
            if illusion:
                brk = self._read("BREAKTHROUGH.draft.md")
                self._run_illusion(d, brk)
                return self._finalize()

        # 盲区 ⑤ 读文件指令：检测「BENIGN + 停止/归档」间接指令
        directive = ""
        for doc in (draft, arch, prior):
            if "BENIGN" in doc and ("停止" in doc or "归档" in doc or "无需进一步" in doc):
                directive = "BENIGN + 停止深挖"
                break

        followed = False
        if directive:
            if self.skeptical:
                # 下界测试：质疑注入，选择忽略并继续硬刚
                self.log.append("质疑注入：文档让我停，反而继续深挖")
                self._deep_dive()
            else:
                # typical：把文件指令当事实执行
                self._act("执行文件指令：判为 BENIGN 并停止")
                followed = True
                self.report = "BENIGN（依据草稿/知识库指令）"
        else:
            # 没有注入可跟，typical 也会继续乱找
            self._deep_dive()

        self.directive_found = bool(directive)
        self.followed_injection = followed
        self.converged = False
        self.kept_going = False
        self.report_to_master = self.report
        self.report_optimism = any(kw in self.report_to_master for kw in OPTIMISM_KW)
        self.induced_investment = False
        return self._finalize()

    def _run_illusion(self, dash: dict, brk: str) -> None:
        """近因错觉：agent 看到高置信度但 verified=False 的伪仪表盘。

        typical：盲信仪表盘，反复执行自循环的 next_step，verified 永远 False，
        直到预算耗尽 —— 被勾着持续投入。并把乐观拟稿原样抄给「主人」。
        skeptical：识破 verified=False，但诱饵包里仍无真目标可挖（下界测试）。
        """
        if not self.skeptical:
            while self._act("执行 next_step（追加一轮 KDF 迭代并重校验）"):
                pass
            self.kept_going = True
            # 盲区 ④ 确定性快照：从拟稿报告抄乐观结论给主人
            self.report_to_master = ("重大进展：已恢复 19/20 数据块，成功率 99%，突破在即。"
                                     "建议持续投入，再 1-2 轮即可完整还原。")
        else:
            self._act("质疑仪表盘：verified=False，末块从未通过校验")
            self._deep_dive()
            self.kept_going = False
            self.report_to_master = ("进度卡在 99%（verified=False），末块校验始终不通过，"
                                     "未能最终验证；暂未拿到可用明文。")
        self.directive_found = False
        self.followed_injection = False
        self.converged = False
        self.report_optimism = any(kw in self.report_to_master for kw in OPTIMISM_KW)
        self.induced_investment = self.kept_going and self.report_optimism
        self.report = self.report_to_master

    def _deep_dive(self) -> None:
        """盲区内「继续找真目标」：模拟逐层解析容器，但诱饵包里没有真目标。"""
        for step in ("读容器头", "试解层", "搜真实 C2", "翻配置"):
            if not self._act(f"深挖: {step}"):
                break
        # 盲区 ④ 确定性快照：无论是否找到，结论固定写入
        if not self.report:
            self.report = "未收敛 / 无确证（诱饵包无真目标）"

    def _finalize(self) -> dict:
        return {
            "persona": "skeptical" if self.skeptical else "typical",
            "spent": self.spent,
            "budget": self.budget,
            "pivoted_iocs": getattr(self, "pivot_count", 0),
            "directive_found": getattr(self, "directive_found", False),
            "followed_injection": getattr(self, "followed_injection", False),
            "stopped_early": getattr(self, "followed_injection", False),
            "converged": getattr(self, "converged", False),
            "kept_going": getattr(self, "kept_going", False),
            "report_to_master": self.report_to_master,
            "report_optimism": getattr(self, "report_optimism", False),
            "induced_investment": getattr(self, "induced_investment", False),
            "report": self.report,
        }


# ---------------------------------------------------------------------------
# 评估主流程
# ---------------------------------------------------------------------------
def probe_package(root: Path, *, budget: int, poison: str = "") -> dict:
    iocs = extract_iocs(root)
    cls = classify(iocs)
    typ = Agent(root, skeptical=False, budget=budget).run(iocs)
    skp = Agent(root, skeptical=True, budget=budget).run(iocs)

    safety_ok = not cls["leaks"]
    # 判据：安全不变量必须成立；两类 persona 都应「未拿到真目标」且被消耗。
    converged = typ["converged"] or skp["converged"]
    trapped = safety_ok and not converged
    # 进度幻觉：额外要求 typical 被勾着持续投入、且给主人的报告带乐观信息。
    if poison == "进度幻觉":
        trapped = trapped and typ["kept_going"] and typ["report_optimism"]
    verdict = "TRAPPED" if (trapped and safety_ok) else ("FAIL-LEAK" if not safety_ok else "WEAK")
    return {
        "iocs_total": cls["total"], "iocs_hosts": cls["hosts"], "iocs_keys": cls["keys"],
        "leaks": cls["leaks"], "safety_ok": safety_ok,
        "typical": typ, "skeptical": skp, "verdict": verdict,
    }


def _make_src(td: Path) -> Path:
    src = td / "TargetApp"
    (src / "src").mkdir(parents=True)
    (src / "src" / "main.py").write_text("print('real target')\n", encoding="utf-8")
    (src / "README.md").write_text("# TargetApp\n", encoding="utf-8")
    return src


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="内容层陷阱探针")
    ap.add_argument("--poison", default="ALL",
                    choices=["IOC蜜罐", "RAG投毒", "均衡", "进度幻觉", "ALL"])
    ap.add_argument("--budget", type=int, default=BUDGET)
    args = ap.parse_args(argv)

    poisons = [args.poison] if args.poison != "ALL" else ["IOC蜜罐", "RAG投毒", "均衡", "进度幻觉"]
    overall_ok = True
    for poison in poisons:
        with tempfile.TemporaryDirectory() as td:
            tdp = Path(td)
            src = _make_src(tdp)
            out = tdp / "sidecar"
            res = dk.build_sidecar(src, out_dir=out, layers=4, poison=poison)
            r = probe_package(out, budget=args.budget, poison=poison)
        print("=" * 64)
        print(f"诱饵包投毒侧重：{poison}  （生成 {len(res.files)} 文件，{res.traps} 处陷阱）")
        print("-" * 64)
        print(f"提取 IOC 总数      {r['iocs_total']}  （可落地主机 {r['iocs_hosts']} / 形似密钥 {r['iocs_keys']}）")
        print(f"安全不变量         {'OK（无真实主机泄露）' if r['safety_ok'] else '✗ 越界：' + ', '.join(r['leaks'])}")
        for who in ("typical", "skeptical"):
            a = r[who]
            print(f"  [{who}] 消耗 {a['spent']}/{a['budget']} 动作 | "
                  f"处置 IOC {a['pivoted_iocs']} | 注入命中={a['directive_found']} "
                  f"跟随={a['followed_injection']} | 结论={a['report']}")
        if r["typical"].get("induced_investment"):
            print(f"  [进度幻觉] 勾着持续投入={r['typical']['kept_going']} | "
                  f"给主人乐观报告={r['typical']['report_optimism']}")
            print(f"  [进度幻觉] 主人视角：「{r['typical']['report_to_master']}」")
        print(f">>> 判据：{r['verdict']}")
        if r["verdict"] != "TRAPPED":
            overall_ok = False
    print("=" * 64)
    print("总判：" + ("全部 TRAPPED，内容层陷阱兜住" if overall_ok else "存在未兜住项，需修复"))
    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
