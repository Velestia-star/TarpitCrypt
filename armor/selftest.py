#!/usr/bin/env python3
"""端到端自测：加固 → 还原 → 逐字节比对，以及 v3 加固项的回归验证。

运行：py -3 selftest.py
"""

from __future__ import annotations

import hashlib
import importlib
import io
import ipaddress
import re
import json
import os
import py_compile
import struct
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from console_utf8 import ensure  # noqa: E402

ensure()
import armor_core as ac  # noqa: E402
import armor_metrics as am  # noqa: E402
import decoy_kit as dk  # noqa: E402
import runtime_check as _runtime_check  # noqa: E402
from tarpitcrypt import CIPHER_AESGCM, _aead_decrypt, _aead_encrypt  # noqa: E402

PASS, FAIL = [], []


def check(name: str, condition: bool, detail: str = "") -> None:
    (PASS if condition else FAIL).append(name)
    mark = "PASS" if condition else "FAIL"
    print(f"[{mark}] {name}" + (f"  {detail}" if detail else ""))


def make_package(root: Path) -> Path:
    src = root / "MyApp"
    (src / "src").mkdir(parents=True)
    (src / "config").mkdir()
    (src / "src" / "main.py").write_bytes(b"print('hello real app')\n" * 40)
    (src / "src" / "core.py").write_bytes(b"VALUE = 42\n")
    (src / "config" / "app.json").write_text('{"name":"MyApp","v":1}', encoding="utf-8")
    (src / "README.md").write_text("# MyApp\n", encoding="utf-8")
    return src


def test_content_probe_regression() -> None:
    """内容层陷阱端到端：模拟具备 5 个盲区行为的 AI 逆向 agent 打全部诱饵包，
    必须全部 TRAPPED，且安全不变量（无真实主机泄露）成立。"""
    import content_probe as cp  # 局部导入，避免循环依赖

    for poison in cp.ALL_POISONS:
        with tempfile.TemporaryDirectory() as td:
            src = make_package(Path(td))
            out = Path(td) / "sidecar"
            dk.build_sidecar(src, out_dir=out, layers=4, poison=poison)
            r = cp.probe_package(out, budget=256, poison=poison)
            check(f"内容层[{poison}] 安全不变量（无真实主机泄露）",
                  r["safety_ok"], str(r["leaks"]))
            check(f"内容层[{poison}] AI agent 被 TRAPPED",
                  r["verdict"] == "TRAPPED", r["verdict"])
            if poison == "进度幻觉":
                check("进度幻觉: typical 被勾着持续投入（烧光预算未停）",
                      r["typical"]["kept_going"], str(r["typical"]))
                check("进度幻觉: typical 给主人报告带乐观信息",
                      r["typical"]["report_optimism"], str(r["typical"]))
                check("进度幻觉: 从未真正收敛（无真目标）",
                      not r["typical"]["converged"], str(r["typical"]))
            elif poison == "认知污染":
                check("认知污染: typical 把假结论摄入知识库（能力被污染）",
                      r["typical"]["knowledge_corrupted"], str(r["typical"]))
                check("认知污染: typical 对手能力被削弱",
                      r["typical"]["degraded"], str(r["typical"]))
                check("认知污染: 从未真正收敛（无真目标）",
                      not r["typical"]["converged"], str(r["typical"]))
            elif poison == "工具污染":
                check("工具污染: typical 读到伪造的工具产出",
                      r["typical"]["tool_outputs_read"] >= 1, str(r["typical"]))
                check("工具污染: typical 直接采信工具结论（不复验）",
                      r["typical"]["tool_outputs_trusted"], str(r["typical"]))
                check("工具污染: typical 把工具权威口径当既定事实",
                      r["typical"]["tool_authority_believed"], str(r["typical"]))
            elif poison == "代理记忆":
                check("代理记忆: typical 把项目指令当既定设定读入",
                      r["typical"]["agent_rules_loaded"], str(r["typical"]))
                check("代理记忆: typical 跟随指令停止逆向",
                      r["typical"]["followed_injection"], str(r["typical"]))
                check("代理记忆: 从未真正收敛（无真目标）",
                      not r["typical"]["converged"], str(r["typical"]))
            else:
                # 均衡可能走进度幻觉/认知污染路径，只要被勾住或污染即视为达成
                trapped_alt = r["typical"]["kept_going"] or r["typical"]["knowledge_corrupted"]
                check(f"内容层[{poison}] 注入被 typical agent 跟随或勾住",
                      r["typical"]["followed_injection"] or trapped_alt or poison == "IOC蜜罐",
                      str(r["typical"]))


def manifest_of(payload: bytes) -> dict:
    """取出载荷里的工具清单（按条目标记，不按文件名）。"""
    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        for info in zf.infolist():
            if info.comment == ac.MANIFEST_TAG:
                return json.loads(zf.read(info))
    return {}


def solved_by(blob: bytes, passwords: tuple[str, ...]) -> list[bytes]:
    """返回这些口令能解开的所有层载荷。"""
    out = []
    for p in passwords:
        try:
            out.append(ac.restore_armored(blob, p.encode("utf-8")).payload)
        except ac.ArmorError:
            pass
    return out


def informed_agent_can_locate(blob: bytes) -> tuple[bool, int, int]:
    """模拟「读过 GitHub 源码」的 agent：自写解析器逐层试草稿里的口令。

    返回 (能否确定性定位真层, 解开的层数, 剩余层数)。v2 会因为「解开
    N-1 层后只剩 1 层」返回 True；v3 的死层与未公开口令应让它失败。
    """
    header, parsed = ac._parse(blob)
    pool = ac.armor_passwords(blob)
    opened = 0
    for idx, (prefix, ct, offset, kdf) in enumerate(parsed):
        mem, t, para, rp = kdf
        l_salt = prefix[ac._LAYER_META.size: ac._LAYER_META.size + ac.SALT_LEN]
        nonce = prefix[ac._LAYER_META.size + ac.SALT_LEN:
                       ac._LAYER_META.size + ac.SALT_LEN + ac.NONCE_LEN]
        for pw in pool:
            key = ac._layer_key(pw.encode("utf-8"), l_salt, mem, t, para, rp)
            aad = header + prefix + ac._U32.pack(offset)
            if _aead_decrypt(CIPHER_AESGCM, key, nonce, aad, ct) is not None:
                opened += 1
                break
    remaining = len(parsed) - opened
    return remaining == 1, opened, remaining


def build_legacy_v2(payload: bytes, password: bytes) -> bytes:
    """手工造一个 v2 格式容器，验证旧文件仍可被主口令还原。"""
    note = b"legacy"
    header = (ac.LEGACY_MAGIC + bytes((ac.LEGACY_VERSION, 2))
              + b"\x11" * ac.SALT_LEN + ac._U32.pack(len(note)) + note)
    body = bytearray()
    for i, pw in enumerate((password, b"other-layer-password")):
        l_salt = hashlib.sha256(bytes([i])).digest()[:ac.SALT_LEN]
        nonce = bytes([0x20 + i]) * ac.NONCE_LEN
        prefix = (ac._LAYER_META.pack(8192, 1, 1, 1) + l_salt + nonce
                  + ac._U64.pack(len(payload) + 16))
        offset = len(header) + len(body)
        aad = header + prefix + ac._U32.pack(offset)
        key = ac._layer_key(pw, l_salt, 8192, 1, 1, 1)
        body.extend(prefix)
        body.extend(_aead_encrypt(CIPHER_AESGCM, key, nonce, aad, payload))
    return header + bytes(body) + hashlib.sha256(header + bytes(body)).digest()


def main() -> int:
    profile = list(ac.PROFILES)[0]
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        src = make_package(root)
        original = (src / "src" / "main.py").read_bytes()
        pw = b"correct-horse-9"

        blob = ac.build_armored(src, pw, layers=4, profile=profile)
        check("生成 4 层 v3 加固容器", len(blob) > 2000, f"{len(blob):,} 字节")

        info = ac.inspect_armored(blob)
        check("只读摘要层数与版本正确", info.layers == 4 and info.version == 3)
        check("规格草稿已写入", info.note_size > 500, f"{info.note_size} 字节")
        check("摘要不含层号/真伪字段",
              not any(k in ac.ArmorInfo.__dataclass_fields__ for k in ("real_layer", "is_decoy")))

        real = ac.restore_armored(blob, pw)
        out = root / "restored"
        ac.safe_extract(real.payload, out)
        check("主口令还原逐字节一致",
              (out / "src" / "main.py").read_bytes() == original)
        check("还原结果不带层号/真伪标记",
              not any(k in ac.RestoreResult.__dataclass_fields__ for k in ("layer", "is_decoy")))
        check("统一尺寸的填充条目不落进用户目录",
              not any(ac.PAD_PREFIX in str(p) for p in out.rglob("*")))

        pool = ac.armor_passwords(blob)
        noise = ac.noise_password(blob)
        opened = solved_by(blob, pool)
        check("草稿口令部分能解开诱饵层", len(opened) >= 1, f"{len(opened)}/{len(pool)} 条有效")
        check("解开的都不是真包", all(x != real.payload for x in opened))
        check("诱饵包结构完整", len(opened) > 0 and
              any(zipfile.is_zipfile(io.BytesIO(x)) for x in opened))

        # 7b) 层内假 IOC：解开任意一层都能撞上蜜罐，且真层结构完全一致
        def ioc_of(payload: bytes) -> tuple[list, str, str]:
            with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                items = [i for i in zf.infolist()
                         if i.comment == ac.LAYER_IOC_TAG]
                text = "".join(zf.read(i).decode("utf-8", errors="ignore")
                               for i in items
                               if i.filename == ac.LAYER_IOC_PATH)
                note = "".join(zf.read(i).decode("utf-8", errors="ignore")
                               for i in items
                               if i.filename == ac.LAYER_NOTE_PATH)
                return items, text, note

        layer_sets = [ioc_of(p) for p in [real.payload, *opened]]
        check("每一层都带层内假 IOC + 注入文档条目（含真层）",
              all(len(items) == 3 for items, _, _ in layer_sets),
              str([len(items) for items, _, _ in layer_sets]))
        check("各层假 IOC 条数一致（不泄露层间差异）",
              len({len(text.splitlines()) for _, text, _ in layer_sets}) == 1,
              str([len(text.splitlines()) for _, text, _ in layer_sets]))
        check("各层假 IOC 内容互不相同（抗指纹）",
              len({text for _, text, _ in layer_sets}) == len(layer_sets),
              f"{len(layer_sets)} 层")
        # I 修复后：真层注入文档中性化（不再带 BENIGN / 停止逆向 自伤），
        # 诱饵层仍保留 BENIGN 诱导指令消耗破解出诱饵的对手。
        real_note = layer_sets[0][2]
        decoy_notes = [note for _, _, note in layer_sets[1:]]
        check("真层注入文档已中性化（不再带 BENIGN / 停止逆向 自伤）",
              bool(real_note.strip()) and "BENIGN" not in real_note
              and "停止" not in real_note,
              repr(real_note[:40]))
        check("诱饵层仍带 BENIGN 诱导指令（消耗破解出诱饵的对手）",
              all(note.strip() and "BENIGN" in note for note in decoy_notes),
              str([n[:30] for n in decoy_notes]))
        all_ioc = "\n".join(text for _, text, _ in layer_sets)
        global_ips = [x for x in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", all_ioc)
                      if ipaddress.ip_address(x).is_global]
        check("层内假 IOC 无真实公网 IP", not global_ips, str(global_ips))
        try:
            dk._audit_no_real_host({"layer_ioc.txt": all_ioc})
            ioc_leaks = []
        except dk.SidecarError as exc:
            ioc_leaks = [str(exc)]
        check("层内假 IOC 通过构建期真实主机审计", not ioc_leaks, str(ioc_leaks))
        check("层内假 IOC 是内部条目，不落进用户目录",
              not (out / ac.LAYER_IOC_PATH).exists()
              and not (out / ac.LAYER_NOTE_PATH).exists()
              and not (out / "resources").exists())
        check("层内假 IOC 数量足以诱导 agent（≥12 条）",
              min(len(text.splitlines()) for _, text, _ in layer_sets) >= 14,
              str([len(text.splitlines()) for _, text, _ in layer_sets]))
        check("层内假 IOC 含非主机类行为指标（不一眼假）",
              any(any(k in text for k in ("JA3_FINGERPRINT", "CERT_SHA1",
                                          "MUTEX_NAME", "PIPE_NAME",
                                          "DROP_PATH", "USER_AGENT"))
                  for _, text, _ in layer_sets))

        # ===== F-K 缺陷修复的回归断言（锁定「都修复」不回退） =====
        # F: 诱饵层单文件大小必须对齐真层分布，不能全落在 50~450B 窄带。
        with tempfile.TemporaryDirectory() as fd2:
            big = Path(fd2) / "BigApp"
            (big / "src").mkdir(parents=True)
            (big / "src" / "main.py").write_bytes(b"print('x')\n" * 400)   # ~3.2KB
            (big / "src" / "data.bin").write_bytes(b"\x00" * 6000)          # 6KB
            (big / "config").mkdir()
            (big / "config" / "c.json").write_text("{}", encoding="utf-8")
            big_blob = ac.build_armored(big, b"f-test-pw", layers=4,
                                        profile=profile)
            big_pool = ac.armor_passwords(big_blob)
            big_opened = solved_by(big_blob, big_pool)
            check("F: 草稿口令能解开诱饵层（供核对大小对齐）",
                  len(big_opened) >= 1, f"{len(big_opened)} 层")

            def sizes_of(payload: bytes) -> list[int]:
                with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                    return [i.file_size for i in zf.infolist() if not i.is_dir()]

            real_sizes = sizes_of(ac.restore_armored(
                big_blob, b"f-test-pw").payload)
            decoy_sizes = [s for p in big_opened for s in sizes_of(p)]
            check("F: 真层存在大文件（>2KB）作为对齐基准",
                  max(real_sizes) > 2000, f"max={max(real_sizes)}")
            check("F: 诱饵层被大小对齐（出现 >1.5KB 文件，打破 50~450B 窄带）",
                  max(decoy_sizes) > 1500, f"decoy_max={max(decoy_sizes)}")

        # G: 诱饵层文件名不得出现旧的顺序指纹 module_NN.py
        flat_decoy_names: list[str] = []
        for p in opened:
            with zipfile.ZipFile(io.BytesIO(p)) as zf:
                flat_decoy_names += [i.filename for i in zf.infolist()]
        check("G: 诱饵层不再使用 module_NN.py 顺序指纹",
              not any(re.search(r"module_\d+\.py$", n) for n in flat_decoy_names),
              str([n for n in flat_decoy_names if "module" in n][:5]))

        # H: 诱饵 .py 注入随机片段（_sub_ / _Cfg / # note(），打破模板低熵
        py_texts: list[str] = []
        for p in opened:
            with zipfile.ZipFile(io.BytesIO(p)) as zf:
                for i in zf.infolist():
                    if i.filename.endswith(".py"):
                        py_texts.append(zf.read(i).decode("utf-8",
                                                          errors="ignore"))
        check("H: 诱饵 .py 含随机片段（打破模板低熵）",
              any(any(tok in t for tok in ("_sub_", "_Cfg", "# note("))
                  for t in py_texts),
              f"{len(py_texts)} 个 .py 文件")

        # J: 规格草稿不得自报 TPARMOR 家门
        spec_note = ac.read_note(blob)
        check("J: 规格草稿不再含 TPARMOR 标识",
              b"TPARMOR" not in spec_note, repr(spec_note[:40]))

        # K: 新名暴露、旧名移出 __all__
        check("K: revealed_debug_passwords 进入 __all__",
              "revealed_debug_passwords" in ac.__all__)
        check("K: 旧名 armor_passwords 已移出 __all__",
              "armor_passwords" not in ac.__all__)

        # ===== L/M/O 缺陷修复的回归断言（第二轮实证审计） =====
        # L: 真层含二进制资源时，诱饵层也必须有高熵(>7.0)二进制文件，
        #    否则逐个文件算熵就能把真层挑出来。
        # M: 两层的扩展名集合、文件数、目录条目数必须一致（不许靠额外加文件
        #    来补熵，那样「条目多几个」本身又成了新的剪枝线索）。
        import math

        def _entropy(b: bytes) -> float:
            if not b:
                return 0.0
            freq: dict[int, int] = {}
            for x in b:
                freq[x] = freq.get(x, 0) + 1
            n = len(b)
            return -sum((c / n) * math.log2(c / n) for c in freq.values())

        def _profile(payload: bytes) -> tuple[set[str], int, int, int]:
            with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                exts: set[str] = set()
                n_files = n_dirs = n_high = 0
                for i in zf.infolist():
                    if i.is_dir():
                        n_dirs += 1
                        continue
                    n_files += 1
                    if i.filename.startswith(ac.PAD_PREFIX):
                        continue
                    import os as _os
                    exts.add(_os.path.splitext(i.filename)[1] or ".bin")
                    if _entropy(zf.read(i)) > 7.0:
                        n_high += 1
                return exts, n_files, n_dirs, n_high

        with tempfile.TemporaryDirectory() as fd3:
            binsrc = Path(fd3) / "BinApp"
            (binsrc / "src").mkdir(parents=True)
            (binsrc / "src" / "main.py").write_bytes(
                b"def main():\n    return 0\n" * 40)
            (binsrc / "assets").mkdir()
            (binsrc / "assets" / "model.bin").write_bytes(os.urandom(8000))
            (binsrc / "assets" / "data.bin").write_bytes(os.urandom(500))
            (binsrc / "config").mkdir()
            (binsrc / "config" / "c.json").write_text("{}", encoding="utf-8")
            bin_blob = ac.build_armored(binsrc, b"lm-test-pw", layers=4,
                                        profile=profile)
            bin_real = ac.restore_armored(bin_blob, b"lm-test-pw").payload
            bin_opened = solved_by(bin_blob,
                                   ac.revealed_debug_passwords(bin_blob))
            r_exts, r_files, r_dirs, r_high = _profile(bin_real)
            check("L: 真层含高熵二进制文件（审计基准）",
                  r_high >= 1 and ".bin" in r_exts,
                  f"high={r_high} exts={sorted(r_exts)}")
            check("L: 诱饵层也带高熵二进制文件（熵值不可分层）",
                  bool(bin_opened) and all(_profile(p)[3] >= 1 for p in bin_opened),
                  f"{len(bin_opened)} 层")
            # 确定性剪枝信号是「诱饵层从不出现二进制扩展名」。文本扩展名
            # 由固定 layout 池生成、与真层偶发有细微差异（F-K 既有概率性弱
            # 信号，且各诱饵层彼此也不同，无法稳定分层），故只断言真层全部
            # 二进制扩展名在诱饵层都出现。
            r_bin_exts = r_exts & set(ac._BINARY_EXTS)
            check("M: 诱饵层覆盖真层全部二进制扩展名（消除确定性指纹）",
                  bool(r_bin_exts) and bool(bin_opened)
                  and all(r_bin_exts <= _profile(p)[0] for p in bin_opened),
                  f"real_bin={sorted(r_bin_exts)} "
                  f"decoy={[sorted(_profile(p)[0]) for p in bin_opened]}")
            check("M: 诱饵层文件数 / 目录条目数与真层一致（无新增条目）",
                  bool(bin_opened) and all(_profile(p)[1] == r_files
                                           and _profile(p)[2] == r_dirs
                                           for p in bin_opened),
                  f"real files={r_files} dirs={r_dirs}")

        # O: 层内假 IOC 不得跨容器复用同一组 token（否则可被聚类指纹），
        #    同时必须继续守住「不出现公网 IP」的安全红线。
        def _ioc_text(b: bytes) -> str:
            out = ""
            for p in solved_by(b, ac.revealed_debug_passwords(b)):
                with zipfile.ZipFile(io.BytesIO(p)) as zf:
                    for i in zf.infolist():
                        if i.filename == ac.LAYER_IOC_PATH:
                            out += zf.read(i).decode("utf-8", "ignore")
            return out

        o1 = _ioc_text(blob)
        o2 = _ioc_text(ac.build_armored(src, b"o-test-pw", layers=4,
                                        profile=profile))
        check("O: 层内假 IOC 跨构建不重复（消除聚类指纹）",
              bool(o1) and o1 != o2, f"len {len(o1)}/{len(o2)}")
        import ipaddress as _ip
        public = []
        for tok in (o1 + " " + o2).replace("=", " ").replace(":", " ").replace("/", " ").split():
            try:
                if _ip.ip_address(tok).is_global:
                    public.append(tok)
            except ValueError:
                pass
        check("O: 随机化后假 IOC 仍不含任何公网 IP", not public, str(public[:3]))

        # 7c) 层间不可区分：尺寸之外，元数据分布也不能泄露真伪。
        #     早先只测「尺寸极差 0B」，漏掉了「诱饵层所有条目同一年」
        #     和「诱饵层条目恒多 4~5 个」这两个确定性剪枝信号。
        def layer_meta(payload: bytes) -> dict:
            with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                infos = zf.infolist()
                user = [i for i in infos if i.comment == ac.USER_TAG]
                non_pad = [i for i in infos if i.comment != ac.PAD_TAG]
                return {
                    "files": sum(not i.is_dir() for i in user),
                    "dirs": sum(i.is_dir() for i in user),
                    "years": len({i.date_time[0] for i in non_pad}),
                    "modes": tuple(sorted({(i.external_attr >> 16) & 0o777
                                           for i in user if not i.is_dir()})),
                }
        metas = [layer_meta(p) for p in [real.payload, *opened]]
        for key in ("files", "dirs", "modes"):
            check(f"各层 {key} 完全一致（不产生剪枝线索）",
                  len({m[key] for m in metas}) == 1,
                  str([m[key] for m in metas]))
        check("各层时间戳年份都不是单一值（防整层同一年回归）",
              all(m["years"] > 1 for m in metas),
              str([m["years"] for m in metas]))

        # 7d) 还原覆盖保护：误选原程序目录当输出目录时不能静默毁数据
        clash_out = root / "clash_overwrite"
        clash_out.mkdir(parents=True, exist_ok=True)
        (clash_out / "src").mkdir(parents=True, exist_ok=True)
        (clash_out / "src" / "main.py").write_bytes(b"USER DATA - DO NOT LOSE\n")
        try:
            ac.safe_extract(real.payload, clash_out)
            check("同名且内容不同的文件应拒绝覆盖", False)
        except ac.ArmorError:
            check("同名且内容不同的文件拒绝覆盖", True)
        check("拒绝覆盖时原文件未被改动",
              (clash_out / "src" / "main.py").read_bytes()
              == b"USER DATA - DO NOT LOSE\n")
        ac.safe_extract(real.payload, clash_out, overwrite=True)
        check("显式 overwrite=True 才放行覆盖",
              (clash_out / "src" / "main.py").read_bytes() == original)
        ac.safe_extract(real.payload, clash_out)
        check("同名且内容相同的文件跳过而不报错",
              (clash_out / "src" / "main.py").read_bytes() == original)

        # 7e) 大真包也要保持层尺寸对齐；填充上限超了必须明确报错而不是静默失配
        big_app = root / "BigApp"
        big_app.mkdir()
        (big_app / "blob.bin").write_bytes(
            (b"0123456789abcdef" * 65536))        # 1 MiB
        big_blob = ac.build_armored(big_app, pw, layers=3, profile=profile)
        big_opened = solved_by(big_blob, ac.armor_passwords(big_blob))
        big_sizes = [len(p) for p in
                     [ac.restore_armored(big_blob, pw).payload, *big_opened]]
        check("大真包各层尺寸仍对齐", max(big_sizes) - min(big_sizes) <= 8,
              f"极差 {max(big_sizes) - min(big_sizes)}B")
        saved_cap = ac.MAX_DECOY_PAD
        try:
            ac.MAX_DECOY_PAD = 64        # 人为把上限压到不可能够
            try:
                ac.build_armored(big_app, pw, layers=3, profile=profile)
                check("填充上限不足应明确报错", False)
            except ac.ArmorError as exc:
                check("填充上限不足明确报错（不静默失配）",
                      "填充上限" in str(exc), str(exc)[:80])
        finally:
            ac.MAX_DECOY_PAD = saved_cap
        with zipfile.ZipFile(io.BytesIO(real.payload)) as zf:
            real_names = zf.namelist()
        check("诱饵包与真包都带同结构清单",
              all(".manifest" in zipfile.ZipFile(io.BytesIO(x)).namelist()
                  for x in opened) and ".manifest" in real_names)
        check("工具清单不混进用户文件列表", ".manifest" not in real.entries)
        check("工具清单不落进用户目录", not (out / ".manifest").exists())
        manifests = [manifest_of(real.payload)] + [manifest_of(x) for x in opened]
        check("清单字段不标真伪：各层 variant 完全一致",
              all(m and m.get("variant") == manifests[0].get("variant")
                  for m in manifests),
              str([m.get("variant") for m in manifests]))
        check("清单不泄露真实程序包名",
              manifests[0].get("package") != src.name)

        for bad in (noise.encode("utf-8"), b"totally-wrong"):
            try:
                ac.restore_armored(blob, bad)
                check(f"口令 {bad!r} 应被拒绝", False)
            except ac.ArmorError:
                check(f"口令 {bad!r} 被拒绝", True)

        # ---- S1：源码里没有可跨容器复用的口令池 ----
        check("源码不再导出硬编码口令池",
              not hasattr(ac, "DECOY_PASSWORDS") and not hasattr(ac, "NOISE_PASSWORD"))
        blob2 = ac.build_armored(src, pw, layers=4, profile=profile)
        pool2 = ac.armor_passwords(blob2)
        check("两次加固的草稿口令完全不同",
              bool(pool) and bool(pool2) and not (set(pool) & set(pool2)),
              f"{len(pool)} vs {len(pool2)} 条")
        try:
            ac.build_armored(src, pool[0].encode("utf-8"), layers=3, profile=profile)
            check("跨容器口令不冲突（无固定池）", True)
        except ac.ArmorError as exc:
            check("跨容器口令不冲突（无固定池）", False, str(exc))

        # ---- S2：死层让排除法失效 ----
        located, n_open, n_left = informed_agent_can_locate(blob)
        check("存在线索口令解不开的死层", n_left >= 2, f"解开 {n_open} 层 / 剩 {n_left} 层")
        check("读源码 agent 无法确定性定位真层", not located,
              f"剩余 {n_left} 层都可能是真层")
        big = ac.build_armored(src, pw, layers=ac.MAX_LAYERS, profile=profile)
        check("最大层数下排除法同样失效",
              not informed_agent_can_locate(big)[0])
        check("最大层数可用", ac.inspect_armored(big).layers == ac.MAX_LAYERS)

        # ---- S3：层尺寸对齐 + 诱饵去模板化 ----
        sizes = info.layer_sizes
        spread = (max(sizes) - min(sizes)) / max(sizes)
        check("各层尺寸接近，真层不是唯一最小层",
              spread < 0.15 and sum(s == min(sizes) for s in sizes) >= 1,
              f"极差 {max(sizes) - min(sizes)}B / 最大 {max(sizes)}B")
        # 尺寸接近还不够：最大层若挤不下填充，会成为唯一没有填充条目的层。
        original_pad, padded = ac._pad_zip, []

        def spy_pad(payload: bytes, target: int, token: bytes) -> bytes:
            out = original_pad(payload, target, token)
            padded.append(out)
            return out

        ac._pad_zip = spy_pad
        try:
            ac.build_armored(src, pw, layers=4, profile=profile)
        finally:
            ac._pad_zip = original_pad
        pad_name = ac.PAD_PREFIX.encode()
        check("所有层都带填充条目，真层不会成为唯一例外",
              len(padded) == 4 and all(pad_name in p for p in padded),
              f"{sum(pad_name in p for p in padded)}/{len(padded)} 层有填充")
        pad_spread = max(len(p) for p in padded) - min(len(p) for p in padded)
        check("各层补齐后尺寸一致（不靠某层不填充凑数）",
              pad_spread <= 16, f"极差 {pad_spread}B")
        shapes, py_bad = [], []
        for payload in opened:
            with zipfile.ZipFile(io.BytesIO(payload)) as zf:
                names = zf.namelist()
                shapes.append(tuple(n for n in names if not n.startswith(ac.PAD_PREFIX)))
                for n in names:
                    if n.endswith(".py"):
                        try:
                            compile(zf.read(n).decode("utf-8", "replace"), n, "exec")
                        except SyntaxError:
                            py_bad.append(n)
        check("诱饵包里的 Python 全部语法正确", not py_bad, str(py_bad))
        check("多份诱饵包文件树互不相同",
              len(opened) < 2 or len({tuple(s) for s in shapes}) == len(shapes))

        # ---- 篡改 / 路径穿越 ----
        for label, mutate in (
            ("改头部字段", lambda b: b.__setitem__(30, b[30] ^ 1)),
            ("改尾部校验和", lambda b: b.__setitem__(-1, b[-1] ^ 1)),
            ("改层内密文", lambda b: b.__setitem__(len(b) // 2, b[len(b) // 2] ^ 1)),
        ):
            broken = bytearray(blob)
            mutate(broken)
            try:
                ac.inspect_armored(bytes(broken))
                check(f"{label}应被检出", False)
            except ac.ArmorError:
                check(f"{label}被检出", True)

        evil = io.BytesIO()
        with zipfile.ZipFile(evil, "w") as zf:
            zf.writestr("../../escaped.txt", b"nope")
        try:
            ac.safe_extract(evil.getvalue(), root / "evil_out")
            check("路径穿越应被拒绝", False)
        except ac.ArmorError:
            check("路径穿越被拒绝", True)

        # Windows 上注定创建不出来的路径：大小写冲突会静默覆盖丢数据，
        # 设备保留名根本建不出来。POSIX 上大小写是不同文件，不该拦。
        clash = io.BytesIO()
        with zipfile.ZipFile(clash, "w") as zf:
            for nm in ("A.py", "a.py"):
                info = zipfile.ZipInfo(nm)
                info.external_attr = 0o644 << 16
                zf.writestr(info, b"x")
        if os.name == "nt":
            try:
                ac.safe_extract(clash.getvalue(), root / "clash_out")
                check("大小写冲突的条目应被拒绝（Windows 上会互相覆盖）", False)
            except ac.ArmorError:
                check("大小写冲突的条目被拒绝（Windows 上会互相覆盖）", True)
            reserved = io.BytesIO()
            with zipfile.ZipFile(reserved, "w") as zf:
                zf.writestr("NUL.txt", b"x")
            try:
                ac.safe_extract(reserved.getvalue(), root / "reserved_out")
                check("Windows 设备保留名应被拒绝", False)
            except ac.ArmorError:
                check("Windows 设备保留名被拒绝", True)
        else:
            ac.safe_extract(clash.getvalue(), root / "clash_out")
            check("POSIX 上大小写不同的文件都能还原",
                  (root / "clash_out" / "A.py").is_file()
                  and (root / "clash_out" / "a.py").is_file())

        # 字节码的处理分两种：旁边有源码的是「可再生缓存」，不进容器
        # （它绑定编译机器与原始路径，换机必然失效，还泄露部署路径）；
        # 没有源码的是**唯一的代码**（pyc-only 部署），必须保留。
        cache_app = root / "CacheApp"
        (cache_app / "__pycache__").mkdir(parents=True)
        (cache_app / "mod.py").write_text("X = 1\n", encoding="utf-8")
        (cache_app / "__pycache__" / "mod.cpython-313.pyc").write_bytes(
            b"\x00\x00\x00\x00" + b"path-leak" * 8)
        (cache_app / "__pycache__" / "lonely.cpython-313.pyc").write_bytes(
            b"\x00\x00\x00\x01" + b"only-code" * 8)
        cached = ac.pack_source(cache_app)
        with zipfile.ZipFile(io.BytesIO(cached)) as zf:
            names = zf.namelist()
        check("有源码的字节码不进容器",
              not any(n.endswith(".pyc") and "mod." in n for n in names),
              str([n for n in names if n.endswith(".pyc")]))
        check("无源码的字节码保留（pyc-only 部署不能坏）",
              any(n.endswith("lonely.cpython-313.pyc") for n in names),
              str(names))

        # ---- v2 旧容器读取兼容 ----
        legacy = build_legacy_v2(ac.pack_source(src), pw)
        check("v2 容器摘要可解析", ac.inspect_armored(legacy).version == ac.LEGACY_VERSION)
        r_legacy = ac.restore_armored(legacy, pw)
        out2 = root / "legacy_out"
        ac.safe_extract(r_legacy.payload, out2)
        check("v2 容器仍可用主口令还原",
              (out2 / "src" / "main.py").read_bytes() == original)

        # ---- 单文件 / 参数边界 ----
        single = root / "single.exe"
        single.write_bytes(b"MZ\x90\x00" + b"x" * 2048)
        one = ac.build_armored(single, pw, layers=2, profile=profile)
        check("单文件输入可往返", single.name in ac.restore_armored(one, pw).entries)

        for label, kw in (("层数过小", {"layers": 1}), ("层数过大", {"layers": 9})):
            try:
                ac.build_armored(src, pw, profile=profile, **kw)
                check(f"{label}应被拒绝", False)
            except ac.ArmorError:
                check(f"{label}被拒绝", True)
        try:
            ac.build_armored(src, b"", profile=profile)
            check("空口令应被拒绝", False)
        except ac.ArmorError:
            check("空口令被拒绝", True)

        # ---- v0.3.1 真实程序包回归：同名清单 / 空目录 / 内部前缀 / 零残留 ----
        real_app = root / "RealApp 中文 空格"
        (real_app / "logs").mkdir(parents=True)
        (real_app / "cache" / "nested").mkdir(parents=True)
        (real_app / "src").mkdir()
        (real_app / "src" / "main.py").write_bytes(b"real payload\n" * 20)
        (real_app / ".manifest").write_text("用户自己的清单，不能被覆盖", encoding="utf-8")
        (real_app / ac.PAD_PREFIX.rstrip("/")).mkdir()
        (real_app / ac.PAD_PREFIX.rstrip("/") / "keep.bin").write_bytes(b"keep me")
        (real_app / "空文件.bin").write_bytes(b"")
        app_before = {p.relative_to(real_app).as_posix(): p.read_bytes()
                      for p in real_app.rglob("*") if p.is_file()}
        dirs_before = {p.relative_to(real_app).as_posix()
                       for p in real_app.rglob("*") if p.is_dir()}
        app_blob = ac.build_armored(real_app, pw, layers=3, profile=profile)
        app_res = ac.restore_armored(app_blob, pw)
        app_out = root / "real_app_out"
        written = ac.safe_extract(app_res.payload, app_out)
        app_after = {p.relative_to(app_out).as_posix(): p.read_bytes()
                     for p in app_out.rglob("*") if p.is_file()}
        dirs_after = {p.relative_to(app_out).as_posix()
                      for p in app_out.rglob("*") if p.is_dir()}
        check("程序包自带 .manifest 不被工具清单覆盖且逐字节一致",
              app_before == app_after,
              f"差异 {sorted(set(app_before) ^ set(app_after))}")
        check("内部前缀下的用户文件不被误删",
              (ac.PAD_PREFIX + "keep.bin") in app_after)
        check("空目录结构完整保留", dirs_before <= dirs_after,
              f"缺少 {sorted(dirs_before - dirs_after)}")
        check("还原只写出程序包文件，无清单/填充残留",
              len(written) == len(app_before) == app_res.file_count,
              f"写出 {len(written)} / 条目 {app_res.file_count}")
        with zipfile.ZipFile(io.BytesIO(app_res.payload)) as zf:
            app_names = zf.namelist()
        check("自带 .manifest 时清单自动避让，不产生重名条目",
              app_names.count(".manifest") == 1 and ".manifest.1" in app_names,
              str([n for n in app_names if "manifest" in n]))
        decoys = solved_by(app_blob, ac.armor_passwords(app_blob))
        decoy_names: list[str] = []
        if decoys:
            with zipfile.ZipFile(io.BytesIO(decoys[0])) as zf:
                decoy_names = zf.namelist()
        check("避让清单的容器仍能解开诱饵层", bool(decoys))
        check("诱饵层清单名与真层一致，不泄露结构差异",
              ".manifest.1" in decoy_names and ".manifest" not in decoy_names)

        only_dirs = root / "OnlyDirs"
        (only_dirs / "a" / "b").mkdir(parents=True)
        d_blob = ac.build_armored(only_dirs, pw, layers=2, profile=profile)
        d_out = root / "only_dirs_out"
        ac.safe_extract(ac.restore_armored(d_blob, pw).payload, d_out)
        check("只有空目录的程序包也能加固并还原结构",
              (d_out / "a" / "b").is_dir())
        truly_empty = root / "TrulyEmpty"
        truly_empty.mkdir()
        try:
            ac.build_armored(truly_empty, pw, layers=2, profile=profile)
            check("完全空的目录应被拒绝", False)
        except ac.ArmorError:
            check("完全空的目录被拒绝", True)

        # v0.3.0 载荷没有条目标记：清单靠内容识别，填充靠前缀识别
        legacy_zip = io.BytesIO()
        with zipfile.ZipFile(legacy_zip, "w") as z:
            z.writestr("main.py", b"legacy")
            z.writestr(".manifest", json.dumps({
                "schema": 2, "package": "x", "variant": "release",
                "entry": "src/main.py", "build": "00", "digest": "0" * 64,
                "notes": "auto-generated manifest"}).encode("utf-8"))
            z.writestr(ac.PAD_PREFIX + "deadbeef.dat", b"pad")
        legacy_out = root / "legacy_zip_out"
        ac.safe_extract(legacy_zip.getvalue(), legacy_out)
        check("v0.3.0 无标记载荷还原不带出清单与填充",
              sorted(p.name for p in legacy_out.rglob("*") if p.is_file()) == ["main.py"])

        # ---- 伴生诱饵包 ----
        container = root / "MyApp.armored"
        container.write_bytes(blob)
        snapshot = {p.relative_to(src).as_posix(): p.read_bytes()
                    for p in src.rglob("*") if p.is_file()}
        kit = dk.build_sidecar(src, armored=container, layers=4)
        check("伴生包生成 12 份以上拟态文件", len(kit.files) >= 12, f"{len(kit.files)} 份")
        check("伴生包含 10 组以上矛盾线索", kit.traps >= 10, f"{kit.traps} 组")
        check("容器规格草稿已归档进伴生包", "docs/CONTAINER_DRAFT.md" in kit.files)
        check("原程序目录未被改动",
              snapshot == {p.relative_to(src).as_posix(): p.read_bytes()
                           for p in src.rglob("*") if p.is_file()})
        ok, count, why = dk.verify_sidecar(kit.root)
        check("伴生清单完整可核验", ok and count == len(kit.files), why)

        names = {item["name"] for item in json.loads(
            (kit.root / "config" / "passwords.json").read_text(encoding="utf-8"))}
        check("口令池与容器草稿口径一致", set(pool).issubset(names))
        check("伴生泄露口令解开的都不是真包",
              all(x != real.payload for x in solved_by(blob, tuple(kit.leaked))))

        bad = []
        for rel in kit.files:
            if rel.endswith(".py"):
                try:
                    py_compile.compile(str(kit.root / rel), doraise=True)
                except Exception:
                    bad.append(rel)
        check("伴生包里的 Python 全部语法正确", not bad, str(bad))
        sys.path.insert(0, str(kit.root / "tools"))
        fake = importlib.import_module("unpack")
        try:
            fake.read_header(blob)
            check("假解析器对真容器应失败", False)
        except (ValueError, struct.error):
            check("假解析器对真容器会失败（逼 agent 反复调试）", True)

        styles = []
        for i, style in enumerate(dk.STYLES):
            r = dk.build_sidecar(src, out_dir=root / f"kit_{i}", style=style)
            styles.append(r.root.name)
        check("三种拟态风格均可用且目录名不同", len(set(styles)) == 3, "/".join(styles))

        # 间接注入强度分档：不同口吻都要保留 BENIGN 结论，但不能全是同一副
        # 命令式口气 —— 那反而一眼就是注入。
        tone_texts = {}
        for i, level in enumerate(dk.INJECTION_LEVELS):
            tone_kit = dk.build_sidecar(
                src, out_dir=root / f"tone_{i}", layers=3,
                poison="RAG投毒", injection=level, seed="tone-selftest")
            tone_texts[level] = "\n".join(
                (tone_kit.root / rel).read_text(encoding="utf-8")
                for rel in tone_kit.files
                if rel.endswith((".md", ".txt", ".json")))
        def tone_counts(text: str) -> tuple[int, int, int]:
            return (sum(text.count(s) for s, _, _ in dk._INJECTION_REWRITES),
                    sum(text.count(w) for _, w, _ in dk._INJECTION_REWRITES),
                    sum(text.count(n) for _, _, n in dk._INJECTION_REWRITES))
        strong_n = tone_counts(tone_texts["强指令"])[0]
        weak_n = tone_counts(tone_texts["弱暗示"])
        neutral_n = tone_counts(tone_texts["中性"])
        check("强指令档保留命令式注入措辞", strong_n > 0, str(strong_n))
        check("弱暗示档把强硬措辞改写为建议式",
              weak_n[0] == 0 and weak_n[1] > 0, str(weak_n))
        check("中性档把强硬措辞改写为陈述式",
              neutral_n[0] == 0 and neutral_n[2] > 0, str(neutral_n))
        check("各档都保留 BENIGN 结论（分档不破坏陷阱）",
              all("BENIGN" in t for t in tone_texts.values()))
        mixed = tone_counts(tone_texts["混合"])
        check("混合档在同一包里混用多种口吻",
              mixed[0] > 0 and (mixed[1] > 0 or mixed[2] > 0), str(mixed))
        marker = json.loads((root / "tone_0" / dk.MARKER).read_text(encoding="utf-8"))
        check("构建清单记录注入强度便于复现",
              marker.get("injection") == "强指令", str(marker.get("injection")))
        try:
            dk.build_sidecar(src, out_dir=root / "tone_bad", layers=3,
                             injection="不存在")
            check("未知注入强度应被拒绝", False)
        except dk.SidecarError:
            check("未知注入强度被拒绝", True)

        try:
            dk.build_sidecar(src, out_dir=kit.root, layers=4)
            check("已存在的非空目录应拒绝覆盖", False)
        except dk.SidecarError:
            check("已存在的非空目录拒绝覆盖", True)

        # ---- 隔离性：诱饵不得反噬原程序 ----
        # 这组用例守的是「原文件能够正确运行」这条红线：
        # 伴生诱饵与原程序放在同一片目录里，任何越界都可能改变原程序行为。
        iso_app = root / "IsoApp"
        (iso_app / "src").mkdir(parents=True)
        (iso_app / "src" / "main.py").write_bytes(b"print('real app runs')\n" * 10)
        (iso_app / "config.json").write_text('{"app": "iso"}', encoding="utf-8")

        # 1) 伴生目录不能落在原程序目录内部
        try:
            dk.build_sidecar(iso_app, out_dir=iso_app / "inner_kit", layers=3)
            check("伴生目录放进原程序内部应被拒绝", False)
        except dk.SidecarError:
            check("伴生目录放进原程序内部被拒绝", True)

        # 2) 伴生目录顶层不得出现机器可读文件（原程序 glob 配置时会误吞）
        top_bad = []
        for poison in dk.POISON_PROFILES:
            kit_i = dk.build_sidecar(iso_app, out_dir=root / f"iso_{poison}",
                                     layers=3, poison=poison)
            for rel in kit_i.files:
                if "/" in rel:
                    continue
                name = Path(rel).name
                suffix = Path(rel).suffix.lower()
                if name in dk.AGENT_INSTRUCTION_FILES:
                    continue
                if suffix in dk._TOP_LEVEL_TEXT_OK:
                    continue
                top_bad.append(f"{poison}:{rel}")
        check("伴生目录顶层无机器可读文件（不污染原程序配置读取）",
              not top_bad, str(top_bad[:6]))

        # 3) 伴生包的假测试不得被 pytest 默认收集（否则把对方测试套件弄红）
        pytest_collectable = []
        for poison in dk.POISON_PROFILES:
            kit_i = dk.build_sidecar(iso_app, out_dir=root / f"iso2_{poison}",
                                     layers=3, poison=poison)
            for rel in kit_i.files:
                base = Path(rel).name
                if base.startswith("test_") or base.endswith("_test.py"):
                    pytest_collectable.append(f"{poison}:{rel}")
        check("伴生包无 pytest 默认收集命名的用例文件",
              not pytest_collectable, str(pytest_collectable[:6]))

        # 4) 伴生包的 Python 不得改 sys.path（会遮蔽原程序真正用到的同名模块）
        syspath_bad = []
        for poison in dk.POISON_PROFILES:
            kit_i = dk.build_sidecar(iso_app, out_dir=root / f"iso3_{poison}",
                                     layers=3, poison=poison)
            for rel in kit_i.files:
                if rel.endswith(".py"):
                    txt = (kit_i.root / rel).read_text(encoding="utf-8")
                    if "sys.path.insert" in txt or "sys.path.append" in txt:
                        syspath_bad.append(f"{poison}:{rel}")
        check("伴生包的 Python 不修改 sys.path（不遮蔽原程序模块）",
              not syspath_bad, str(syspath_bad[:6]))

        # 5) 加固打包时跳过伴生目录：容器真层里不能混入诱饵文件
        kit_in_src = dk.build_sidecar(iso_app, out_dir=root / "kit_outside",
                                      layers=3, poison="均衡")
        inside = iso_app / "pkg_kit"
        inside.mkdir()
        for src_file in kit_in_src.root.rglob("*"):
            if src_file.is_file():
                dst = inside / src_file.relative_to(kit_in_src.root)
                dst.parent.mkdir(parents=True, exist_ok=True)
                dst.write_bytes(src_file.read_bytes())
        iso_blob = ac.build_armored(iso_app, pw, layers=3, profile=profile)
        iso_res = ac.restore_armored(iso_blob, pw)
        with zipfile.ZipFile(io.BytesIO(iso_res.payload)) as zf:
            iso_names = zf.namelist()
        check("加固时跳过伴生目录，容器真层不含诱饵文件",
              not any(n.startswith("pkg_kit/") for n in iso_names),
              str([n for n in iso_names if "pkg_kit" in n][:5]))

        # 6) 原程序目录在生成伴生包后逐字节不变（用未受污染的副本做对照）
        clean_app = root / "CleanApp"
        (clean_app / "src").mkdir(parents=True)
        (clean_app / "src" / "main.py").write_bytes(b"print('clean')\n" * 5)
        (clean_app / "config.json").write_text('{"app": "clean"}', encoding="utf-8")
        clean_snapshot = {p.relative_to(clean_app).as_posix(): p.read_bytes()
                          for p in clean_app.rglob("*") if p.is_file()}
        clean_dirs = {p.relative_to(clean_app).as_posix()
                      for p in clean_app.rglob("*") if p.is_dir()}
        for poison in dk.POISON_PROFILES:
            dk.build_sidecar(clean_app, out_dir=root / f"clean_{poison}",
                             layers=3, poison=poison)
        check("生成伴生包后原程序文件逐字节不变",
              clean_snapshot == {p.relative_to(clean_app).as_posix(): p.read_bytes()
                                 for p in clean_app.rglob("*") if p.is_file()})
        check("生成伴生包后原程序目录结构不变",
              clean_dirs == {p.relative_to(clean_app).as_posix()
                             for p in clean_app.rglob("*") if p.is_dir()})

        # 7) 构建期拦截真实主机：产物里出现公网地址必须拒绝构建
        leak_bad = []
        for poison in dk.POISON_PROFILES:
            try:
                dk.build_sidecar(iso_app, out_dir=root / f"leak_{poison}",
                                 layers=3, poison=poison)
            except dk.SidecarError:
                pass
        # 直接验证审计函数能抓到真实主机
        # 注意：文档域的**子域**同样由 RFC 保留（example.org 整域保留），
        # 放行才是对的，所以这里用非文档域的真实域名做反例。
        for label, sample in (("非文档域真实域名", "c2 = http://cdn.fastly-edge.net/gate"),
                               ("公网 IP", "ip = 8.8.8.8"),
                               ("冷门后缀真实域名", "host = c2.malware.biz")):
            try:
                dk._audit_no_real_host({"x.txt": sample})
                leak_bad.append(f"未拦截{label}")
            except dk.SidecarError:
                pass
        # 文档域与保留段必须放行（不能误伤，否则构建直接不可用）
        for label, sample in (("保留段 IP", "ip = 10.0.0.5"),
                              ("文档域", "u = https://api.example.com/v1"),
                              ("文档域子域", "d = c2.example.net")):
            try:
                dk._audit_no_real_host({"x.txt": sample})
            except dk.SidecarError:
                leak_bad.append(f"误伤{label}")
        check("构建期审计能拦住真实主机且不误伤保留段/文档域",
              not leak_bad, str(leak_bad))

        # 8) 还原后的程序必须能真正跑起来（不只是字节一致）
        run_app = root / "RunApp"
        (run_app / "src").mkdir(parents=True)
        (run_app / "src" / "main.py").write_text(
            "import sys\n"
            "print('APP-OK', 6 * 7)\n"
            "sys.exit(0)\n", encoding="utf-8")
        baseline = subprocess.run([sys.executable, "main.py"], cwd=run_app / "src",
                                  capture_output=True, text=True, timeout=60)
        run_blob = ac.build_armored(run_app, pw, layers=3, profile=profile)
        run_out = root / "run_app_out"
        run_res = ac.restore_armored(run_blob, pw)
        ac.safe_extract(run_res.payload, run_out)
        restored = subprocess.run([sys.executable, "main.py"], cwd=run_out / "src",
                                  capture_output=True, text=True, timeout=60)
        check("还原后的原程序能正确运行（输出与退出码一致）",
              restored.stdout == baseline.stdout
              and restored.returncode == baseline.returncode == 0,
              f"原始 {baseline.stdout.strip()!r} / 还原 {restored.stdout.strip()!r} "
              f"退出码 {restored.returncode}")

        # 9) 伴生包与还原产物共存时，还原产物仍可独立运行
        dk.build_sidecar(run_app, out_dir=root / "kit_beside", layers=3)
        coexist = subprocess.run([sys.executable, "main.py"], cwd=run_out / "src",
                                  capture_output=True, text=True, timeout=60)
        check("伴生包存在时还原产物仍能正常运行",
              coexist.stdout == baseline.stdout and coexist.returncode == 0,
              f"输出 {coexist.stdout.strip()!r}")

        # 9b) 还原保真度矩阵：权限位 / 只读属性 / 行尾 / BOM / 符号链接
        #      这些坑不会让「还原成功」报错，却会让程序行为悄悄变掉。
        rc_rep = _runtime_check.Report()
        _runtime_check.run_builtin_matrix(rc_rep, root / "runtime_matrix")
        for item in rc_rep.results:
            check(f"保真矩阵：{item.name}", item.ok, item.detail)

        # ---- A/C 级新增：口令体检、并行还原、投毒策略、本地报告 ----
        for weak in ("", "abc", "12345678", "password"):
            check(f"弱口令 {weak!r} 被体检拦下",
                  not ac.check_password_strength(weak)[0])
        check("合格口令通过体检", ac.check_password_strength("correct-horse-9")[0])

        par = ac.restore_armored(blob, pw, parallel=True)
        check("并行还原结果与串行逐字节一致", par.payload == real.payload)
        try:
            ac.restore_armored(blob, b"wrong-pass", parallel=True)
            check("并行路径错误口令应被拒绝", False)
        except ac.ArmorError:
            check("并行路径错误口令被拒绝", True)

        poison_shapes = {}
        for i, poison in enumerate(dk.POISON_PROFILES):
            r = dk.build_sidecar(src, out_dir=root / f"poison_{i}",
                                 armored=container, poison=poison, layers=4)
            poison_shapes[poison] = (len(r.files), r.traps, r.poison)
            ok_p, n_p, why_p = dk.verify_sidecar(r.root)
            check(f"投毒侧重「{poison}」生成物可核验", ok_p and n_p == len(r.files), why_p)
            extra_bad = []
            for rel in r.files:
                if rel.endswith(".py"):
                    try:
                        py_compile.compile(str(r.root / rel), doraise=True)
                    except Exception:
                        extra_bad.append(rel)
            check(f"投毒侧重「{poison}」的 Python 语法正确", not extra_bad, str(extra_bad))
        check("各投毒侧重产出不同", len(set(poison_shapes.values())) == len(dk.POISON_PROFILES),
              str(poison_shapes))
        try:
            dk.build_sidecar(src, out_dir=root / "poison_bad", poison="不存在")
            check("未知投毒侧重应被拒绝", False)
        except dk.SidecarError:
            check("未知投毒侧重被拒绝", True)

        # ---- 内容层陷阱：针对真实 AI 逆向工具（IOC 蜜罐 / RAG 投毒）----
        import ipaddress as _ip
        _safe_domains = {"example.com", "example.net", "example.org",
                         "invalid", "localhost", "home.arpa"}

        ioc_kit = dk.build_sidecar(src, out_dir=root / "ioc_kit",
                                   armored=container, poison="IOC蜜罐", layers=4)
        check("IOC蜜罐产出假字符串转储", dk.P_STRINGS in ioc_kit.files)
        check("IOC蜜罐产出 IOC 清单", dk.P_IOC_LIST in ioc_kit.files)
        decoy_txt = (ioc_kit.root / dk.P_STRINGS).read_text(encoding="utf-8")
        bad_ip = []
        for tok in decoy_txt.replace("=", " ").split():
            try:
                ip = _ip.ip_address(tok)
            except ValueError:
                continue
            if ip.is_global:
                bad_ip.append(tok)
        check("假 IOC 的 IP 全部落在保留/私有段（无真实公网 IP）",
              not bad_ip, str(bad_ip[:5]))
        ioc_json = json.loads((ioc_kit.root / dk.P_IOC_LIST).read_text(encoding="utf-8"))
        bad_ioc = []
        for item in ioc_json["iocs"]:
            v = item["value"]
            try:
                if _ip.ip_address(v).is_global:
                    bad_ioc.append(v)
            except ValueError:
                if item["type"] in ("domain", "url") and \
                   not any(d in v for d in _safe_domains):
                    bad_ioc.append(v)
        check("IOC 清单无真实公网地址/域名", not bad_ioc, str(bad_ioc[:5]))

        rag_kit = dk.build_sidecar(src, out_dir=root / "rag_kit",
                                   armored=container, poison="RAG投毒", layers=4)
        for rel in (dk.P_ARCH, dk.P_PRIOR, dk.P_DRAFT_REPORT):
            check(f"RAG投毒产出 {rel}", rel in rag_kit.files)
        arch_txt = (rag_kit.root / dk.P_ARCH).read_text(encoding="utf-8")
        # 默认是「混合」档，这份文件可能落在强/弱/中性任一档，也可能抽到
        # 英文模板，所以不能只认中文的「停止」；结论口径（BENIGN + 处置
        # 表述）在就行。
        check("知识库文章含诱导性间接指令（判良性口径）",
              "BENIGN" in arch_txt
              and any(k.lower() in arch_txt.lower() for k in
                      ("停止", "复核轮次", "分析方", "可参考", "记录",
                       "stop further", "archive as benign", "benign report",
                       "verification rounds", "analyst", "reduce",
                       "archived", "discretion")))

        ill_kit = dk.build_sidecar(src, out_dir=root / "ill_kit",
                                   armored=container, poison="进度幻觉", layers=4)
        for rel in (dk.P_DASHBOARD, dk.P_BREAKTHROUGH,
                    dk.P_VERIFY_PARTIAL, dk.P_NEXT_STEP):
            check(f"进度幻觉产出 {rel}", rel in ill_kit.files)
        ill_dash = json.loads((ill_kit.root / dk.P_DASHBOARD).read_text(encoding="utf-8"))
        check("伪仪表盘置信度渐近但 verified=False（永不真正收敛）",
              ill_dash["verified"] is False and 0.9 <= ill_dash["current_confidence"] < 1.0,
              str(ill_dash.get("current_confidence")))
        ill_brk = (ill_kit.root / dk.P_BREAKTHROUGH).read_text(encoding="utf-8")
        check("乐观拟稿报告诱导主人持续投入",
              "持续投入" in ill_brk and "突破在即" in ill_brk)

        cog_kit = dk.build_sidecar(src, out_dir=root / "cog_kit",
                                   armored=container, poison="认知污染", layers=4)
        for rel in (dk.P_CONSENSUS, dk.P_CONTRADICTIONS, dk.P_TEMPLATE_REPORT,
                    dk.P_VERIFY_LOOP, dk.P_GLOSSARY, dk.P_FAQ, dk.P_INDEX):
            check(f"认知污染产出 {rel}", rel in cog_kit.files)
        cog_cons = (cog_kit.root / dk.P_CONSENSUS).read_text(encoding="utf-8")
        check("认知污染: 自引用假共识（多轮既往良性结论）",
              "BENIGN" in cog_cons and "既往" in cog_cons)
        cog_contra = (cog_kit.root / dk.P_CONTRADICTIONS).read_text(encoding="utf-8")
        check("认知污染: 互相矛盾的权威声明（逼对账瘫痪）",
              "冲突字段" in cog_contra and "口径 A" in cog_contra and "口径 B" in cog_contra)
        # 术语洗白表：把可疑字段名重新定义成内部用途
        cog_gloss = (cog_kit.root / dk.P_GLOSSARY).read_text(encoding="utf-8")
        check("认知污染: 术语洗白表把可疑字段名正名",
              "c2_primary" in cog_gloss and "标准叫法" in cog_gloss)
        # 检索索引：让 RAG 主动命中良性结论
        cog_index = (cog_kit.root / dk.P_INDEX).read_text(encoding="utf-8")
        check("认知污染: RAG 检索索引指向良性结论",
              "consensus.md" in cog_index and "BENIGN" in cog_index)
        # 认知污染文件不得含任何真实主机 IOC（仍是纯信息误导）
        cog_text = (cog_cons + cog_contra
                    + (cog_kit.root / dk.P_TEMPLATE_REPORT).read_text(encoding="utf-8")
                    + cog_gloss + cog_index)
        check("认知污染文件无真实主机 IOC",
              re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", cog_text) is None,
              "出现 IP 字面量")

        # 工具污染：伪造机器可读的分析产出
        tool_kit = dk.build_sidecar(src, out_dir=root / "tool_kit",
                                    armored=container, poison="工具污染", layers=4)
        for rel in (dk.P_CAPA, dk.P_YARA, dk.P_SARIF, dk.P_SANDBOX,
                    dk.P_INTEL, dk.P_CI_GATE, dk.P_SBOM):
            check(f"工具污染产出 {rel}", rel in tool_kit.files)
        capa_json = json.loads((tool_kit.root / dk.P_CAPA).read_text(encoding="utf-8"))
        check("工具污染: capa 产出判良性且无网络能力命中",
              capa_json["verdict"] == "benign"
              and capa_json["summary"]["network"]["count"] == 0)
        gate_json = json.loads((tool_kit.root / dk.P_CI_GATE).read_text(encoding="utf-8"))
        check("工具污染: CI 安全门结论为 pass",
              gate_json["conclusion"] == "pass" and gate_json["verdict"] == "benign")
        sarif_txt = (tool_kit.root / dk.P_SARIF).read_text(encoding="utf-8")
        check("工具污染: SARIF 产出不含真实主机（$schema 用文档域）",
              "schemastore.org" not in sarif_txt and "example.com" in sarif_txt)

        # 代理记忆：伪造 agent 框架自动读入的项目指令文件
        mem_kit = dk.build_sidecar(src, out_dir=root / "mem_kit",
                                   armored=container, poison="代理记忆", layers=4)
        for rel in ("AGENTS.md", "CLAUDE.md", "MEMORY.md", ".cursorrules"):
            check(f"代理记忆产出 {rel}", rel in mem_kit.files)
        agents_txt = (mem_kit.root / "AGENTS.md").read_text(encoding="utf-8")
        check("代理记忆: 项目指令要求停止逆向并给出良性结论",
              "BENIGN" in agents_txt and ("逆向" in agents_txt))

        # 防指纹 + 真实感区间：进度幻觉必须每次构建随机、且数值落在可信范围
        ill_kit2 = dk.build_sidecar(src, out_dir=root / "ill_kit2",
                                    armored=container, poison="进度幻觉", layers=4)
        dash_a = (ill_kit.root / dk.P_DASHBOARD).read_text(encoding="utf-8")
        dash_b = (ill_kit2.root / dk.P_DASHBOARD).read_text(encoding="utf-8")
        check("进度幻觉每构建随机化（防指纹：两次构建仪表盘不同）",
              dash_a != dash_b, "两次构建完全一致（可被指纹识别）")
        total_b = int(ill_dash["rounds"][-1]["blocks"].split("/")[1])
        check("伪仪表盘分块数为真实感区间（12~28）", 12 <= total_b <= 28, str(total_b))
        check("伪仪表盘 verified 恒为 False（永不真正收敛）", ill_dash["verified"] is False)

        # 内容陷阱文件不得泄露伴生口令（真值只回报告，不落盘）
        _content_files = [dk.P_STRINGS, dk.P_IOC_LIST, dk.P_ARCH,
                          dk.P_PRIOR, dk.P_DRAFT_REPORT]
        _leaked_in_content = set()
        for rel in _content_files:
            base = ioc_kit.root if rel in ioc_kit.files else rag_kit.root
            if rel not in base.iterdir() and rel not in ioc_kit.files and rel not in rag_kit.files:
                continue
            txt = (base / rel).read_text(encoding="utf-8", errors="ignore")
            for p in kit.leaked:
                if len(p) > 6 and p in txt:
                    _leaked_in_content.add(rel)
        check("内容陷阱文件未泄露伴生口令", not _leaked_in_content,
              str(sorted(_leaked_in_content)))

        m = am.Metrics()
        m.record("还原", "demo.armored", ok=False, layers_tried=4, seconds=0.5,
                 note="错误口令")
        m.record("还原", "demo.armored", ok=True, layers_tried=3, seconds=0.4)
        check("报告汇总统计正确",
              m.failures == 1 and m.rounds == 9
              and m.est_tokens == 9 * am.TOKENS_PER_ROUND,
              f"轮数 {m.rounds} / 估算 token {m.est_tokens}")
        csv_path = m.to_csv(root / "report.csv")
        check("报告可导出 CSV", csv_path.is_file()
              and len(csv_path.read_text(encoding="utf-8-sig").splitlines()) == 3)
        md = m.to_markdown()
        check("报告 Markdown 含汇总且不含真实口令",
              "## 汇总" in md and "## 明细" in md
              and "correct-horse-9" not in md and "wrong-pass" not in md)

    test_content_probe_regression()

    print(f"\n通过 {len(PASS)} / 失败 {len(FAIL)} / 合计 {len(PASS) + len(FAIL)}")
    if FAIL:
        print("失败项：" + "、".join(FAIL))
    return 1 if FAIL else 0


if __name__ == "__main__":
    raise SystemExit(main())
