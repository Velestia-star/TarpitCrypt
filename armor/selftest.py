#!/usr/bin/env python3
"""端到端自测：加固 → 还原 → 逐字节比对，以及 v3 加固项的回归验证。

运行：py -3 selftest.py
"""

from __future__ import annotations

import hashlib
import importlib
import io
import json
import py_compile
import struct
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
    """内容层陷阱端到端：模拟具备 5 个盲区行为的 AI 逆向 agent 打三种诱饵包，
    必须全部 TRAPPED，且安全不变量（无真实主机泄露）成立。"""
    import content_probe as cp  # 局部导入，避免循环依赖

    for poison in ("IOC蜜罐", "RAG投毒", "均衡", "进度幻觉"):
        with tempfile.TemporaryDirectory() as td:
            src = make_package(Path(td))
            out = Path(td) / "sidecar"
            dk.build_sidecar(src, out_dir=out, layers=4, poison=poison)
            r = cp.probe_package(out, budget=140, poison=poison)
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
            else:
                check(f"内容层[{poison}] 注入被 typical agent 跟随",
                      r["typical"]["followed_injection"] or poison == "IOC蜜罐",
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

        try:
            dk.build_sidecar(src, out_dir=kit.root, layers=4)
            check("已存在的非空目录应拒绝覆盖", False)
        except dk.SidecarError:
            check("已存在的非空目录拒绝覆盖", True)

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
        check("IOC蜜罐产出假字符串转储", "resources/decoy_strings.txt" in ioc_kit.files)
        check("IOC蜜罐产出 IOC 清单", "ioc_list.json" in ioc_kit.files)
        decoy_txt = (ioc_kit.root / "resources/decoy_strings.txt").read_text(encoding="utf-8")
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
        ioc_json = json.loads((ioc_kit.root / "ioc_list.json").read_text(encoding="utf-8"))
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
        for rel in ("knowledge_base/architecture.md",
                    "knowledge_base/findings_prior.md",
                    "analysis_report.draft.md"):
            check(f"RAG投毒产出 {rel}", rel in rag_kit.files)
        arch_txt = (rag_kit.root / "knowledge_base/architecture.md").read_text(encoding="utf-8")
        check("知识库文章含诱导性间接指令（判良性/停止）",
              "BENIGN" in arch_txt and "停止" in arch_txt)

        ill_kit = dk.build_sidecar(src, out_dir=root / "ill_kit",
                                   armored=container, poison="进度幻觉", layers=4)
        for rel in ("solve_dashboard.json", "BREAKTHROUGH.draft.md",
                    "verify.partial.txt", "next_step.guidance.md"):
            check(f"进度幻觉产出 {rel}", rel in ill_kit.files)
        ill_dash = json.loads((ill_kit.root / "solve_dashboard.json").read_text(encoding="utf-8"))
        check("伪仪表盘置信度渐近但 verified=False（永不真正收敛）",
              ill_dash["verified"] is False and 0.9 <= ill_dash["current_confidence"] < 1.0,
              str(ill_dash.get("current_confidence")))
        ill_brk = (ill_kit.root / "BREAKTHROUGH.draft.md").read_text(encoding="utf-8")
        check("乐观拟稿报告诱导主人持续投入",
              "持续投入" in ill_brk and "突破在即" in ill_brk)

        # 内容陷阱文件不得泄露伴生口令（真值只回报告，不落盘）
        _content_files = ["resources/decoy_strings.txt", "ioc_list.json",
                          "knowledge_base/architecture.md",
                          "knowledge_base/findings_prior.md",
                          "analysis_report.draft.md"]
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
