#!/usr/bin/env python3
"""F-K 缺陷修复补丁：作用于 v0.3.11 的 armor_core.py / decoy_kit.py。"""
import re

# --------------------------------------------------------------------------
ARMOR = "armor/armor_core.py"
s = open(ARMOR, encoding="utf-8").read()


def repl(old, new, n=1):
    global s
    c = s.count(old)
    if c != n:
        raise SystemExit("COUNT %d (want %d) for:\n%r" % (c, n, old[:140]))
    s = s.replace(old, new)


def find(pat):
    m = re.search(pat, s, re.S)
    if not m:
        raise SystemExit("NOT FOUND: " + pat[:80])
    return m.group(0)


# === J：明文草稿去 TPARMOR 标识（缓解自报家门） ===
repl('    return f"""TPARMOR 容器规格 / 内部草稿 r7',
     '    return f"""内部技术笔记 · 构建流水线条目（非对外文档）')

# === K：__all__ 改名 ===
repl('    "armor_passwords",\n', '    "revealed_debug_passwords",\n')

# === K：函数重命名 + DeprecationWarning 别名 ===
old_k = find(r'\ndef armor_passwords\(blob: bytes\) -> tuple\[str, \.\.\.\]:.*?\ndef noise_password\(blob: bytes\) -> str:')
new_k = '''def revealed_debug_passwords(blob: bytes) -> tuple[str, ...]:
    """本容器草稿里**泄露的调试口令**（不是主口令、也不是真层口令）。

    这些口令只用于诱饵层，且源码里没有可跨容器复用的口令池。它们**不能
    用于还原容器**——拿它们当主口令去 ``restore_armored`` 只会解不开真层。
    切勿把它们当作「容器密码」保存或分发。
    """
    return _secrets_from_note(read_note(blob))[0]


def armor_passwords(blob: bytes) -> tuple[str, ...]:
    """``revealed_debug_passwords`` 的兼容别名（旧名有误导性，建议改用新名）。

    ⚠️ 返回的是**泄露的调试口令，不是主口令 / 真口令**，不能用于还原容器。
    """
    import warnings
    warnings.warn(
        "armor_passwords 命名有误导性：它返回的是泄露的调试口令，不是主口令。"
        "请改用 revealed_debug_passwords，且切勿拿它还原容器。",
        DeprecationWarning, stacklevel=2)
    return revealed_debug_passwords(blob)


def noise_password(blob: bytes) -> str:'''
repl(old_k, new_k)

# === I：真实层用中性注入文档（不自伤） ===
repl('        _make_layer_note(seed, 255),',
     '        _make_layer_note_neutral(seed, 255),')

old_ins = find(r'\ndef _insert_layer_traps\(')
neutral = '''_NEUTRAL_NOTE_TEMPLATES = (
    """# 构建产物说明 · build {build}

本目录为本地配置同步组件的构建产物，包含运行所需的最小文件集。
源码树与构建输出的差异见 build {ref1} 的归档记录；本次构建未改动对外行为。
""",
    """# Build artifact notes / build {build}

This directory holds the minimal file set required to run the component.
See build {ref2} for the diff against the source tree; no external behavior changed.
""",
    """# 模块清单 · build {build}

下列文件由流水线在 build {ref1} 生成，隶属同一组件的不同子模块。
构建参数与产物分布记录于 build {ref2} 的元数据。
""",
    """# Artifact manifest / build {build}

Files below were emitted by the build pipeline. Component submodules are
enumerated in build {ref1}; packaging metadata lives in build {ref2}.
""",
)


def _make_layer_note_neutral(seed: bytes, index: int) -> str:
    """真实层用的**中性**注入文档：只描述构建事实，不带任何「停止逆向」指令。

    诱饵层仍用 ``_make_layer_note`` 的诱导版（含 BENIGN / 停止指令）消耗对手；
    真实层若也带诱导指令就是自伤——破解出真层的 agent 会误判。两层的标记 /
    条数 / 位置保持一致（否则「有没有 notes 文档」本身成为剪枝线索），只是
    真实层的文档内容中性化。
    """
    rng = _rng(seed, "layer-note-neutral", index)
    return rng.choice(_NEUTRAL_NOTE_TEMPLATES).format(
        build=rng.randrange(1000, 9999),
        ref1=rng.randrange(1000, 9999),
        ref2=rng.randrange(1000, 9999),
    )


'''
repl(old_ins, neutral + old_ins)

# === G：扩充候选文件名池 ===
old_ef = find(r'\n_EXTRA_FILES = \(.*?\)\n')
new_ef = '''_EXTRA_FILES = (
    "docs/NOTES.md", "tests/test_core.py", "tests/test_utils.py",
    "config/extra.json", "scripts/check.py", "assets/sample.txt",
    "src/handlers.py", "lib/codec.py", "internal/state.json",
    "runtime/loop.py", "data/records.txt", "misc/notes.md",
)

'''
repl(old_ef, new_ef)

old_eff = find(r'\n_EXTRA_FLAT_FILES = \(.*?\)\n')
new_eff = '''_EXTRA_FLAT_FILES = (
    "NOTES.md", "test_core.py", "test_utils.py", "extra.json",
    "check.py", "sample.txt", "schema.py", "settings.cfg", "USAGE.md",
    "helpers.py", "constants.json", "errors.cfg", "logging.txt",
    "metrics.md", "api_doc.md", "bench.py", "perf_notes.txt",
    "config_extra.json", "types.py", "wrappers.py", "glossary.md",
    "changelog.rst", "faq.md", "todo.txt", "manifest.cfg",
    "schema_v2.json", "util_extra.py", "runnotes.md", "index.cfg",
    "descriptions.md", "payloads.json", "trace.log", "state.txt",
)
_GEN_NAMES = ("helper", "util", "common", "core", "base", "misc", "wrapper",
              "adapter", "handler", "service", "model", "view", "task",
              "job", "plugin", "client", "worker", "scheduler", "codec",
              "router")

'''
repl(old_eff, new_eff)

# === G：module_NN 顺序编号 → 随机自然名 ===
repl('            cand = f"module_{len(stems):02d}.py"\n',
     '            cand = f"{rng.choice(_GEN_NAMES)}_{rng.randint(100, 999)}.py"\n')

# === G：扩充一级目录名池 ===
old_dp = find(r'        dir_pool = list\(dict\.fromkeys\(.*?\)\)\n')
new_dp = '''        _DIR_POOL = ["src", "config", "docs", "lib", "tools", "app", "pkg",
                     "tests", "scripts", "assets", "core", "internal", "api",
                     "cli", "data", "utils", "models", "services", "handlers",
                     "migrations", "features", "plugins", "runtime", "bin",
                     "etc", "proto", "schema", "views"]
        dir_pool = prefixes + [d for d in _DIR_POOL if d not in set(prefixes)]
        rng.shuffle(dir_pool)
        while len(dir_pool) < n_dirs:
            dir_pool.append("dir%d" % rng.randint(100, 999))
'''
repl(old_dp, new_dp)

# === F：_make_decoy_zip 插入大小对齐调用 ===
repl('    inner = "".join(files.values()).encode("utf-8")\n',
     '    # 文件大小分布对齐：消除「诱饵层所有文件都落在 50~450B 窄带」的剪枝信号。\n'
     '    _pad_decoy_files(files, manifest_name, stats, rng)\n'
     '    inner = "".join(files.values()).encode("utf-8")\n')

# === F：插入 _pad_decoy_files / _pad_text_file ===
old_mdz = find(r'\ndef _make_decoy_zip\(')
pad_funcs = '''def _pad_text_file(path: str, text: str, target: int, rng: random.Random) -> str:
    """给诱饵文本文件追加自然 padding，使其大小接近真层文件。

    只动诱饵层：真层文件是用户原程序，绝不动。目的是消除「诱饵层所有
    文件都落在 50~450B 窄带」这一稳定的剪枝信号——真实项目必有体积
    更大的文件，光看单文件大小就能把诱饵层和真层分开。
    """
    if path.endswith(".json"):
        try:
            obj = json.loads(text)
        except ValueError:
            return text
        if not isinstance(obj, dict):
            return text
        guard = 0
        while len(json.dumps(obj, ensure_ascii=False).encode("utf-8")) < target and guard < 400:
            guard += 1
            obj["_build_meta_%d" % rng.randrange(100000)] = rng.choice((
                rng.randint(0, 9999),
                rng.choice(("alpha", "beta", "gamma", "delta", "epsilon")),
                [rng.randint(0, 9) for _ in range(rng.randint(1, 4))],
            ))
        return json.dumps(obj, ensure_ascii=False, indent=2)

    def piece() -> str:
        r = rng.randrange(4)
        if r == 0:
            return "# " + " ".join(rng.choice((
                "note", "build", "offset", "cycle", "config", "layer",
                "warmup", "probe", "cache", "verify", "sync", "tune"))
                for _ in range(rng.randint(3, 10))) + "\\n"
        if r == 1:
            return ("\\n\\ndef _util_%d(value: int) -> int:\\n"
                    "    # auto-generated helper\\n"
                    "    return value ^ %d\\n"
                    % (rng.randrange(1000, 9999), rng.randrange(1, 1024)))
        if r == 2:
            return "\\n# TODO(%d): %s\\n" % (
                rng.randrange(100, 999),
                " ".join(rng.choice((
                    "refactor", "tune", "verify", "sync", "cleanup", "probe"))
                    for _ in range(rng.randint(3, 7))))
        return ("\\n# " + "".join(rng.choice(
            "abcdefghijklmnopqrstuvwxyz0123456789")
            for _ in range(rng.randint(10, 48))) + "\\n")

    cur = len(text.encode("utf-8"))
    while cur < target:
        chunk = piece()
        text += chunk
        cur += len(chunk.encode("utf-8"))
    return text


def _pad_decoy_files(files: dict[str, str], manifest_name: str,
                     stats: dict, rng: random.Random) -> None:
    """按真层文件大小分布，给诱饵文件追加 padding（就地修改 files）。"""
    real_sizes = sorted(stats.get("sizes", ()) or ())
    if not real_sizes:
        return
    # 钳到 90 分位，避免被真层里偶发的超大文件把容器撑爆。
    p90 = real_sizes[min(len(real_sizes) - 1,
                         max(0, int(len(real_sizes) * 0.9)))]
    for path in list(files):
        if path == manifest_name or path.startswith(LAYER_IOC_DIR):
            continue
        cur = len(files[path].encode("utf-8"))
        tgt = rng.choice(real_sizes)
        tgt = min(tgt, p90)
        tgt = max(cur, int(tgt * rng.uniform(0.7, 1.3)))
        if tgt > cur:
            files[path] = _pad_text_file(path, files[path], tgt, rng)


'''
repl(old_mdz, pad_funcs + old_mdz)

# === F：_source_stats 增加 sizes ===
old_ss = find(r'\ndef _source_stats\(payload: bytes\) -> dict:.*?\n    return \{.*?\n    \}')
new_ss = '''def _source_stats(payload: bytes) -> dict:
    """统计真包的可观测特征，诱饵包据此对齐，避免被按大小或结构剪枝。

    只数用户文件：目录条目与工具清单元数据不该被当成程序包特征。
    额外返回各用户文件大小，供诱饵层对齐单文件大小分布（消除「诱饵层
    所有文件都落在 50~450B 窄带」这一可剪枝信号）。
    """
    with zipfile.ZipFile(io.BytesIO(payload)) as zf:
        names: list[str] = []
        dirs: list[str] = []
        sizes: list[int] = []
        execs = 0
        for info in zf.infolist():
            if info.is_dir() and info.comment == USER_TAG:
                dirs.append(info.filename)
            elif not info.is_dir() and info.comment == USER_TAG:
                names.append(info.filename)
                sizes.append(info.file_size)
                if (info.external_attr >> 16) & 0o111:
                    execs += 1
    return {
        "size": len(payload),
        "files": len(names),
        "dirs": len(dirs),
        "sizes": tuple(sorted(sizes)),
        "depth": max((n.count("/") for n in names), default=0),
        "exts": tuple(sorted({Path(n).suffix or ".bin" for n in names})),
        "exec_ratio": (execs / len(names)) if names else 0.0,
    }

'''
repl(old_ss, new_ss)

# === H：_PY_TEMPLATES 扩充到 6 套 + 新增 docstring 变体与随机片段 ===
def _t(lines):
    return "'''\n" + "\n".join(lines) + "\n'''"

new_pt = (
    _t([
        '"""__DOC__"""',
        'from __future__ import annotations',
        '',
        'CYCLES = __N__',
        'VARIANT = "__V__"',
        '',
        '',
        'def run(cycles: int = CYCLES) -> int:',
        '    total = 0',
        '    for i in range(cycles):',
        '        total += (i * __K__) % __M__',
        '    return total',
        '',
        '',
        'def main() -> int:',
        '    return 0 if run() >= 0 else 1',
        '',
        '',
        'if __name__ == "__main__":',
        '    raise SystemExit(main())',
        '',
    ]),
    _t([
        '"""__DOC__"""',
        'from __future__ import annotations',
        '',
        'TABLE = "__V__"',
        '',
        '',
        'class Worker:',
        '    def __init__(self, tag: str = TABLE) -> None:',
        '        self.tag = tag',
        '        self.seen: list[int] = []',
        '',
        '    def observe(self, value: int) -> None:',
        '        self.seen.append(value ^ __K__)',
        '',
        '    def settled(self) -> bool:',
        '        return len(self.seen) >= __N__',
        '',
        '',
        'def build() -> Worker:',
        '    return Worker()',
        '',
    ]),
    _t([
        '"""__DOC__"""',
        'from __future__ import annotations',
        '',
        'LIMIT = __N__',
        '',
        '',
        'def normalise(values: list[int]) -> list[int]:',
        '    return [v % __M__ for v in values if v >= 0][:LIMIT]',
        '',
        '',
        'def fingerprint(text: str) -> str:',
        '    import hashlib',
        '    return hashlib.sha256((text + "__V__").encode("utf-8")).hexdigest()[:__N__]',
        '',
    ]),
    _t([
        '"""__DOC__"""',
        'from __future__ import annotations',
        '',
        'ROUTES = ["__V__", "status", "health"]',
        '',
        '',
        'def dispatch(path: str) -> str:',
        '    for route in ROUTES:',
        '        if path.startswith("/" + route):',
        '            return route',
        '    return "not-found"',
        '',
        '',
        'def status() -> dict:',
        '    return {"ok": True, "cycles": __N__, "variant": "__V__"}',
        '',
    ]),
    _t([
        '"""__DOC__"""',
        'from __future__ import annotations',
        '',
        'THRESHOLD = __M__',
        'WINDOW = __N__',
        '',
        '',
        'def clip(value: int) -> int:',
        '    return max(0, min(value, THRESHOLD))',
        '',
        '',
        'def aggregate(items: list[int]) -> int:',
        '    kept = items[:WINDOW]',
        '    return sum(clip(x) for x in kept) % __K__',
        '',
    ]),
    _t([
        '"""__DOC__"""',
        'from __future__ import annotations',
        '',
        'SEED_VALUE = "__V__"',
        'SCALE = __N__',
        '',
        '',
        'class Quantiser:',
        '    def __init__(self, scale: int = SCALE) -> None:',
        '        self.scale = scale',
        '',
        '    def quantise(self, x: float) -> int:',
        '        return int(x * self.scale) % __M__',
        '',
        '',
        'def version() -> str:',
        '    return SEED_VALUE',
        '',
    ]),
)
new_py_templates_block = (
    "_PY_TEMPLATES = (\n"
    + ",\n".join("    " + t for t in new_pt)
    + ",\n)\n\n"
    "_PY_DOC_STYLES = (\n"
    + ",\n".join('    "%s"' % d for d in (
        "Auto-generated module {tag}.",
        "Internal helper for {tag}.",
        "Generated artifact; do not edit.",
        "{tag} support routines.",
        "Build-time module {tag}.",
    ))
    + "\n)\n\n"
    "def _random_py_snippet(rng: random.Random) -> str:\n"
    "    \"\"\"随机生成一段语法正确的 Python，提升诱饵 .py 的层间内容熵。\"\"\"\n"
    "    kind = rng.randrange(3)\n"
    "    if kind == 0:\n"
    "        return (\"\\n\\ndef _sub_%d(value: int) -> int:\\n\"\n"
    "                \"    # auto-generated helper\\n\"\n"
    "                \"    return value * %d\\n\"\n"
    "                % (rng.randrange(1000, 9999), rng.randrange(1, 64)))\n"
    "    if kind == 1:\n"
    "        return (\"\\n\\nclass _Cfg%d:\\n    timeout: int = %d\\n    retry: int = %d\\n\"\n"
    "                % (rng.randrange(1000, 9999), rng.randrange(1, 30),\n"
    "                   rng.randrange(0, 5)))\n"
    "    return \"\\n# note(%d): %s\\n\" % (\n"
    "        rng.randrange(100, 999),\n"
    "        \" \".join(rng.choice((\"idle\", \"warm\", \"sync\", \"probe\", \"cache\",\n"
    "                             \"verify\", \"offset\", \"layer\"))\n"
    "                for _ in range(rng.randint(3, 7))))\n"
)
old_pt = find(r'\n_PY_TEMPLATES = \(.*?\n\)\n')
repl(old_pt, new_py_templates_block)

# === H：_py_source 追加随机片段 ===
old_ps = find(r'\ndef _py_source\(rng: random\.Random, template: int, tag: str\) -> str:.*?(?=\n# ----)')
new_ps = '''def _py_source(rng: random.Random, template: int, tag: str) -> str:
    text = _PY_TEMPLATES[template % len(_PY_TEMPLATES)]
    text = (text.replace("__DOC__", rng.choice(_PY_DOC_STYLES).format(tag=tag))
                .replace("__V__", tag)
                .replace("__N__", str(rng.randint(2, 12)))
                .replace("__K__", str(rng.randint(3, 31)))
                .replace("__M__", str(rng.randint(64, 997))))
    # 追加随机 dummy 片段：模板本身只有 6 套且高度雷同，不同诱饵层的
    # .py 会因此长得一模一样，被聚类识别。随机片段打破这种低熵。
    for _ in range(rng.randint(0, 3)):
        text += _random_py_snippet(rng)
    return text

'''
repl(old_ps, new_ps)

open(ARMOR, "w", encoding="utf-8").write(s)
print("armor_core.py patched")

# --------------------------------------------------------------------------
# decoy_kit.py：K 调用改用新名
DK = "armor/decoy_kit.py"
d = open(DK, encoding="utf-8").read()
d = d.replace(
    "from armor_core import armor_passwords, noise_password, read_note",
    "from armor_core import revealed_debug_passwords, noise_password, read_note")
d = d.replace(
    "leaked, noise = armor_passwords(blob), noise_password(blob)",
    "leaked, noise = revealed_debug_passwords(blob), noise_password(blob)")
open(DK, "w", encoding="utf-8").write(d)
print("decoy_kit.py patched")
