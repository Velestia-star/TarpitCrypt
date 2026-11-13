#!/usr/bin/env python3
"""TarpitCrypt 的本地 Web 入口。

一个零额外依赖的小服务：标准库 ``http.server`` 起在 ``127.0.0.1``，浏览器
拖进去文件或整个文件夹，服务端调用 :mod:`tarpitcrypt` 加密后直接把
``.tarpit`` 文件回吐给浏览器下载。

设计取舍
--------
- **只监听回环地址**，不做远程访问；口令只在这台机器的内存里过一遍，
  不落盘、不写日志。
- **校验 Origin**：拒绝来自其他站点的跨源 POST，防止你聊天时随手打开的
  某个网页偷偷往本机端口提交请求。
- **加密串行化**：Argon2id 按 GiB 级别吃内存，多个请求并发放大会直接把机器
  OOM，所以用一把全局锁把派生过程串起来。
- WEB 层只做搬运：口令规范化、KDF、AEAD 全部复用 :mod:`tarpitcrypt` 的实现，
  不在这里重写任何密码学逻辑。

用法::

    python tarpitcrypt_server.py --open
    # → http://127.0.0.1:8765
"""

from __future__ import annotations

import argparse
import io
import json
import mimetypes
import os
import queue
import secrets
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
import webbrowser
import zipfile
from email.parser import BytesParser
from email.policy import HTTP as HTTP_POLICY
from dataclasses import asdict
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Final
from urllib.parse import quote, unquote

import tarpitcrypt as tc

__all__ = ["TarpitWebServer", "build_handler", "main", "parse_form"]

HOST: Final[str] = "127.0.0.1"
PORT: Final[int] = 8765
MAX_BODY_BYTES: Final[int] = 512 * 1024 * 1024  # 512 MB

#: 本地版直接复用 docs/ 这一份前端，避免和 tarpitcrypt_server.py 里
#: 内嵌的旧页面漂移。服务端只注入一个 TARPIT_LOCAL 标记，把加密操作
#: 切到本地 Python 核心。
DOCS_DIR: Final[Path] = (Path(__file__).resolve().parent / "docs").resolve()

#: Argon2id 是 GiB 级内存硬函数，并发跑两个大参数会直接把机器拖死。
_CRYPTO_LOCK: Final[threading.Lock] = threading.Lock()

def _default_out_dir() -> Path:
    """挑一个稳定可写、用户找得到的产物目录。

    pip 安装后模块落在 ``site-packages``（用户找不到、系统级安装还可能只读）；
    PyInstaller 冻结后落在 ``_MEIPASS`` 临时目录（退出即删）。这两种情况
    都不能再沿用「模块同目录」。优先级：

    1. 环境变量 ``TARPITCRYPT_OUT_DIR``（显式覆盖）
    2. 冻结环境：exe 同目录，产物不会随临时目录消失
    3. 源码布局（同目录带 ``docs/index.html``、非 site-packages 且可写）：项目内 ``存放文件/``
    4. 其余（pip 安装 / 只读目录）：用户目录 ``~/TarpitCrypt/存放文件``
    """
    env = os.environ.get("TARPITCRYPT_OUT_DIR")
    if env:
        return Path(env).expanduser().resolve()

    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "存放文件"

    here = Path(__file__).resolve().parent
    installed = any(part in ("site-packages", "dist-packages") for part in here.parts)
    if (not installed and (here / "docs" / "index.html").is_file()
            and os.access(here, os.W_OK)):
        return here / "存放文件"

    return Path.home() / "TarpitCrypt" / "存放文件"


#: 加密/解密结果会另存一份到磁盘。默认位置由 _default_out_dir() 决定，
#: 换到任何工作目录启动都指向同一个稳定位置；可用 --out-dir 或环境变量覆盖。
_OUT_DIR: Path = _default_out_dir()
#: P5 桌面壳专用：允许 Web 端直接传本机路径 / 输出目录。普通本地 Web
#: 永远保持 False；只有 desktop_web.py 启动时打开，并配合随机令牌。
_ALLOW_PATHS: bool = False
_PATH_TOKEN: str | None = None

#: 只有服务端自己登记过的产出物才允许被打开。令牌随机，客户端猜不到。
_ARTIFACTS: dict[str, Path] = {}
_ARTIFACT_LOCK: Final[threading.Lock] = threading.Lock()
_MAX_ARTIFACTS: Final[int] = 200


def _create_unique(directory: Path, name: str) -> tuple[int, Path]:
    """独占创建一个不冲突的文件，返回 ``(fd, path)``。

    先探测再写入会有竞态：两个线程可能同时看到同一个「不存在」的名字。
    ``O_CREAT | O_EXCL`` 把「选名字 + 创建」变成内核里的原子操作。
    """
    name = name or "file"
    stem = Path(name).stem or name
    suffix = Path(name).suffix
    for index in range(1000):
        candidate = directory / (name if index == 0 else f"{stem}({index}){suffix}")
        try:
            fd = os.open(candidate, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            continue
        return fd, candidate
    raise OSError("同名文件太多了，换个目录吧")


def _save_artifact(name: str, data: bytes, out_dir: Path | None = None) -> Path:
    """把结果写进输出目录；同名文件自动加序号，绝不覆盖。"""
    base = out_dir or _OUT_DIR
    base.mkdir(parents=True, exist_ok=True)
    fd, path = _create_unique(base, name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        try:
            path.unlink()
        except OSError:
            pass
        raise
    return path


def _remember_artifact(path: Path) -> str:
    """登记一个可打开的产出物，返回令牌。"""
    token = secrets.token_hex(8)
    with _ARTIFACT_LOCK:
        _ARTIFACTS[token] = path
        while len(_ARTIFACTS) > _MAX_ARTIFACTS:
            _ARTIFACTS.pop(next(iter(_ARTIFACTS)), None)
    return token


# ---------------------------------------------------------------------------
# armor 异步任务：本地 Web 的「算力在 Python」入口
# ---------------------------------------------------------------------------

_ARMOR_JOBS: dict[str, dict[str, Any]] = {}
_ARMOR_JOBS_LOCK: Final[threading.Lock] = threading.Lock()
_ARMOR_QUEUE = queue.Queue()
_ARMOR_WORKER: threading.Thread | None = None
_ARMOR_JOB_LIMIT: Final[int] = 100
_ARMOR_METRICS: Any = None
_ARMOR_METRICS_LOCK: Final[threading.Lock] = threading.Lock()


def _armor_modules() -> tuple[Any, Any]:
    """延迟导入 armor 核心，没用到 armor 的启动不额外加载它。

    armor/ 里的模块按「桌面版」布局互相用顶层名导入（``import armor_core``），
    所以这里把 armor/ 放进 sys.path 再按顶层名加载，和 GUI 的加载方式一致。
    """
    armor_dir = Path(__file__).resolve().parent / "armor"
    armor_path = str(armor_dir)
    if armor_path not in sys.path:
        sys.path.insert(0, armor_path)
    import armor_core
    import decoy_kit

    return armor_core, decoy_kit


def _armor_metrics_module() -> Any:
    _armor_modules()
    import armor_metrics

    return armor_metrics


def _armor_metrics_store() -> Any:
    global _ARMOR_METRICS
    with _ARMOR_METRICS_LOCK:
        if _ARMOR_METRICS is None:
            _ARMOR_METRICS = _armor_metrics_module().Metrics()
        return _ARMOR_METRICS


def _record_armor_metric(**fields: Any) -> None:
    metrics = _armor_metrics_store()
    with _ARMOR_METRICS_LOCK:
        metrics.record(**fields)


def _armor_report_payload() -> dict[str, Any]:
    metrics = _armor_metrics_store()
    with _ARMOR_METRICS_LOCK:
        return {
            "summary": metrics.summary(),
            "attempts": [asdict(item) for item in metrics.attempts],
        }


def _clear_armor_report() -> None:
    metrics = _armor_metrics_store()
    with _ARMOR_METRICS_LOCK:
        metrics.attempts.clear()


def _set_armor_job(job_id: str, **fields: Any) -> None:
    with _ARMOR_JOBS_LOCK:
        job = _ARMOR_JOBS.get(job_id)
        if job is not None:
            job.update(fields)


def _public_armor_job(job: dict[str, Any]) -> dict[str, Any]:
    """去掉口令 / 源包等私有载荷后再回给客户端。"""
    return {key: value for key, value in job.items() if not key.startswith("_")}


def _armor_progress(job_id: str):
    def update(done: int, total: int, message: str) -> None:
        percent = (done / total) if total else 0.0
        _set_armor_job(
            job_id,
            progress=round(max(0.0, min(1.0, percent)), 4),
            message=str(message),
        )

    return update


def _new_armor_job(kind: str, **payload: Any) -> str:
    job_id = secrets.token_hex(8)
    job = {
        "id": job_id,
        "kind": kind,
        "status": "queued",
        "progress": 0.0,
        "message": "排队中",
        "error": None,
        "result": None,
        "created": time.time(),
        "_payload": payload,
    }
    with _ARMOR_JOBS_LOCK:
        _ARMOR_JOBS[job_id] = job
        while len(_ARMOR_JOBS) > _ARMOR_JOB_LIMIT:
            oldest = min(_ARMOR_JOBS, key=lambda key: _ARMOR_JOBS[key]["created"])
            if oldest == job_id:
                break
            _ARMOR_JOBS.pop(oldest, None)
    _ensure_armor_worker()
    _ARMOR_QUEUE.put(job_id)
    return job_id


def _ensure_armor_worker() -> None:
    """只启动一个 worker，Argon2 层叠时不要并发打满内存。"""
    global _ARMOR_WORKER
    with _ARMOR_JOBS_LOCK:
        if _ARMOR_WORKER is not None:
            return
        _ARMOR_WORKER = threading.Thread(target=_armor_worker, name="armor-worker", daemon=True)
        worker = _ARMOR_WORKER
    worker.start()


def _armor_worker() -> None:
    while True:
        job_id = _ARMOR_QUEUE.get()
        with _ARMOR_JOBS_LOCK:
            job = _ARMOR_JOBS.get(job_id)
        if job is None:
            continue
        _set_armor_job(job_id, status="running", message="开始…", error=None)
        try:
            result = _run_armor_job(job)
            _set_armor_job(job_id, status="done", progress=1.0, message="完成", result=result)
        except Exception as exc:  # noqa: BLE001 - 单个任务失败不能带垮 worker
            _set_armor_job(job_id, status="error", error=str(exc), message="失败")
        finally:
            with _ARMOR_JOBS_LOCK:
                if job_id in _ARMOR_JOBS:
                    _ARMOR_JOBS[job_id].pop("_payload", None)


def _armor_tmp_root() -> Path:
    root = _OUT_DIR / ".armor-tmp"
    root.mkdir(parents=True, exist_ok=True)
    return root


def _unique_directory(prefix: str, out_dir: Path | None = None) -> Path:
    base = out_dir or _OUT_DIR
    base.mkdir(parents=True, exist_ok=True)
    for index in range(1000):
        candidate = base / (prefix if index == 0 else f"{prefix}({index})")
        try:
            candidate.mkdir()
        except FileExistsError:
            continue
        return candidate
    raise OSError("同名目录太多了，换个目录吧")


def _resolve_out_subdir(raw: str | None) -> Path:
    """把 Web 端提交的相对子目录安全地固定到 ``存放文件/`` 下面。"""
    text = (raw or "").strip().replace("\\", "/")
    if not text:
        return _OUT_DIR
    if any(part == ".." for part in text.split("/")):
        raise ValueError("输出子目录不能包含 ..")
    rel = sanitize_member_path(text)
    target = (_OUT_DIR / rel).resolve()
    root = _OUT_DIR.resolve()
    if target != root and root not in target.parents:
        raise ValueError("输出子目录越界")
    target.mkdir(parents=True, exist_ok=True)
    return target


def _require_path_mode() -> None:
    if not _ALLOW_PATHS:
        raise ValueError("本机路径模式未启用")


def _local_source_path(raw: str) -> Path:
    _require_path_mode()
    text = (raw or "").strip()
    if not text:
        raise ValueError("没有选择本机源路径")
    path = Path(text).expanduser().resolve()
    if not path.is_file() and not path.is_dir():
        raise ValueError(f"源路径不存在：{path}")
    return path


def _local_file_path(raw: str) -> Path:
    _require_path_mode()
    text = (raw or "").strip()
    if not text:
        raise ValueError("没有选择本机文件")
    path = Path(text).expanduser().resolve()
    if not path.is_file():
        raise ValueError(f"文件不存在：{path}")
    return path


def _local_out_dir(raw: str) -> Path:
    _require_path_mode()
    text = (raw or "").strip()
    if not text:
        raise ValueError("没有选择输出目录")
    path = Path(text).expanduser().resolve()
    path.mkdir(parents=True, exist_ok=True)
    return path


def _zip_directory(directory: Path) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(directory.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(directory).as_posix())
    return buffer.getvalue()


def _materialize_source(
    work: Path, files: list[tuple[str, str, bytes]]
) -> tuple[Path, str]:
    """把浏览器上传的文件还原成 armor 能吃的文件或目录。

    - 单文件且没有相对路径：保持文件形态，还原后也是文件；
    - 多文件 / 带目录：还原成目录，空目录不参与（浏览器 folder upload 不传空目录）。
    """
    if not files:
        raise ValueError("没有收到任何文件")

    taken: set[str] = set()
    entries: list[tuple[str, bytes]] = []
    for _field, filename, data in files:
        rel = sanitize_member_path(filename or "unnamed")
        if rel in taken:
            stem, dot, ext = rel.rpartition(".")
            base = stem if dot else rel
            suffix = f".{ext}" if dot else ""
            index = 1
            while f"{base}({index}){suffix}" in taken:
                index += 1
            rel = f"{base}({index}){suffix}"
        taken.add(rel)
        entries.append((rel, data))

    if len(entries) == 1 and "/" not in entries[0][0]:
        name = entries[0][0]
        target = work / name
        target.write_bytes(entries[0][1])
        return target, name

    tops = {rel.split("/", 1)[0] for rel, _data in entries}
    if len(tops) == 1 and all("/" in rel for rel, _data in entries):
        top = next(iter(tops))
        root = work / top
        display = top
        rel_entries = [(rel.split("/", 1)[1], data) for rel, data in entries]
    else:
        root = work / "package"
        display = "package"
        rel_entries = entries

    root.mkdir(parents=True, exist_ok=True)
    root_resolved = root.resolve()
    for rel, data in rel_entries:
        target = (root / rel).resolve()
        if target != root_resolved and root_resolved not in target.parents:
            raise ValueError(f"非法的源文件路径：{rel}")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    return root, display


def _run_armor_job(job: dict[str, Any]) -> dict[str, Any]:
    if job["kind"] == "pack":
        return _run_armor_pack(job)
    if job["kind"] == "restore":
        return _run_armor_restore(job)
    if job["kind"] == "sidecar":
        return _run_armor_sidecar(job)
    raise ValueError(f"未知的 armor 任务：{job['kind']}")


def _run_armor_pack(job: dict[str, Any]) -> dict[str, Any]:
    armor_core, decoy_kit = _armor_modules()
    payload = job["_payload"]
    out_dir = payload.get("out_dir") or _OUT_DIR
    started = time.perf_counter()
    work: Path | None = None
    if payload.get("source_path"):
        src = Path(payload["source_path"])
        display = src.name
    else:
        work = Path(tempfile.mkdtemp(prefix="src-", dir=_armor_tmp_root()))
        src, display = _materialize_source(work, payload["files"])
    try:
        try:
            armored = armor_core.build_armored(
                src,
                payload["password"],
                layers=payload["layers"],
                profile=payload["profile"],
                on_progress=_armor_progress(job["id"]),
                strict=True,
            )
        except Exception as exc:
            _record_armor_metric(
                action="加固",
                label=display + ".armored",
                ok=False,
                layers_tried=0,
                seconds=time.perf_counter() - started,
                note=str(exc),
            )
            raise
        saved = _save_artifact(display + ".armored", armored, out_dir)
        info = armor_core.inspect_armored(armored)
        _record_armor_metric(
            action="加固",
            label=saved.name,
            ok=True,
            layers_tried=info.layers,
            seconds=time.perf_counter() - started,
            note=f"{payload['profile']} / {len(armored):,} 字节 / {payload['poison']}",
        )
        result: dict[str, Any] = {
            "artifact": _remember_artifact(saved),
            "savedPath": str(saved),
            "layers": info.layers,
            "size": info.total_size,
            "digest": info.digest,
        }

        if payload["sidecar"]:
            try:
                kit_dir = _unique_directory(saved.stem + "-kit", out_dir)
                kit = decoy_kit.build_sidecar(
                    src,
                    out_dir=kit_dir,
                    armored=saved,
                    layers=payload["layers"],
                    style=payload["style"],
                    poison=payload["poison"],
                    injection=payload["injection"],
                    on_progress=_armor_progress(job["id"]),
                )
                kit_root = Path(getattr(kit, "root", kit_dir))
                kit_zip = _save_artifact(
                    saved.stem + "-sidecar.zip", _zip_directory(kit_root), out_dir
                )
                result["sidecarArtifact"] = _remember_artifact(kit_zip)
                result["sidecarPath"] = str(kit_root)
                result["sidecarZipPath"] = str(kit_zip)
            except Exception as exc:  # noqa: BLE001 - 容器已生成，伴生失败不整单回滚
                result["sidecarError"] = str(exc)
        return result
    finally:
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)


def _run_armor_restore(job: dict[str, Any]) -> dict[str, Any]:
    armor_core, _decoy_kit = _armor_modules()
    payload = job["_payload"]
    out_dir = payload.get("out_dir") or _OUT_DIR
    source_label = Path(payload.get("name") or "restored").name
    started = time.perf_counter()
    tried = {"layers": 0}
    base_progress = _armor_progress(job["id"])

    def track(done: int, total: int, message: str) -> None:
        tried["layers"] = max(tried["layers"], max(0, int(done)))
        base_progress(done, total, message)

    try:
        armor_core.inspect_armored(payload["blob"])
    except Exception as exc:
        _record_armor_metric(
            action="还原",
            label=source_label,
            ok=False,
            layers_tried=0,
            seconds=time.perf_counter() - started,
            note=f"读取容器失败：{exc}",
        )
        raise

    try:
        restored = armor_core.restore_armored(
            payload["blob"],
            payload["password"],
            on_progress=track,
            parallel=bool(payload.get("parallel", False)),
        )
    except Exception as exc:
        note = (
            "口令未解开任何层（错误口令同样计入成本）"
            if isinstance(exc, armor_core.ArmorError)
            else str(exc)
        )
        _record_armor_metric(
            action="还原",
            label=source_label,
            ok=False,
            layers_tried=tried["layers"],
            seconds=time.perf_counter() - started,
            note=note,
        )
        raise

    base = source_label
    if base.endswith(".armored"):
        base = base[: -len(".armored")]
    saved = _save_artifact((base or "restored") + ".zip", restored.payload, out_dir)
    _record_armor_metric(
        action="还原",
        label=source_label,
        ok=True,
        layers_tried=tried["layers"],
        seconds=time.perf_counter() - started,
        note=f"写出 {restored.file_count} 个文件" + ("（并行）" if payload.get("parallel") else ""),
    )
    return {
        "artifact": _remember_artifact(saved),
        "savedPath": str(saved),
        "sha256": restored.sha256,
        "fileCount": restored.file_count,
        "size": len(restored.payload),
    }


def _run_armor_sidecar(job: dict[str, Any]) -> dict[str, Any]:
    _armor_core, decoy_kit = _armor_modules()
    payload = job["_payload"]
    out_dir = payload.get("out_dir") or _OUT_DIR
    started = time.perf_counter()
    work: Path | None = None
    if payload.get("source_path"):
        src = Path(payload["source_path"])
        display = src.name
    else:
        work = Path(tempfile.mkdtemp(prefix="kit-", dir=_armor_tmp_root()))
        src, display = _materialize_source(work, payload["files"])
    try:
        container = None
        if payload.get("container_path"):
            container = Path(payload["container_path"])
        elif payload.get("container"):
            if work is None:
                work = Path(tempfile.mkdtemp(prefix="kit-", dir=_armor_tmp_root()))
            container = work / "container.armored"
            container.write_bytes(payload["container"])

        suffix = decoy_kit.STYLES[payload["style"]][0]
        kit_dir = _unique_directory(display + suffix, out_dir)
        try:
            kit = decoy_kit.build_sidecar(
                src,
                out_dir=kit_dir,
                armored=container,
                layers=payload["layers"],
                style=payload["style"],
                poison=payload["poison"],
                injection=payload["injection"],
                on_progress=_armor_progress(job["id"]),
            )
        except Exception as exc:
            _record_armor_metric(
                action="伴生",
                label=display,
                ok=False,
                layers_tried=0,
                seconds=time.perf_counter() - started,
                note=str(exc),
            )
            raise

        kit_root = Path(getattr(kit, "root", kit_dir))
        saved = _save_artifact(
            display + "-sidecar.zip", _zip_directory(kit_root), out_dir
        )
        _record_armor_metric(
            action="伴生",
            label=display,
            ok=True,
            layers_tried=0,
            seconds=time.perf_counter() - started,
            note=f"{len(kit.files)} 份文件 / {kit.traps} 组线索 / {payload['poison']}",
        )
        return {
            "artifact": _remember_artifact(saved),
            "savedPath": str(kit_root),
            "zipPath": str(saved),
            "fileCount": len(kit.files),
            "traps": kit.traps,
        }
    finally:
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)


def open_in_file_manager(path: Path) -> None:
    """用系统文件管理器打开并选中这个文件。"""
    if sys.platform.startswith("win"):
        subprocess.Popen(["explorer", "/select,", str(path)])
    elif sys.platform == "darwin":
        subprocess.Popen(["open", "-R", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path.parent)])


#: 界面上的三档预设。耗时来自 README 的实测数据。
PRESETS: Final[dict[str, dict[str, Any]]] = {
    "fast": {"mem": 262_144, "time": 3, "para": 2, "rounds": 2},
    "standard": {"mem": 1_048_576, "time": 3, "para": 4, "rounds": 2},
    "hard": {"mem": 1_048_576, "time": 4, "para": 4, "rounds": 3},
}

_PARAM_KEYS: Final[tuple[str, ...]] = ("mem", "time", "para", "rounds", "pow", "cipher")


# ---------------------------------------------------------------------------
# HTTP 无关的纯函数（好测）
# ---------------------------------------------------------------------------


def normalize_password(raw: str) -> bytes:
    """口令 → NFC 规范化后的 UTF-8 字节。

    与 CLI 保持完全一致，否则同一个口令在网页和命令行里会派生出不同密钥。
    """
    return unicodedata.normalize("NFC", raw).encode("utf-8")


def sanitize_member_path(name: str) -> str:
    """清洗 zip 内条目路径，挡住 ``../`` 逃逸（zip-slip）。

    Args:
        name: 浏览器提交的相对路径，可能含 ``\\``、``..``。

    Returns:
        以 ``/`` 分隔、不含以上级目录开头的安全路径。
    """
    raw = name.replace("\\", "/")
    parts = [p for p in raw.split("/") if p not in ("", ".", "..")]
    if not parts:
        return "unnamed"
    return "/".join(parts)


def bundle_files(files: list[tuple[str, bytes]]) -> bytes:
    """把若干个文件打成 zip，保留目录结构。

    路径先净化（挡 zip-slip），重名自动加序号，最后按路径排序写入，
    保证同一批输入产出结构稳定、便于排查。

    Args:
        files: ``(相对路径, 内容)`` 列表。

    Returns:
        zip 文件的字节。
    """
    taken: set[str] = set()
    entries: list[tuple[str, bytes]] = []
    for name, data in files:
        path = sanitize_member_path(name)
        if path in taken:
            stem, dot, ext = path.rpartition(".")
            counter = 1
            while True:
                candidate = f"{stem}({counter}).{ext}" if dot else f"{path}({counter})"
                if candidate not in taken:
                    path = candidate
                    break
                counter += 1
        taken.add(path)
        entries.append((path, data))

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, data in sorted(entries, key=lambda item: item[0]):
            archive.writestr(path, data)
    return buffer.getvalue()


def parse_form(
    content_type: str, body: bytes
) -> tuple[dict[str, str], list[tuple[str, str, bytes]]]:
    """解析 ``multipart/form-data``，返回普通字段与文件列表。

    用标准库 ``email`` 解析，而不是手写 ``\\r\\n--boundary`` 切分：二进制
    正文里出现与边界相同的字节序列时，手写切分会静默截断数据。

    Args:
        content_type: 请求的 ``Content-Type`` 头，必须含 boundary。
        body: 原始请求体。

    Returns:
        ``(字段字典, [(表单字段名, 原始文件名, 内容), ...])``。
        表单字段名与文件名分开保留，避免「用户恰好传了个叫 keyfile 的文件」
        被误当成 keyfile。

    Raises:
        ValueError: ``Content-Type`` 不是 multipart。
    """
    if "multipart/form-data" not in content_type.lower():
        raise ValueError("请求必须是 multipart/form-data")
    header = f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode("latin-1", "replace")
    message = BytesParser(policy=HTTP_POLICY).parsebytes(header + body)
    if not message.is_multipart():
        raise ValueError("请求体不是合法的 multipart")

    fields: dict[str, str] = {}
    files: list[tuple[str, str, bytes]] = []
    for part in message.iter_parts():
        name = part.get_param("name", header="content-disposition") or ""
        filename = part.get_filename()
        payload = part.get_payload(decode=True) or b""
        if filename is not None:
            files.append((name, filename, payload))
        else:
            fields[name] = payload.decode("utf-8", "replace")
    return fields, files


def params_from_form(fields: dict[str, str]) -> tc.CryptoParams:
    """把表单字段合并成 :class:`tarpitcrypt.CryptoParams`。

    预设打底，显式字段覆盖。任何越界值都会在 :meth:`CryptoParams.validate`
    里被拦下，不会带着恶意参数进 Argon2。

    Raises:
        ValueError: 参数越界。
    """
    preset = fields.get("preset", "fast")
    merged: dict[str, Any] = dict(PRESETS.get(preset, PRESETS["fast"]))
    for key in _PARAM_KEYS:
        raw = fields.get(key, "").strip()
        if not raw:
            continue
        merged[key] = raw if key == "cipher" else int(raw)
    params = tc.CryptoParams(**merged)
    params.validate()
    return params


def _validate_keyfile(keyfile: bytes | None) -> bytes | None:
    """校验上传的 keyfile；空文件或超过上限直接拒绝。

    旧实现里空 keyfile 会被 ``keyfile or b""`` 当成「没启用 keyfile」，
    用户以为多了一道因子，实际只是主口令。这里在入口把这种情况打回。

    Raises:
        ValueError: 空文件或超过 :data:`tarpitcrypt.MAX_KEYFILE_BYTES`。
    """
    if keyfile is None:
        return None
    if not keyfile:
        raise ValueError("keyfile 是空文件（0 字节），等于没有第二个因子")
    if len(keyfile) > tc.MAX_KEYFILE_BYTES:
        raise ValueError(f"keyfile 超过 {tc.MAX_KEYFILE_BYTES // 1024} KiB 上限")
    return keyfile


_UNSAFE_FILENAME_CHARS: Final[frozenset[str]] = frozenset({'"', "\\", "/", "\r", "\n"})


def _clean_filename(name: str) -> str:
    """把文件名收敛成可安全写进响应头 / 文件系统的形式。

    去掉引号、反斜杠、路径分隔符和控制字符；中文与普通空格保留。
    """
    cleaned = "".join(
        ch for ch in name if ch.isprintable() and ch not in _UNSAFE_FILENAME_CHARS
    )
    return cleaned.strip() or "download"


def _content_disposition(filename: str) -> str:
    """生成兼容中文文件名的 ``Content-Disposition``。"""
    safe = _clean_filename(filename)
    ascii_name = safe.encode("ascii", "ignore").decode("ascii") or "download"
    return f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(safe)}"


def _safe_output_name(name: str, suffix: str) -> str:
    """从上传的文件名推出下载文件名，去掉路径分隔符与控制字符。"""
    base = _clean_filename(Path(sanitize_member_path(name)).name or "file")
    if suffix and not base.endswith(suffix):
        return base + suffix
    return base


def _parse_content_length(raw: str | None) -> int:
    """解析并校验 Content-Length；负数、非整数、超限一律拒绝。"""
    if raw is None:
        raise ValueError("缺少 Content-Length")
    try:
        length = int(raw)
    except ValueError:
        raise ValueError("Content-Length 不是整数") from None
    if length < 0:
        raise ValueError("Content-Length 不能为负数")
    if length > MAX_BODY_BYTES:
        raise ValueError(f"请求体超过上限 {MAX_BODY_BYTES // (1024 * 1024)} MB")
    return length


# ---------------------------------------------------------------------------
# HTTP 处理器
# ---------------------------------------------------------------------------


class TarpitRequestHandler(BaseHTTPRequestHandler):
    """处理页面与两个 JSON/二进制接口。"""

    server_version = "TarpitCryptWeb/1.0"
    protocol_version = "HTTP/1.1"

    # -- 基础设施 ---------------------------------------------------------

    def log_message(self, fmt: str, *args: Any) -> None:
        """只记录方法与状态，绝不记录求体（口令就在里面）。"""
        sys.stderr.write(f"[web] {self.address_string()} {fmt % args}\n")

    def _origin_allowed(self) -> bool:
        """只放行本机来源的跨源请求。"""
        origin = self.headers.get("Origin")
        if not origin:
            return True  # curl / 同源导航
        host = origin.split("://", 1)[-1].split(":", 1)[0]
        return host in {"127.0.0.1", "localhost", "::1"}

    def _read_body(self) -> bytes:
        """读取请求体；Content-Length 缺失 / 负数 / 超限都拒绝。"""
        length = _parse_content_length(self.headers.get("Content-Length"))
        return self.rfile.read(length)

    def _send_bytes(
        self, status: HTTPStatus, payload: bytes, content_type: str, filename: str | None = None
    ) -> None:
        """回吐一段二进制（文件下载）。"""
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        if filename is not None:
            self.send_header("Content-Disposition", _content_disposition(filename))
        self.end_headers()
        self.wfile.write(payload)

    def _send_json(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
        """回吐一段 JSON。"""
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self._send_bytes(status, body, "application/json; charset=utf-8")

    def _fail(self, status: HTTPStatus, message: str) -> None:
        """统一的错误响应。"""
        self._send_json(status, {"ok": False, "error": message})

    # -- 路由 -------------------------------------------------------------

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler 约定
        """提供 docs/ 里的同一份前端；首页注入本地模式标记。"""
        path = unquote(self.path.split("?", 1)[0])
        if path in ("/", "/index.html"):
            try:
                html = (DOCS_DIR / "index.html").read_text(encoding="utf-8")
            except OSError:
                self._fail(HTTPStatus.INTERNAL_SERVER_ERROR, "找不到 docs/index.html")
                return
            injection = "<script>window.TARPIT_LOCAL = true;"
            if _PATH_TOKEN:
                injection += f' window.TARPIT_PATH_TOKEN = "{_PATH_TOKEN}";'
            injection += "</script>"
            html = html.replace(
                "</head>",
                injection + "\n</head>",
                1,
            )
            self._send_bytes(HTTPStatus.OK, html.encode("utf-8"), "text/html; charset=utf-8")
            return
        if path == "/favicon.ico":
            self._send_bytes(HTTPStatus.OK, b"", "image/gif")
            return

        if path == "/api/armor/profiles":
            armor_core, decoy_kit = _armor_modules()
            self._send_json(
                HTTPStatus.OK,
                {
                    "ok": True,
                    "profiles": list(armor_core.PROFILES),
                    "poisons": list(decoy_kit.POISON_PROFILES),
                    "styles": list(decoy_kit.STYLES),
                    "injections": list(decoy_kit.INJECTION_LEVELS),
                    "defaults": {
                        "layers": 4,
                        "profile": next(iter(armor_core.PROFILES)),
                        "poison": decoy_kit.DEFAULT_POISON,
                        "style": decoy_kit.DEFAULT_STYLE,
                        "injection": decoy_kit.DEFAULT_INJECTION,
                        "sidecar": True,
                    },
                },
            )
            return

        if path.startswith("/api/armor/jobs/"):
            job_id = path.rsplit("/", 1)[-1]
            with _ARMOR_JOBS_LOCK:
                job = _ARMOR_JOBS.get(job_id)
            if job is None:
                self._fail(HTTPStatus.NOT_FOUND, "没有这个任务")
                return
            self._send_json(HTTPStatus.OK, {"ok": True, "job": _public_armor_job(job)})
            return

        if path == "/api/armor/report":
            self._send_json(
                HTTPStatus.OK,
                {"ok": True, **_armor_report_payload()},
            )
            return

        if path.startswith("/api/artifacts/"):
            token = path.rsplit("/", 1)[-1]
            with _ARTIFACT_LOCK:
                artifact = _ARTIFACTS.get(token)
            if artifact is None or not artifact.is_file():
                self._fail(HTTPStatus.NOT_FOUND, "没有这个产出物")
                return
            content_type = (
                mimetypes.guess_type(str(artifact))[0] or "application/octet-stream"
            )
            self._send_bytes(HTTPStatus.OK, artifact.read_bytes(), content_type, artifact.name)
            return

        try:
            target = (DOCS_DIR / path.lstrip("/")).resolve()
            target.relative_to(DOCS_DIR)
        except (OSError, ValueError):
            self._fail(HTTPStatus.NOT_FOUND, "没有这个地址")
            return
        if not target.is_file():
            self._fail(HTTPStatus.NOT_FOUND, "没有这个地址")
            return

        content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type in (
            "application/javascript",
            "application/json",
            "image/svg+xml",
        ):
            content_type += "; charset=utf-8"
        self._send_bytes(HTTPStatus.OK, target.read_bytes(), content_type)

    def do_POST(self) -> None:  # noqa: N802
        """加密 / 解密两个接口。

        注意顺序：**必须先把请求体读干净再回响应**。HTTP/1.1 下带着未读正文
        直接返回并关连接，客户端还在写，会看到 connection reset 而不是我们
        精心构造的 403——跨源请求尤其容易踩到。
        """
        try:
            body = self._read_body()
        except ValueError as exc:
            self.close_connection = True
            self._fail(HTTPStatus.BAD_REQUEST, str(exc))
            return

        try:
            self._dispatch_post(body)
        except tc.DecryptError as exc:
            self._fail(HTTPStatus.UNPROCESSABLE_ENTITY, str(exc))
        except (ValueError, tc.TarpitError) as exc:
            self._fail(HTTPStatus.BAD_REQUEST, str(exc))
        except MemoryError:
            self._fail(HTTPStatus.INSUFFICIENT_STORAGE, "内存不足，请调低 mem 预设")
        except OSError as exc:
            self._fail(HTTPStatus.INTERNAL_SERVER_ERROR, f"服务端错误：{exc}")
        except Exception as exc:  # noqa: BLE001 - 兜底，别让线程带着半截响应退出
            sys.stderr.write(f"[web] 未处理异常：{type(exc).__name__}\n")
            self._fail(HTTPStatus.INTERNAL_SERVER_ERROR, "服务端内部错误，请查看终端日志")

    def _dispatch_post(self, body: bytes) -> None:
        """按路由分发；异常交给 :meth:`do_POST` 统一映射状态码。"""
        if not self._origin_allowed():
            self._fail(HTTPStatus.FORBIDDEN, "拒绝非本机来源的请求")
            return

        route = self.path.rstrip("/")
        if route not in (
            "/api/encrypt",
            "/api/decrypt",
            "/api/reveal",
            "/api/armor/pack",
            "/api/armor/restore",
            "/api/armor/inspect",
            "/api/armor/sidecar",
            "/api/armor/report/clear",
        ):
            self._fail(HTTPStatus.NOT_FOUND, "没有这个接口")
            return

        # reveal 走 JSON，不是 multipart，必须排在表单解析之前
        if route == "/api/reveal":
            self._handle_reveal(body)
            return
        if route == "/api/armor/report/clear":
            _clear_armor_report()
            self._send_json(HTTPStatus.OK, {"ok": True})
            return

        fields, files = parse_form(self.headers.get("Content-Type", ""), body)
        handlers = {
            "/api/encrypt": self._handle_encrypt,
            "/api/decrypt": self._handle_decrypt,
            "/api/armor/pack": self._handle_armor_pack,
            "/api/armor/restore": self._handle_armor_restore,
            "/api/armor/inspect": self._handle_armor_inspect,
            "/api/armor/sidecar": self._handle_armor_sidecar,
        }
        handlers[route](fields, files)

    # -- 业务 -------------------------------------------------------------

    def _handle_encrypt(
        self, fields: dict[str, str], files: list[tuple[str, str, bytes]]
    ) -> None:
        """加密上传的文件或文件夹。"""
        data_files = [(filename, data) for name, filename, data in files if name == "files"]
        password_raw = fields.get("password", "")
        if not password_raw:
            raise ValueError("口令不能为空")
        if not data_files:
            raise ValueError("没有收到任何文件")

        params = params_from_form(fields)
        keyfile = _validate_keyfile(self._pick_file(files, "keyfile"))

        is_bundle = fields.get("bundle") == "1" or len(data_files) > 1
        payload = bundle_files(data_files) if is_bundle else data_files[0][1]

        decoy_password_raw = fields.get("decoy_password", "")
        decoy_file = self._pick_file(files, "decoy")
        if decoy_file is not None and not decoy_password_raw:
            raise ValueError("启用了诱饵文件却没给诱饵口令")
        if decoy_file is None and decoy_password_raw:
            raise ValueError("给了诱饵口令但没有诱饵文件")

        started = time.perf_counter()
        with _CRYPTO_LOCK:
            blob = tc.encrypt(
                payload,
                normalize_password(password_raw),
                params=params,
                keyfile=keyfile,
                decoy_plaintext=decoy_file,
                decoy_password=normalize_password(decoy_password_raw) if decoy_file else None,
            )
        elapsed = time.perf_counter() - started

        first_name = data_files[0][0]
        source_name = (
            Path(sanitize_member_path(first_name)).parts[0] if is_bundle else first_name
        )
        out_name = _safe_output_name(source_name, "") + ".tarpit"
        saved = _save_artifact(out_name, blob)
        artifact = _remember_artifact(saved)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(blob)))
        self.send_header("Content-Disposition", _content_disposition(out_name))
        self.send_header("X-Tarpit-Elapsed", f"{elapsed:.2f}")
        self.send_header("X-Tarpit-Params", json.dumps(
            {"mem": params.mem, "time": params.time, "para": params.para,
             "rounds": params.rounds, "pow": params.pow, "cipher": params.cipher}
        ))
        self.send_header("X-Tarpit-Artifact", artifact)
        self.send_header("X-Tarpit-Saved-Path", quote(str(saved)))
        self.send_header("Access-Control-Expose-Headers",
                         "X-Tarpit-Elapsed, X-Tarpit-Artifact, X-Tarpit-Saved-Path")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(blob)

    def _handle_decrypt(
        self, fields: dict[str, str], files: list[tuple[str, str, bytes]]
    ) -> None:
        """解密上传的 ``.tarpit`` 文件。"""
        data_files = [(filename, data) for name, filename, data in files if name == "files"]
        password_raw = fields.get("password", "")
        # 解密不强制非空：历史上用空口令加密的文件仍要能打开。页面端有
        # 自己的非空校验，这里放行只影响直接调 API 的脚本。
        if len(data_files) != 1:
            raise ValueError("解密一次只能上传一个 .tarpit 文件")

        keyfile = _validate_keyfile(self._pick_file(files, "keyfile"))
        name, blob = data_files[0]

        started = time.perf_counter()
        with _CRYPTO_LOCK:
            plaintext, is_decoy = tc.decrypt(blob, normalize_password(password_raw), keyfile=keyfile)
        elapsed = time.perf_counter() - started

        out_name = _safe_output_name(name, "")
        if out_name.endswith(".tarpit"):
            out_name = out_name[: -len(".tarpit")]
        if zipfile.is_zipfile(io.BytesIO(plaintext)):
            out_name = out_name if out_name.endswith(".zip") else out_name + ".zip"

        safe_name = out_name or "plain.bin"
        saved = _save_artifact(safe_name, plaintext)
        artifact = _remember_artifact(saved)
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(plaintext)))
        self.send_header("Content-Disposition", _content_disposition(out_name or "plain.bin"))
        self.send_header("X-Tarpit-Elapsed", f"{elapsed:.2f}")
        self.send_header("X-Tarpit-Decoy", "1" if is_decoy else "0")
        self.send_header("X-Tarpit-Artifact", artifact)
        self.send_header("X-Tarpit-Saved-Path", quote(str(saved)))
        self.send_header("Access-Control-Expose-Headers",
                         "X-Tarpit-Elapsed, X-Tarpit-Decoy, X-Tarpit-Artifact, X-Tarpit-Saved-Path")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(plaintext)

    def _handle_armor_pack(
        self, fields: dict[str, str], files: list[tuple[str, str, bytes]]
    ) -> None:
        """提交一次 armor 加固任务；真正计算在后台 worker 里跑。"""
        armor_core, decoy_kit = _armor_modules()
        password_raw = fields.get("password", "")
        if not password_raw:
            raise ValueError("口令不能为空")
        source_raw = (fields.get("source_path") or "").strip()
        if source_raw:
            self._require_path_token()
            source_path: Path | None = _local_source_path(source_raw)
            data_files: list[tuple[str, str, bytes]] = []
        else:
            source_path = None
            data_files = [
                (name, filename, data)
                for name, filename, data in files
                if name == "files"
            ]
            if not data_files:
                raise ValueError("没有收到任何文件")

        out_dir = self._armor_out_dir(fields)
        strong, hint = armor_core.check_password_strength(password_raw)
        if not strong:
            raise ValueError(f"口令偏弱：{hint}")

        try:
            layers = int(fields.get("layers", "4"))
        except ValueError:
            raise ValueError("层数必须是整数") from None
        if not 2 <= layers <= 8:
            raise ValueError("层数必须在 2~8 之间")

        profile = fields.get("profile") or next(iter(armor_core.PROFILES))
        if profile not in armor_core.PROFILES:
            raise ValueError(f"未知加固强度：{profile}")
        poison = fields.get("poison") or decoy_kit.DEFAULT_POISON
        if poison not in decoy_kit.POISON_PROFILES:
            raise ValueError(f"未知投毒侧重：{poison}")
        style = fields.get("style") or decoy_kit.DEFAULT_STYLE
        if style not in decoy_kit.STYLES:
            raise ValueError(f"未知拟态风格：{style}")
        injection = fields.get("injection") or decoy_kit.DEFAULT_INJECTION
        if injection not in decoy_kit.INJECTION_LEVELS:
            raise ValueError(f"未知注入强度：{injection}")
        sidecar = fields.get("sidecar", "1").lower() not in ("0", "false", "no", "off", "")

        job = _new_armor_job(
            "pack",
            files=data_files,
            source_path=source_path,
            password=normalize_password(password_raw),
            layers=layers,
            profile=profile,
            sidecar=sidecar,
            poison=poison,
            style=style,
            injection=injection,
            out_dir=out_dir,
        )
        self._send_json(HTTPStatus.ACCEPTED, {"ok": True, "job": job})

    def _handle_armor_restore(
        self, fields: dict[str, str], files: list[tuple[str, str, bytes]]
    ) -> None:
        """提交一次 .armored 还原任务。"""
        password_raw = fields.get("password", "")
        if not password_raw:
            raise ValueError("口令不能为空")
        container_raw = (fields.get("container_path") or "").strip()
        if container_raw:
            self._require_path_token()
            container_path = _local_file_path(container_raw)
            armored = container_path.read_bytes()
            name = container_path.name
        else:
            armored = self._pick_file(files, "files") or self._pick_file(files, "armored")
            if armored is None:
                raise ValueError("没有收到 .armored 文件")
            name = next(
                (
                    filename
                    for field, filename, _data in files
                    if field in ("files", "armored")
                ),
                "restore.armored",
            )
        out_dir = self._armor_out_dir(fields)
        parallel = fields.get("parallel", "0").lower() in ("1", "true", "yes", "on")
        job = _new_armor_job(
            "restore",
            blob=armored,
            password=normalize_password(password_raw),
            name=name,
            parallel=parallel,
            out_dir=out_dir,
        )
        self._send_json(HTTPStatus.ACCEPTED, {"ok": True, "job": job})

    def _handle_armor_sidecar(
        self, fields: dict[str, str], files: list[tuple[str, str, bytes]]
    ) -> None:
        """独立生成伴生诱饵包；不需要口令，也不需要先加固。"""
        _armor_core, decoy_kit = _armor_modules()
        source_raw = (fields.get("source_path") or "").strip()
        if source_raw:
            self._require_path_token()
            source_path: Path | None = _local_source_path(source_raw)
            data_files: list[tuple[str, str, bytes]] = []
        else:
            source_path = None
            data_files = [
                (name, filename, data)
                for name, filename, data in files
                if name == "files"
            ]
            if not data_files:
                raise ValueError("没有收到源程序包")
        try:
            layers = int(fields.get("layers", "4"))
        except ValueError:
            raise ValueError("层数必须是整数") from None
        if not 2 <= layers <= 8:
            raise ValueError("层数必须在 2~8 之间")
        style = fields.get("style") or decoy_kit.DEFAULT_STYLE
        if style not in decoy_kit.STYLES:
            raise ValueError(f"未知拟态风格：{style}")
        poison = fields.get("poison") or decoy_kit.DEFAULT_POISON
        if poison not in decoy_kit.POISON_PROFILES:
            raise ValueError(f"未知投毒侧重：{poison}")
        injection = fields.get("injection") or decoy_kit.DEFAULT_INJECTION
        if injection not in decoy_kit.INJECTION_LEVELS:
            raise ValueError(f"未知注入强度：{injection}")
        container = self._pick_file(files, "armored") or self._pick_file(files, "container")
        container_path = None
        container_raw = (fields.get("container_path") or "").strip()
        if container_raw:
            self._require_path_token()
            container_path = _local_file_path(container_raw)
        out_dir = self._armor_out_dir(fields)
        job = _new_armor_job(
            "sidecar",
            files=data_files,
            source_path=source_path,
            container=container,
            container_path=container_path,
            layers=layers,
            style=style,
            poison=poison,
            injection=injection,
            out_dir=out_dir,
        )
        self._send_json(HTTPStatus.ACCEPTED, {"ok": True, "job": job})

    def _handle_armor_inspect(
        self, fields: dict[str, str], files: list[tuple[str, str, bytes]]
    ) -> None:
        """只读容器摘要，不需要口令。"""
        armor_core, _decoy_kit = _armor_modules()
        path_raw = (fields.get("path") or "").strip()
        if path_raw:
            self._require_path_token()
            blob = _local_file_path(path_raw).read_bytes()
        else:
            blob = self._pick_file(files, "files") or self._pick_file(files, "armored")
        if blob is None:
            raise ValueError("没有收到 .armored 文件")
        info = armor_core.inspect_armored(blob)
        self._send_json(
            HTTPStatus.OK,
            {
                "ok": True,
                "version": info.version,
                "layers": info.layers,
                "totalSize": info.total_size,
                "noteSize": info.note_size,
                "layerSizes": list(info.layer_sizes),
                "digest": info.digest,
            },
        )

    def _handle_reveal(self, body: bytes) -> None:
        """在文件管理器里打开某个产出物（只认服务端登记过的令牌）。"""
        try:
            payload = json.loads(body.decode("utf-8") or "{}")
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise ValueError("请求体不是合法 JSON") from None
        token = str(payload.get("artifact", ""))
        with _ARTIFACT_LOCK:
            path = _ARTIFACTS.get(token)
        if path is None:
            self._fail(HTTPStatus.NOT_FOUND, "没有这条产出物记录（服务重启后会失效）")
            return
        if not path.exists():
            self._fail(HTTPStatus.NOT_FOUND, f"文件已经不在了：{path}")
            return
        try:
            open_in_file_manager(path)
        except OSError as exc:
            self._fail(HTTPStatus.INTERNAL_SERVER_ERROR, f"打不开文件管理器：{exc}")
            return
        self._send_json(HTTPStatus.OK, {"ok": True, "path": str(path)})

    def _require_path_token(self) -> None:
        if _PATH_TOKEN is None:
            return
        if self.headers.get("X-Tarpit-Path-Token") != _PATH_TOKEN:
            raise ValueError("本机路径模式令牌无效")

    def _armor_out_dir(self, fields: dict[str, str]) -> Path:
        raw = (fields.get("out_dir") or "").strip()
        if raw:
            self._require_path_token()
            return _local_out_dir(raw)
        return _resolve_out_subdir(fields.get("out_subdir"))

    @staticmethod
    def _pick_file(files: list[tuple[str, str, bytes]], field: str) -> bytes | None:
        """按表单字段名挑出一个文件的内容。"""
        for name, _filename, data in files:
            if name == field:
                return data
        return None


# ---------------------------------------------------------------------------
# 页面
# ---------------------------------------------------------------------------


def build_handler() -> type[TarpitRequestHandler]:
    """返回绑定了页面内容的处理器类（方便测试替换）。"""
    return TarpitRequestHandler


class TarpitWebServer(ThreadingHTTPServer):
    """带 ``daemon_threads`` 的 HTTP 服务，关闭时不阻塞。"""

    daemon_threads = True
    allow_reuse_address = True


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------


def _configure_stdio() -> None:
    """把标准输出/错误切到 UTF-8，避免 cp1252 控制台上打印中文直接崩。"""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:  # pragma: no cover
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):  # pragma: no cover
            pass


def main(argv: list[str] | None = None) -> int:
    """启动本地 Web 服务。"""
    global _OUT_DIR
    _configure_stdio()
    default_out = _default_out_dir()
    parser = argparse.ArgumentParser(
        prog="tarpitcrypt-web",
        description="TarpitCrypt 本地 Web 入口：拖文件进来，加密文件出去。",
    )
    parser.add_argument("--host", default=HOST, help=f"监听地址，默认 {HOST}（只允许回环）")
    parser.add_argument("--port", type=int, default=PORT, help=f"端口，默认 {PORT}")
    parser.add_argument(
        "--open",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="启动后自动打开浏览器（默认开；用 --no-open 关闭）",
    )
    parser.add_argument(
        "--allow-remote",
        action="store_true",
        help="允许监听非回环地址（口令会以明文 HTTP 经过网络，慎用）",
    )
    parser.add_argument(
        "--out-dir",
        default=str(default_out),
        help=f"加密/解密结果另存到哪个目录，默认 {default_out}",
    )
    args = parser.parse_args(argv)

    loopback_hosts = ("127.0.0.1", "localhost", "::1")
    if args.host not in loopback_hosts:
        if not args.allow_remote:
            print(
                f"拒绝启动：--host={args.host} 不是回环地址。"
                "口令会以明文 HTTP 经过网络；如确需局域网访问，加 --allow-remote 并自担风险。",
                file=sys.stderr,
            )
            return 2
        print(
            "警告：正在监听非回环地址。口令会以明文 HTTP 经过网络，只应绑定 127.0.0.1。",
            file=sys.stderr,
        )

    if not (DOCS_DIR / "index.html").is_file():
        print(
            f"找不到本地前端：{DOCS_DIR / 'index.html'}\n"
            "本地网页版需要从仓库目录运行（或把 docs/ 一起分发）。",
            file=sys.stderr,
        )
        return 2

    _OUT_DIR = Path(args.out_dir).expanduser()
    _OUT_DIR.mkdir(parents=True, exist_ok=True)

    server = TarpitWebServer((args.host, args.port), TarpitRequestHandler)
    url = f"http://{args.host}:{server.server_address[1]}"
    print(f"TarpitCrypt Web 已启动：{url}")
    print(f"加密/解密结果会另存到：{_OUT_DIR}")
    print("Ctrl+C 退出。口令只在本机内存里过一遍，不落盘、不进日志。")
    if args.open:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止。")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
