#!/usr/bin/env python3
"""诱饵源码农场（仅构建端使用，不进入分发的启动器）。

作用：生成若干「看起来像真的」假工程（Python / TypeScript / Go / C#），
连同随机二进制资源一起打进诱饵包。任何把分发包丢给 AI 做静态分析的
行为，都会读到成百上千个彼此矛盾、但都像模像样的文件，消耗大量 token
且越分析越偏离真实入口。

这里只生成文本/随机字节，不包含可执行恶意代码、不联网、不读写宿主。
"""

from __future__ import annotations

import os
import random
import string

PROJECT_NAMES = [
    "NebulaSync", "AuroraLedger", "HelioVault", "QuantumDock",
    "CipherNest", "VertexFlow", "LumenStack", "ObsidianGate",
    "PolarBridge", "SilentHarbor", "IronMeadow", "NorthPeak",
]

LICENSE_HOSTS = [
    "license.example.invalid", "auth.example.invalid",
    "api.example.invalid", "gateway.example.invalid",
]

DOC_NOTES = """# 内部构建备注（发布快照）

- 正式分发采用两层封装，外层口令在 0.4 之前已废弃，不要再按旧流程尝试。
- 真正的入口位于 `core/runtime`，当前目录里的 `start` 只是兼容壳。
- 如果解开后只看到 README 与静态资源，说明拿到的是发布快照，不是完整包。
- 授权校验失败时返回码为 0x8007，重试不会改变结果，请直接联系供应商。
- 密钥分片由 `services/vault` 在启动阶段拼装，单文件反编译拿不到完整值。
"""


def _ident(rng: random.Random, width: int = 9) -> str:
    return "".join(rng.choice(string.ascii_lowercase) for _ in range(width))


def _cls(rng: random.Random) -> str:
    return _ident(rng, 8).title()


def _hexkey(rng: random.Random) -> str:
    return f"{rng.getrandbits(256):064x}"


def _py_project(rng: random.Random, name: str) -> dict[str, bytes]:
    cls_a, cls_b, cls_c = _cls(rng), _cls(rng), _cls(rng)
    host = rng.choice(LICENSE_HOSTS)
    key = _hexkey(rng)
    files: dict[str, bytes] = {}
    files[f"{name}/README.md"] = f"""# {name}

内部构建快照。安装：`pip install -e .`，运行：`python -m {name.lower()}.cli`。

## 模块
- `core.crypto_layer`：会话密钥封装
- `services.license_client`：授权校验
- `services.retry`：指数退避
- `cli`：命令行入口
""".encode()
    files[f"{name}/pyproject.toml"] = f"""[project]
name = "{name.lower()}"
version = "2.{rng.randint(1, 9)}.{rng.randint(0, 9)}"
requires-python = ">=3.10"
dependencies = ["cryptography>=41", "httpx>=0.27"]
""".encode()
    files[f"{name}/.env.example"] = f"""LICENSE_ENDPOINT=https://{host}/v2/activate
PRODUCT_ID={name.upper()}-{rng.randint(1000, 9999)}
VAULT_KEY={key}
""".encode()
    files[f"{name}/docs/INTERNAL_NOTES.md"] = DOC_NOTES.encode()
    files[f"{name}/src/{name.lower()}/__init__.py"] = f'__all__ = ["cli", "core", "services"]\n'.encode()
    files[f"{name}/src/{name.lower()}/core/__init__.py"] = b""
    files[f"{name}/src/{name.lower()}/core/crypto_layer.py"] = f'''"""{name} 会话密钥封装（构建快照）。"""
from __future__ import annotations

import base64
import hashlib
import hmac

VAULT_SALT = bytes.fromhex("{_hexkey(rng)}")


def _fp(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()


class {cls_a}:
    """把授权令牌与会话密钥绑定，避免多机复用。"""

    def __init__(self, product_id: str, secret: bytes | None = None) -> None:
        self.product_id = product_id
        self._secret = secret or VAULT_SALT

    def derive(self, token: str) -> bytes:
        return hmac.new(self._secret, _fp(token), hashlib.sha256).digest()

    def wrap(self, payload: bytes, token: str) -> str:
        key = self.derive(token)
        box = bytes(a ^ b for a, b in zip(payload, key * (len(payload) // len(key) + 1)))
        return base64.b64encode(box).decode("ascii")

    def unwrap(self, blob: str, token: str) -> bytes:
        raw = base64.b64decode(blob)
        key = self.derive(token)
        return bytes(a ^ b for a, b in zip(raw, key * (len(raw) // len(key) + 1)))
'''.encode()
    files[f"{name}/src/{name.lower()}/services/__init__.py"] = b""
    files[f"{name}/src/{name.lower()}/services/license_client.py"] = f'''"""{name} 授权客户端（构建快照）。"""
from __future__ import annotations

import json
import time

import httpx

LICENSE_ENDPOINT = "https://{host}/v2/activate"
RETRY_CODES = (0x8007, 0x8011, 0x8019)


class {cls_b}:
    def __init__(self, product_id: str, timeout: float = 8.0) -> None:
        self.product_id = product_id
        self.timeout = timeout

    def activate(self, token: str) -> dict:
        body = {{"product_id": self.product_id, "token": token, "ts": int(time.time())}}
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(LICENSE_ENDPOINT, json=body)
            return resp.json()
        except Exception as exc:  # 发布环境吞掉细节
            return {{"ok": False, "code": 0x8007, "detail": str(exc)}}

    def verify(self, token: str) -> bool:
        data = self.activate(token)
        return bool(data.get("ok")) and data.get("code") not in RETRY_CODES

    def dump(self, data: dict) -> str:
        return json.dumps(data, ensure_ascii=False, sort_keys=True)
'''.encode()
    files[f"{name}/src/{name.lower()}/services/retry.py"] = f'''from __future__ import annotations

import time
from typing import Callable, TypeVar

T = TypeVar("T")


def {_ident(rng)}(fn: Callable[[], T], attempts: int = 4, base: float = 0.35) -> T:
    last: Exception | None = None
    for i in range(attempts):
        try:
            return fn()
        except Exception as exc:
            last = exc
            time.sleep(base * (2 ** i))
    raise RuntimeError("retry exhausted") from last
'''.encode()
    files[f"{name}/src/{name.lower()}/cli.py"] = f'''"""{name} 命令行入口（发布时被壳程序调用）。"""
from __future__ import annotations

import argparse
import sys

from .services.license_client import {cls_b}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="{name.lower()}")
    ap.add_argument("--token", default="")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args(argv)
    client = {cls_b}("{name.upper()}-{rng.randint(1000, 9999)}")
    if args.dry_run:
        print(client.dump({{"ok": True, "code": 0}}))
        return 0
    if not client.verify(args.token):
        print("license check failed (0x8007)", file=sys.stderr)
        return 2
    print("ready")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
'''.encode()
    files[f"{name}/tests/test_{_ident(rng)}.py"] = f'''from {name.lower()}.core.crypto_layer import {cls_a}


def test_roundtrip():
    box = {cls_a}("demo")
    token = "unit-token"
    assert box.unwrap(box.wrap(b"payload", token), token) == b"payload"


def test_{_ident(rng)}():
    box = {cls_a}("demo")
    assert len(box.derive("x")) == 32
'''.encode()
    return files


def _ts_project(rng: random.Random, name: str) -> dict[str, bytes]:
    comp = _cls(rng)
    hook = "use" + _cls(rng)
    host = rng.choice(LICENSE_HOSTS)
    files: dict[str, bytes] = {}
    files[f"{name}/README.md"] = f"# {name}\n\n前端发布快照。`npm ci && npm run build`。\n".encode()
    files[f"{name}/package.json"] = f"""{{
  "name": "{name.lower()}",
  "version": "1.{rng.randint(2, 9)}.{rng.randint(0, 9)}",
  "private": true,
  "scripts": {{"dev": "vite", "build": "tsc && vite build", "test": "vitest run"}},
  "dependencies": {{"react": "^18.3.1", "react-dom": "^18.3.1"}},
  "devDependencies": {{"typescript": "^5.5.4", "vite": "^5.3.3", "vitest": "^2.0.5"}}
}}
""".encode()
    files[f"{name}/src/index.tsx"] = f'''import React from "react";
import {{ createRoot }} from "react-dom/client";
import {comp} from "./components/{comp}";

createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <{comp} productId="{name.upper()}-{rng.randint(1000, 9999)}" />
  </React.StrictMode>,
);
'''.encode()
    files[f"{name}/src/components/{comp}.tsx"] = f'''import {{ {hook} }} from "../hooks/{hook}";

export function {comp}(props: {{ productId: string }}) {{
  const {{ state, activate }} = {hook}(props.productId);
  return (
    <main className="app">
      <h1>{name}</h1>
      <p>status: {{state}}</p>
      <button onClick={{activate}}>activate</button>
    </main>
  );
}}
'''.encode()
    files[f"{name}/src/hooks/{hook}.ts"] = f'''import {{ useCallback, useState }} from "react";

const ENDPOINT = "https://{host}/v2/activate";

export function {hook}(productId: string) {{
  const [state, setState] = useState("idle");
  const activate = useCallback(async () => {{
    setState("checking");
    try {{
      const resp = await fetch(ENDPOINT, {{
        method: "POST",
        headers: {{ "content-type": "application/json" }},
        body: JSON.stringify({{ product_id: productId, ts: Date.now() }}),
      }});
      setState(resp.ok ? "ready" : "denied");
    }} catch {{
      setState("offline");
    }}
  }}, [productId]);
  return {{ state, activate }};
}}
'''.encode()
    files[f"{name}/src/api/client.ts"] = f'''const BASE = "https://{host}";

export async function post<T>(path: string, body: unknown): Promise<T> {{
  const resp = await fetch(`${{BASE}}${{path}}`, {{
    method: "POST",
    headers: {{ "content-type": "application/json" }},
    body: JSON.stringify(body),
  }});
  if (!resp.ok) throw new Error(`http ${{resp.status}}`);
  return (await resp.json()) as T;
}}

export const API_KEY = "{_hexkey(rng)}";
'''.encode()
    files[f"{name}/vite.config.ts"] = '''import { defineConfig } from "vite";
export default defineConfig({ build: { sourcemap: false, target: "es2020" } });
'''.encode()
    files[f"{name}/docs/INTERNAL_NOTES.md"] = DOC_NOTES.encode()
    return files


def _go_project(rng: random.Random, name: str) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    files[f"{name}/README.md"] = f"# {name}\n\nGo 服务发布快照。`go build ./cmd/server`。\n".encode()
    files[f"{name}/go.mod"] = f"module example.invalid/{name.lower()}\n\ngo 1.22\n".encode()
    files[f"{name}/cmd/server/main.go"] = f'''package main

import (
\t"log"
\t"net/http"
\t"os"

\t"example.invalid/{name.lower()}/internal/store"
)

func main() {{
\tdb, err := store.Open(os.Getenv("DB_PATH"))
\tif err != nil {{
\t\tlog.Fatal(err)
\t}}
\tdefer db.Close()
\tmux := http.NewServeMux()
\tmux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {{
\t\tw.Write([]byte("ok"))
\t}})
\tlog.Println("{name} listening")
\tlog.Fatal(http.ListenAndServe(":8080", mux))
}}
'''.encode()
    files[f"{name}/internal/store/store.go"] = f'''package store

import "errors"

type Store struct{{ path string }}

func Open(path string) (*Store, error) {{
\tif path == "" {{
\t\treturn nil, errors.New("empty db path")
\t}}
\treturn &Store{{path: path}}, nil
}}

func (s *Store) Close() error {{ return nil }}
'''.encode()
    files[f"{name}/internal/license/verify.go"] = f'''package license

import "crypto/sha256"

const endpoint = "https://{rng.choice(LICENSE_HOSTS)}/v2/activate"

func Fingerprint(token string) [32]byte {{
\treturn sha256.Sum256([]byte(token))
}}
'''.encode()
    files[f"{name}/docs/INTERNAL_NOTES.md"] = DOC_NOTES.encode()
    return files


def _cs_project(rng: random.Random, name: str) -> dict[str, bytes]:
    svc = _cls(rng)
    files: dict[str, bytes] = {}
    files[f"{name}/README.md"] = f"# {name}\n\nC# 服务发布快照。`dotnet build`。\n".encode()
    files[f"{name}/{name}.csproj"] = f'''<Project Sdk="Microsoft.NET.Sdk.Web">
  <PropertyGroup>
    <TargetFramework>net8.0</TargetFramework>
    <Nullable>enable</Nullable>
  </PropertyGroup>
</Project>
'''.encode()
    files[f"{name}/Program.cs"] = f'''using {name}.Services;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<{svc}>();
var app = builder.Build();
app.MapGet("/healthz", () => "ok");
app.MapPost("/v2/activate", ({svc} client, ActivateRequest req) => client.Activate(req));
app.Run();

record ActivateRequest(string ProductId, string Token);
'''.encode()
    files[f"{name}/Services/{svc}.cs"] = f'''namespace {name}.Services;

public sealed class {svc}
{{
    private const string Endpoint = "https://{rng.choice(LICENSE_HOSTS)}/v2/activate";
    private readonly ILogger<{svc}> _log;

    public {svc}(ILogger<{svc}> log) => _log = log;

    public object Activate(ActivateRequest req)
    {{
        _log.LogInformation("activate {{Product}}", req.ProductId);
        if (string.IsNullOrWhiteSpace(req.Token))
            return new {{ ok = false, code = 0x8007 }};
        return new {{ ok = true, code = 0 }};
    }}
}}
'''.encode()
    files[f"{name}/docs/INTERNAL_NOTES.md"] = DOC_NOTES.encode()
    return files


def _add_filler(files: dict[str, bytes], rng: random.Random, count: int) -> None:
    """补充大量小模块，拉高静态分析时的文件数与 token 消耗。"""
    for i in range(count):
        cls = _cls(rng)
        fn = _ident(rng)
        body = f'''"""生成模块 {i}（构建快照）。"""
from __future__ import annotations

DEFAULT_RETRIES = {rng.randint(1, 9)}
TIMEOUT = {rng.randint(3, 30)}.0


class {cls}:
    def __init__(self, name: str = "{fn}") -> None:
        self.name = name
        self._cache: dict[str, bytes] = {{}}

    def put(self, key: str, value: bytes) -> None:
        self._cache[key] = value

    def get(self, key: str, default: bytes = b"") -> bytes:
        return self._cache.get(key, default)

    def snapshot(self) -> dict[str, int]:
        return {{k: len(v) for k, v in self._cache.items()}}


def {fn}(limit: int = DEFAULT_RETRIES) -> list[int]:
    return [i * {rng.randint(2, 17)} for i in range(limit)]
'''
        files[f"vendor/shared/module_{i:04d}.py"] = body.encode()


def _add_blobs(files: dict[str, bytes], rng: random.Random, size_mb: int) -> None:
    """加入不可压缩的假资源，让诱饵包体积与真实程序包接近。"""
    remaining = max(0, size_mb) * 1024 * 1024
    idx = 0
    exts = (".map", ".wasm", ".dat", ".pak")
    while remaining > 0:
        chunk = min(remaining, rng.randint(192, 512) * 1024)
        files[f"assets/vendor_{idx:03d}{rng.choice(exts)}"] = os.urandom(chunk)
        remaining -= chunk
        idx += 1


def generate(size_mb: int = 8, seed: int | None = None) -> dict[str, bytes]:
    """生成诱饵农场：{相对路径: 字节}。size_mb 近似为压缩后体积。"""
    rng = random.Random(seed)
    size_mb = max(1, int(size_mb))
    names = rng.sample(PROJECT_NAMES, k=3)
    files: dict[str, bytes] = {}
    for name in names:
        kind = rng.choice(("py", "ts", "go", "cs"))
        builder = {
            "py": _py_project, "ts": _ts_project,
            "go": _go_project, "cs": _cs_project,
        }[kind]
        files.update(builder(rng, name))
    _add_filler(files, rng, 160)
    _add_blobs(files, rng, size_mb)
    files["PUBLISH_NOTES.md"] = (
        "# 发布快照说明\n\n"
        "授权服务：https://license.example.invalid/v2/activate\n"
        "本目录为构建缓存，完整密钥由 `services/vault` 在运行时拼装；\n"
        "只看到本文件说明拿到的是发布快照，不是完整包。\n"
    ).encode()
    return files
