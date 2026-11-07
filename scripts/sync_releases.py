"""把「在线版」入口同步进所有 GitHub Release 的说明里。

幂等：正文里已经有站点地址的会跳过，重复运行不会叠出一堆重复块。
全程不打印令牌。
"""

from __future__ import annotations

import json
import subprocess
import urllib.error
import urllib.request

REPO = "wei238982377/TarpitCrypt"
SITE = "https://wei238982377.github.io/TarpitCrypt/"

BLOCK = (
    "\n\n---\n\n"
    f"**🌐 在线版（打开即用）**：<{SITE}>\n\n"
    f"**📦 源码仓库**：<https://github.com/{REPO}>\n"
)


def credential() -> str:
    """从 git 凭证助手取令牌。"""
    out = subprocess.run(
        ["git", "credential", "fill"],
        input="protocol=https\nhost=github.com\n\n",
        capture_output=True, text=True, check=True,
    ).stdout
    fields = dict(line.split("=", 1) for line in out.splitlines() if "=" in line)
    return fields["password"]


def api(path: str, token: str, method: str = "GET", payload: dict | None = None) -> tuple[int, bytes]:
    """调用 GitHub API。"""
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(
        f"https://api.github.com{path}",
        data=data,
        method=method,
        headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
            "User-Agent": "dsh",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()


def main() -> int:
    token = credential()

    status, body = api(f"/repos/{REPO}/releases?per_page=100", token)
    if status != 200:
        print(f"读取 release 失败: {status} {body[:200]!r}")
        return 1
    releases = json.loads(body)
    print(f"共 {len(releases)} 个 release，开始同步在线版入口\n")

    changed = skipped = failed = 0
    for release in releases:
        tag = release["tag_name"]
        current = release.get("body") or ""
        if SITE in current:
            print(f"  跳过 {tag}：正文里已有站点地址")
            skipped += 1
            continue
        new_body = current.rstrip() + BLOCK
        code, resp = api(
            f"/repos/{REPO}/releases/{release['id']}",
            token,
            method="PATCH",
            payload={"body": new_body},
        )
        if code == 200:
            print(f"  更新 {tag}：{len(current)} → {len(new_body)} 字符")
            changed += 1
        else:
            print(f"  失败 {tag}：{code} {resp[:160]!r}")
            failed += 1

    print(f"\n更新 {changed} 个，跳过 {skipped} 个，失败 {failed} 个")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
