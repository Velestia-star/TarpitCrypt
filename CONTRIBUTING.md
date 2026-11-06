# 协作约定

两人合作的项目，规则写得越早越省事。以下约定同时适用于 v1 加密核心和
`armor/` 加固层。

## 分支与合并

- `main` 保持可用，功能一律走 `feat/…` 分支 + Pull Request，至少另一方看过再合。
- 合并用 **merge commit**，不要 squash —— 贡献归属要能追到具体提交。
- 发版本时打 `vX.Y.Z` tag 并建 Release，CHANGELOG 同步更新。

## 改动前必须先跑

```bash
pip install argon2-cffi cryptography pytest
python -m pytest tests -o addopts=""   # 88 项：v1 单元 + 固定格式兼容 + 浏览器互解 + 编码回归
python armor/selftest.py               # armor 端到端
python armor/probe_agent.py            # 模拟逆向轮数对照
```

CI 会在 3 个系统 × Python 3.11/3.12/3.13 上跑同一套命令。浏览器 ↔ Python
双向互解依赖本机 Edge/Chrome 与 headless WASM，CI 里单独一步且非阻断；
`ruff` 同样暂为建议项（见 `.github/workflows/ci.yml`），存量风格问题清完后
再改成强制。

## 格式冻结是硬约束

`VERSION = 1`（v1 `.tarpit`）和 `VERSION = 3`（armor `.armored`）都已冻结。
`tests/fixtures/` 里是**事先生成并入库的固定样本**，只做解密回归：

- 改动 AAD 组成、头部布局、层顺序、诱饵段位置，都会让这些测试变红；
- 除非决定升格式版本并提供迁移脚本，否则**不要重跑**
  `tests/generate_vectors.py`，也不要手改 `vectors.json`；
- 确需升版本时，在 PR 里写清：旧文件怎么解、迁移脚本在哪、哪个 tag
  之前生成的受影响。

## 「契约 1~5」

源码注释与测试里按「契约 N」组织，但仓库里没有正式的规格文档。这是当初
的输入规格没沉淀下来。在补齐权威版本之前，请以 `tests/` 与源码行为为准，
不要凭编号猜语义；`armor/` 里那些互相矛盾的「规格文档」是**投毒素材**，
不是规格。

## 安全边界

- 只误导，不执行：诱饵与伴生文件全是纯文本，不注入、不联网、不碰第三方系统。
- 不写「这是诱饵」的自曝信号：任何成功/失败标记都会帮逆向方剪枝。
- 漏洞走 `SECURITY.md` 里的私下渠道，不开公开 issue。

## 提交信息

用 `feat(scope):` / `fix(scope):` / `docs:` / `test:` 前缀，正文写「为什么」
而不只是「改了什么」。涉及密码学或格式的地方，附上实测数据与复现命令。
