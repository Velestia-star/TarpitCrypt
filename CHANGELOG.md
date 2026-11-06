# 更新日志

版本号遵循语义化版本，但项目仍在 0.x：格式版本（`VERSION`）与发布版本
是两回事，见 README「版本说明」。

## v0.3.0 — 2026-11-06

第一个正式发布版本。核心玩法闭环，工程化补齐，效果可量化。

### 新增

- **S 级加固（v3 容器，`armor/`）**：调试口令改为每个容器随机派生，源码
  不再有可复用口令池；掺入任何线索口令都解不开的「死层」，让「解开
  N-1 层后剩下那层必然是真层」的排除法失效；诱饵包按真包统计特征随机
  生成，所有层补齐到同一尺寸，按大小剪枝也失效。v2 二进制布局保留，
  旧 `.armored` 仍可用主口令还原。
- **A 级：效果可证明、可配置**：新增 `armor/agent_eval.py`（多轮取样 +
  token 量级估算 + Markdown 报告）、`armor/armor_metrics.py` 与 GUI
  「运行报告」页（错误口令、层尝试、耗时、导出 CSV / Markdown，数据只在
  本地内存）；伴生诱饵新增三种「投毒侧重」，按目标 agent 习惯换线索组合。
- **B 级：工程化**：GitHub Actions CI（3 系统 × Python 3.11/3.12/3.13，
  跑 pytest + armor selftest + 模拟逆向冒烟）；`tests/fixtures/` 四份 v1
  固定格式向量与只读解密回归；`ruff.toml`、`SECURITY.md`、
  `CONTRIBUTING.md`、`docs/AGENT_BENCHMARK.md`；README 作者与贡献者段。
- **C 级：易用与分发**：跨平台「选择文件 / 文件夹」（拖放仍为 Windows
  原生消息）、跨平台打开输出目录、口令强度体检、输出覆盖二次确认、
  低内存档并行尝试各层（最多 4 线程）、源文件上限可用
  `TARPIT_MAX_SOURCE_BYTES` 调整、PyInstaller 打包脚本。

### 修复

- `keygen` 不再静默覆盖已有 keyfile（改用独占创建 `O_EXCL`）。
- 顶部 docstring 关于 keyfile 走 Argon2 `secret` / pepper 的说法与实现
  不符：实际是先用 **HKDF-SHA256** 把口令与 keyfile 合成，再作为单一
  输入喂给 Argon2id。文档已改正。
- README 中「诱饵层让破解成本 ×2」「PoW 提供极廉价快速拒绝路径」两处
  与实测不符的论断已改写；性能表注明是特定机器的观测值，不是承诺。
- LICENSE 版权人由单一署名改为 `TarpitCrypt contributors`（署名细节见
  README）。

### 验证

- `pytest`：81 passed（42 项 v1 单元 + Web 入口 + 21 项固定格式兼容断言
  + 4 项 keygen 覆盖保护）。
- `ruff check .`：All checks passed（`E4/E7/E9/F` 规则集）。
- `armor/selftest.py`：62/62 通过。
- GUI 无头全流程（异步加固 / 伴生 / 并行还原 / 报告页）通过。
- `agent_eval.py`：基线 3 轮拿到真包，盲 agent 约 30~34 轮且无从确证；
  读源码 agent 无法确定性定位真层（v2 时期同样算法 21 轮即可锁定）。
  轮数为模拟下界，真实 agent 实测待补。

## v0.2.0 — 2026-11-06（未打 tag，回溯标记）

图形化加固工具首次进入 `main`（PR #1）：拖放 GUI、v2 多层容器、明文
规格草稿投毒、伴生诱饵包、安全解包。

## v0.1.0 — 2026-11-06（未打 tag，回溯标记）

v1 加密核心：串行 Argon2id + AEAD，CLI 五个子命令，42 个 pytest；
随后补入本地 Web 入口。
