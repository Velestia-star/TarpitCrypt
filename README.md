# TarpitCrypt

> 不是让数据「解不开」，而是让**逆向方判断不了自己是不是找对了**。

TarpitCrypt 是一个**反 AI 逆向的整活项目**。底层是一个本地文件加密工具：
把单次口令猜测的成本钉死在文件头里，每猜一次都要完整执行
`rounds × Argon2id(mem, time, para)`。在此之上，`armor/` 提供图形化加固层，
往逆向链路里投放大量「看起来合理、实际走不通」的线索——诱饵层、死层、
互相矛盾的规格文档、能运行但常量全错的解析器。AI 会反复生成假设、写脚本
验证、推翻重来，每一轮都烧掉上下文和 token。破解者付的不再是电费，是推理
成本；越想一次性看懂，亏得越多。

**边界**：只做信息误导，不执行、不注入、不联网、不接触第三方系统。输出是
容器文件，原程序零改动、用前先还原。**仅用于加固你自己拥有的程序包。**

> 护城河怎么来的、针对哪些真实 AI 逆向工具、利用了它们的哪些盲区，见
> [`armor/` 威胁模型](docs/AI_RE_THREATMODEL.md)；效果量化与待办（含真实
> agent 实测）见 [`docs/AGENT_BENCHMARK.md`](docs/AGENT_BENCHMARK.md)。

---

## 版本说明

| 层面 | 当前值 | 说明 |
| --- | --- | --- |
| 发布版本 | **v0.3.9** | 还原保真度修复：权限位 / 符号链接 / 旧容器兼容，新增 `runtime_check` 可运行性矩阵；v0.3.8 起新增「工具污染」「代理记忆」侧重，见 [CHANGELOG.md](CHANGELOG.md) |
| v1 文件格式 | `VERSION = 1`，`MAGIC = TARPITCR` | `.tarpit` 文件，格式冻结 |
| armor 容器格式 | `VERSION = 3`，`MAGIC = TPARMOR3` | `.armored` 文件；v2 / v0.3.0 容器仍可读 |
| Python 包元数据 | `0.3.9` | `pyproject.toml` |

两层格式互不依赖：`armor/` 只复用 v1 的 Argon2id 与 AES-256-GCM 原语，
**v1 文件格式一个字节没改**。

想直接上手用界面：看 [`armor/README.md`](armor/README.md)，Windows 双击
`armor/启动.bat` 即可拖入加固。想看命令行加密器，继续往下读。

---

## 快速开始

```bash
pip install argon2-cffi cryptography

# 加密
python tarpitcrypt.py encrypt notes.pdf notes.pdf.tarpit
# 解密
python tarpitcrypt.py decrypt notes.pdf.tarpit notes.pdf
# 看文件头（不需要口令）
python tarpitcrypt.py info notes.pdf.tarpit
```

口令通过交互式 `getpass` 输入，或从 stdin 读（`--password-stdin`），
**永远不作为命令行参数**——那样会被 `ps` / 命令行历史记下来。

### 加一个 keyfile

```bash
python tarpitcrypt.py keygen my.key           # 生成 64 字节 keyfile
python tarpitcrypt.py encrypt big.iso big.tarpit --keyfile my.key
python tarpitcrypt.py decrypt big.tarpit big.iso --keyfile my.key
```

keyfile 丢了 = 数据没了。请离线备份（U 盘 / 纸）。别把它和密文放同一个目录。

### 加一个诱饵层

```bash
python tarpitcrypt.py encrypt real.txt out.tarpit --decoy fake.txt
```

同一个文件有两个有效口令：主口令解出 `real.txt`，诱饵口令解出 `fake.txt`。
解密时命中诱饵层，进程退出码是 **2**（见下方退出码表）。

代价：本工具的 `decrypt()` 命中诱饵层前会做两次派生，所以**合法用户会变慢**；
但这不等于攻击者成本翻倍——他只攻主层就能判定一个候选口令失败，不必碰诱饵段。
详见下文「什么情况下不安全」。

### 用 AI 生成的参数

```bash
python tarpitcrypt.py ai-config params.json     # 先校验，看哪些被丢弃
python tarpitcrypt.py encrypt a.txt a.tarpit --ai-config params.json
```

AI 只允许输出下面这些键与值，其他一律丢弃并记 warning——
**AI 永远碰不到口令、密钥、keyfile 的内容，它只产出 JSON 旋钮**：

| 键 | 白名单 |
|---|---|
| `mem` | 262144 / 524288 / 1048576 / 2097152（KiB） |
| `time` | 3 / 4 / 5 |
| `para` | 2 / 4 / 6 |
| `rounds` | 2 / 3 / 4 |
| `pow` | 0 / 16 / 18 / 20 |
| `cipher` | `xchacha20-poly1305` / `aes-256-gcm` |

---

## 在线版（GitHub Pages，纯前端）

把 `docs/` 目录发布成 GitHub Pages 后，可以直接在浏览器里用：

```
https://wei238982377.github.io/TarpitCrypt/
```

**首次启用**：仓库 → Settings → Pages → Source 选 `Deploy from a branch` →
Branch 选 `main`、目录选 `/docs` → Save。之后每次推送自动更新。

和本地网页版的关键区别：**这里没有服务器**。Argon2id 由 `hash-wasm` 编译成
WASM 在浏览器里跑，AEAD 用浏览器原生 WebCrypto，文件一个字节都不会上传。

### 与命令行版完全兼容

网页版产出的 `.tarpit` 和 `tarpitcrypt.py` 产出的**逐字节同格式**，
两边可以互相解开。这不是口号，是有一条专门的双向测试盯着的：

```bash
python -m pytest tests -k browser      # 需要本机装有 Edge/Chrome
```

它做的事：Python 造一份密文嵌进页面 → 无头浏览器解开它、再造一份吐回字节 →
Python 再解开浏览器造的那份，顺带校验浏览器打的 zip。任何一边改了 KDF、
AAD 或字段顺序，这条测试立刻变红。

浏览器版的额外限制（和 CLI 版不同）：

- **只有 AES-256-GCM**。WebCrypto 没有 XChaCha20-Poly1305，这不是偷懒，
  是浏览器确实不提供。
- 强度预设上限压到 **1 GiB**：WASM 在部分设备/移动端分配不到更大的线性内存。
- 跑 Argon2 期间页面会卡住几秒（主线程被 WASM 占满）。这是故意的等待，
  不是卡死；界面上有提示。
- 依赖 `docs/vendor/argon2.umd.min.js`（hash-wasm 4.12.0，MIT，已 vendor
  进仓库，不从 CDN 加载——加密工具不该有运行时供应链依赖）。



## 本地网页版（拖拽即用）

不想碰命令行就用这个。零额外依赖，标准库起服务：

```bash
python tarpitcrypt_server.py --open
# → http://127.0.0.1:8765
```

打开后：**把文件或整个文件夹拖进去** → 输口令 → 点「加密并下载」，
浏览器直接落一个 `.tarpit` 文件。切到「解密」标签，拖回 `.tarpit` 就能解出来。

- 文件夹会被打包成一个 `.tarpit`；解开后是一个 `.zip`（保留目录结构）。
- 支持 keyfile、强度预设、PoW、AEAD 算法、诱饵层。
- 拖入文件夹后，界面上每条文件都带相对路径，能看出结构对不对。

安全边界（务必知道）：

- 只监听 `127.0.0.1`，并校验 `Origin`，拒绝来自其他站点的跨源提交。
- 口令随请求体走**本机回环 HTTP**，不落盘、不进日志、不设 cookie。
  它只在这台机器的内存里存在几秒——但确实存在过。
- Argon2id 是 GiB 级内存硬函数，服务端用一把全局锁把派生过程串行化，
  避免你同时点两次直接把机器 OOM。代价是并发请求要排队。
- 单次请求上限 512 MB（明文、密文都要在内存里过一遍）。
- 网页版不替代 CLI：批量、脚本化、离线环境还是用 `tarpitcrypt.py`。

---

## 单次猜测到底有多贵（本机实测）

| 参数 | 单次尝试耗时 |
|---|---|
| mem=256 MiB, time=3, para=2, rounds=2 | **0.95 s** |
| mem=1 GiB, time=3, para=4, rounds=2 | **3.20 s** |
| mem=1 GiB, time=4, para=4, rounds=3 | **5.86 s** |

> **这些数字是特定机器上的一次观测，不是性能承诺。** 另一台机器实测同一档
> 为 0.47 s。硬件、Python 与 `argon2-cffi` 版本都会影响结果；要复现请用
> 同一份脚本在同一台机器上重跑，别拿表里的秒数当安全保证。

启用诱饵层时，**本工具自带的 `decrypt()` 会做两次 `_derive`**，但这不等于
「破解成本 ×2」：攻击者只攻主层就能判定一个候选口令失败，根本不需要碰诱饵
段。变慢的是合法用户，不是攻击者。早期版本写过 ×2 的说法，已更正。

口径说明：这里的「一次尝试」= 跑完 `_derive` 得到主密钥并完成一次认证。
Argon2id 是内存硬函数，GPU/ASIC 的并行优势被内存带宽卡死，所以这些秒数
**不能靠堆显卡压下去**，只能靠堆内存压——而内存是有货币成本的。

> 一个 8 位随机口令大约 2×10¹⁴ 种组合。按 3.2 s/次计，穷举完需要
> 约 2000 万年。这就是「焦油坑」的全部含义。

---

## 文件格式（VERSION = 1）

所有整数字段大端（`>`）。

| 字段 | 长度 | 说明 |
|---|---|---|
| `MAGIC` | 8 | `b"TARPITCR"` |
| `VERSION` | 1 | `1` |
| `FLAGS` | 1 | bit0=POW, bit1=KEYFILE, bit2=DECOY |
| `KDF参数` | 8 | `>IHBB` → mem(KiB,u32) \| time(u16) \| para(u8) \| rounds(u8) |
| `POW_DIFF` | 1 | 前导零比特数，取值 {0,16,18,20} |
| `SALT` | 32 | 每次加密重新生成 |
| `NONCE` | 24 | 每次加密重新生成（AES-GCM 取前 12 字节） |
| `POW_NONCE` | 8 | PoW 解 |
| `CT_LEN` | 8 | 密文长度 |
| `CT` | `CT_LEN` | 密文（含 16 字节认证标签） |
| `DECOY_NONCE` | 24 | 仅 DECOY 置位时 |
| `DECOY_LEN` | 8 | 仅 DECOY 置位时 |
| `DECOY_CT` | `DECOY_LEN` | 仅 DECOY 置位时 |

头部长 **91 字节**。

**AAD 绑定**：主层 AAD = 整段文件头；诱饵层 AAD = `文件头 ‖ DECOY_NONCE ‖ DECOY_LEN`。
这意味着文件头里任何一个比特被改动，认证都会失败——两段密文也换不了位置。

---

## 为什么安全

- **密钥**：口令与 keyfile 摘要经 HKDF-SHA256 合成为 Argon2id 的输入，
  串行跑 `rounds` 轮，得到 32 字节主密钥。
- **机密性 + 完整性**：AES-256-GCM（或 XChaCha20-Poly1305，若运行库提供），
  16 字节认证标签，密文与文件头都在 AAD 保护下。
  默认用 AES-256-GCM——因为截至 `cryptography` 50.x 它并没有提供
  XChaCha20-Poly1305；选 `--cipher xchacha20-poly1305` 时会**告警并降级**
  到 AES-256-GCM，而不是让程序崩溃。等上游提供该算法，探测会自动启用。
- **随机性**：SALT / NONCE / keyfile / PoW 起点全部来自 `secrets`（操作系统 CSPRNG）。
- **没有自创密码学**：只用 `cryptography` 提供的 AEAD / HKDF，以及
  `argon2-cffi` 的 Argon2id。口令与 keyfile 用 HKDF-SHA256 预哈希合成，
  这是标准的组合方式，不是自研 KDF。
- **文件头先校验后使用**：`mem` / `time` / `para` / `rounds` / `POW_DIFF` 全部
  在进入 Argon2 之前过区间检查，恶意文件没法用超大参数拖死你的机器。

## 什么情况下不安全（请务必读）

1. **口令熵低就全盘皆输。** Argon2 只是把每次尝试变贵，不能把弱口令变强。
   4 位数字 PIN 在 3 秒/次下也只需几小时。用长口令或高熵口令。
2. **keyfile 和密文放在一起等于没有 keyfile**，只是把风险换了个位置。
3. **文件头是明文元数据**：别人能看出你用了多大内存、有没有诱饵层、密文多长。
   这是为「可迁移」付出的代价，VERSION 就是为将来换格式留的口子。
4. **PoW 不增加破解成本。** `POW_NONCE` 就写在文件里，验证只需一次 SHA-256。
   它防控的是「批量低成本造文件」，不是「猜口令」；而且校验发生在
   `_derive` **之后**，Argon2 的钱已经付完，所谓「错误口令的快速拒绝路径」
   省下的只是一次 AEAD，占比可以忽略。真正的成本杠杆是
   `memory_cost × time_cost × rounds`。任何声称 PoW 能拖慢离线破解的说法都不可信。
5. **v1 的诱饵层存在是可见的**（FLAGS.bit2 + DECOY_LEN 明文），命中时还会
   返回 `is_decoy=True`、退出码 2 并写出诱饵明文。它给的是「一个备用口令」，
   **可否认性为零**，也不额外增加攻击者的固定成本。想要「不标记真伪」的
   效果请用 `armor/` 的 v3 容器，两者的设计目标不同。
6. **本工具不防内存取证、不防键盘记录、不防已失陷的主机。** 解密时明文与口令
   一定在内存里出现过。
7. **没有密钥托管。** 口令 + keyfile 丢任何一个，数据永久不可恢复。

---

## 退出码

| 码 | 含义 |
|---|---|
| 0 | 成功 |
| 1 | 参数错误 / 两次口令不一致 |
| 2 | 诱饵层命中 |
| 3 | 解密失败（口令或 keyfile 错误） |
| 4 | 环境错误（依赖缺失、文件不存在等） |

---

## 开发

```bash
pip install argon2-cffi cryptography pytest
python -m pytest tests -o addopts=""   # 88 项：v1 单元 + 固定格式兼容 + keygen 保护 + 浏览器互解 + 控制台编码回归
python -m pytest tests -k browser      # 单跑浏览器 ↔ Python 双向互解（无浏览器时跳过）
python armor/selftest.py               # 194 项
python armor/probe_agent.py            # 模拟逆向轮数对照（加密容器层）
python armor/agent_eval.py --runs 5    # 多轮取样 + 评估报告
python armor/content_probe.py --poison ALL   # 内容层陷阱实测：模拟 AI 逆向 agent 打诱饵包，验证全 TRAPPED 且无真实主机泄露
python -m armor.runtime_check           # 还原保真度与可运行性矩阵：加固→还原→实跑，逐字节 + 权限 + 结构比对
```

### 验证「还原出来还能跑」

加密容器的价值全押在「还原出来的东西和原来一样」上。字节一致**不等于**能跑：
可执行位丢了、只读配置变可写、符号链接变实体文件 —— 这些都不会让「还原成功」
报错，却会让程序行为悄悄变掉。

```bash
python -m armor.runtime_check                      # 跑内置矩阵（16 项）
python -m armor.runtime_check <程序目录>            # 验证真实程序包
python -m armor.runtime_check <程序目录> --run "python main.py"   # 顺带比对运行结果
```

覆盖：内容/权限/结构三方比对、还原后实跑比对 stdout 与退出码、归档内权限位、
只读属性、`.sh` / `.bat` 直接执行、CRLF、UTF-8 BOM、空文件 / 空目录、
中文与空格文件名、大文件、旧格式容器兼容、还原目录可写。

全程离线，只在临时目录操作副本，**原目录一个字节都不改**。

CI 在 3 个系统 × Python 3.11/3.12/3.13 上跑同一套命令，配置见
`.github/workflows/ci.yml`。协作规则见 [CONTRIBUTING.md](CONTRIBUTING.md)，
漏洞报告渠道见 [SECURITY.md](SECURITY.md)。

测试里有两类「不能省」的证据：

- **KDF 黄金向量**：`_derive` 的固定输入 → 固定输出；
- **`tests/fixtures/` 固定格式样本**：四份事先生成并入库的 `.bin`，**只解不加密**。
  其余测试都是「当前代码加密 → 当前代码解密」自洽，改坏 AAD 组成或诱饵段
  顺序时照样全绿；只有这批样本能挡住「已发出的旧文件全解不开」。

任何改动 KDF 流程或文件格式的提交，必须附带：

1. 变更前后的单次尝试成本对比；
2. 对已有文件的影响（不兼容则必须 `VERSION + 1` 并提供迁移脚本）；
3. 新的测试向量（输入、期望输出、口令、keyfile 摘要）。

浏览器版的期望值不是抄一份常量，而是测试时由 Python 侧现算再注入 JS：
它断言的是「两边算出同一个东西」，所以任何一边改了 KDF 都会立刻暴露。

不允许为了「性能」下调 `memory_cost` 或 `time_cost`，也不允许移除 AAD 绑定。

## 兼容性

- v1 `VERSION = 1` 格式冻结。解密端遇到未知 VERSION 直接拒绝，绝不猜测着解。
- 解密端自动识别 AEAD 算法（v1 文件头没有独立的 cipher 字段），
  因此加密时选的算法不影响文件能否被解开。
- `cryptography` 48+ / 50+ 均不提供 `XChaCha20Poly1305`，会自动降级到
  AES-256-GCM；这条降级路径已实测生效。
- armor v3 容器按 v2 的同一二进制布局读取，`MAGIC=TPARMOR2` 的旧
  `.armored` 仍可用主口令还原。

## 作者与贡献者

- [@wei238982377](https://github.com/wei238982377) — 仓库所有者、v1 加密核心与本地 Web 入口
- [@yanmoren](https://github.com/yanmoren) — `armor/` 加固层、GUI、工程化与发布

完整的逐提交记录见仓库 Contributors 页面。欢迎通过 PR 参与，协作约定见
`CONTRIBUTING.md`；安全漏洞请走 `SECURITY.md` 的私下渠道。

## 许可

MIT，版权归 [TarpitCrypt contributors](LICENSE)。
