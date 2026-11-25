# TarpitCrypt

**正常双击即用；只有 AI / 自动化逆向时才会踩进成本陷阱。**

分发出去的是一个普通单文件 exe：双击直接运行，不弹口令，正常使用和传输都不受影响。
真正被消耗的是「想把 exe 拆开看」的人：假包、诱饵源码、伪造索引、反调试降级会把
AI 分析、动态提取和云端爆破的时间、token、算力成本成倍放大。

> 只用于加固你自己拥有或已获授权的程序包。

---

## 快速开始

### 1. 装依赖

```bash
python -m pip install argon2-cffi cryptography
```

构建原生启动器需要 Go 1.22+（只构建时用；分发的加固 exe 不需要 Go，也不需要 Python）。
没有 Go 时 `build_runner.py` 会自动回退到 PyInstaller，并需要额外安装：
`python -m pip install pyinstaller`。

### 2. 构建通用启动器（只做一次）

```bash
python build_runner.py
# 优先 → dist/RTPK_Runner.exe（原生 Go，约 3.5 MB）
# 无 Go → PyInstaller 回退（约 12 MB）
```

### 3. 生成加固 exe

GUI 方式（推荐）：

```bash
python armor_gui.py
```

拖入程序包 → 自动识别 / 选择入口 → 设置排除与陷阱 → 选启动器 → 生成。

### 拖入整个文件夹时

- 根目录只有一个 `exe`（或唯一 `bat/cmd/py`）会自动选中；多个入口时在「入口程序」
  下拉框中选择，列表也会扫描两级子目录（如 `bin\app.exe`）。
- 默认排除 `.git`、`__pycache__`、`*.pyc`、`*.pyo`、`*.log`、`*.tmp`、`.env`；
  `node_modules`、`plugins` 等运行时依赖保留。
- 已经加固过的 exe（带 RTPK footer）不会被识别为入口，也不会被再次打包。
- 「程序包」栏会显示将打包的文件数、体积和排除项数；未选入口时不会开始生成。
- 命令行等价参数：`--entry`、`--exclude`、`--no-default-excludes`。

命令行方式：

```bash
# 推荐：每次构建独立编译一份原生启动器（v4，派生参数只存在于机器码）
python runtime_pack.py build MyApp -o MyApp_protected.exe --native \
    --decoys 12 --farm-mb 8 --trap-profile 标准

# 复用通用启动器（v3 容器，头部带多态参数）
python runtime_pack.py build MyApp -o MyApp_protected.exe \
    --runner dist/RTPK_Runner.exe \
    --decoys 12 --farm-mb 8 --trap-profile 标准

python runtime_pack.py inspect MyApp_protected.exe   # 查看真包 / 假包 / 农场统计
```

### 4. 分发与运行

只分发 `MyApp_protected.exe`。对方双击 → 直接运行原程序 → 退出后临时目录被覆写擦除。
没有口令框，没有激活流程。

---

## 四条陷阱链路

| 陷阱 | 做什么 | 正常用户受影响吗 |
|---|---|---|
| 假包 + 昂贵 KDF | 混入 N 个结构合法的假包，头部宣称 Argon2id 384MiB/3 或 1GiB/5；真实密钥随机，永远解不开 | 否。启动器不按头部参数算 |
| 真包分片 + 伪清单 | 真包按 8MB（标准）/ 4MB（激进）分片；所有明文清单都是伪清单，真实入口/文件数/构建时间只存在加密段 | 否 |
| 原生启动器 | Go 标准库实现，单文件约 3.5 MB；无 Python 运行时、无 `.pyc` 可读；启动不依赖 Python 解包 | 否 |
| 每次构建多态化 | v4：容器头不含派生参数；每次构建生成并编译独立的 `deriveKeyV4`，随机字段顺序 / 轮数 / XOR，常量只存在于机器码 | 否 |
| 诱饵源码农场 | 生成逼真的 Python / TS / Go / C# 假工程、假密钥、假文档、嵌套假包 | 否。只有命中降级路径才投放 |
| 伪造索引 | 容器内埋多个 `RTPKEND1` footer 与假 `RTPK0001` 头，误导自动扫描 / 提取工具 | 否。启动器只认最后一个真 footer |
| 分析环境诱饵模式 | 检测 AI Agent 终端（环境变量）、隐藏窗口的终端父进程、常见逆向工具进程、或 15 分钟内新启动的虚拟机；命中时**不解密真实核心**，只解出诱饵工程并弹出常见运行库错误 | 真实桌面双击 / Explorer 启动不触发 |
| 反调试 | 调试器或口令式参数 → 慢速迷宫（约 75 秒 KDF + 诱饵 + 伪造报错） | 常规双击不触发 |

真包不再以单个大包出现：分片大小与假包接近，明文清单里看不到真实入口、
文件数和构建时间。代价是产物变大（通常为原包加密体的 1.3–1.5 倍）。

核心密钥不保存在源码里：它由本次构建生成的所有包头、盐、随机数和清单派生，
并且每次构建的 domain / mask / 轮数 / 字段顺序 / XOR 都不同。v4 把这些参数
直接编译进本次构建专属的派生闭包（`init` 内注入，不再有可读函数名），
**容器头、文件尾部、字符串表都不出现明文参数**；源码中搜不到固定的 32 字节
密钥常量，二进制里也搜不到十六进制或 JSON 形式的参数，删改任意假包都会导致
真包解不开。

### 分析环境诱饵模式

启动时会做一次轻量判定，命中任一条件即进入诱饵模式：

- **AI Agent 终端**：`CLAUDECODE`、`CURSOR_AGENT`、`TRAE_AGENT`、`CODEX_AGENT`、
  `GEMINI_CLI`、`CLINE_ACTIVE`、`AIDER_AGENT` 等环境变量；
- **隐藏窗口的终端**：父进程是 cmd / PowerShell / python / node / bash，且该父进程
  没有可见窗口（AI 调用的 shell 通常没有；人类自己开的终端有窗口，不误伤）；
- **逆向工具进程**：x64dbg / IDA / Ghidra / Procmon / Process Hacker / WinDbg /
  dnSpy / Frida / Cheat Engine 等；
- **新启动的虚拟机**：VMware / VirtualBox / QEMU / Parallels 驱动或进程存在，
  且系统开机不足 15 分钟；或虚拟机 + 终端父进程。

命中后**不会派生核心密钥、不会解密真实包**，只在临时目录解出一批诱饵源码，
3 秒后弹出 `0xc000007b`（缺少运行库）错误框，15 秒自动关闭并擦除。
实测在 `CLAUDECODE=1` 下 HashCrack 包 5.5 秒出现 405 个诱饵文件，
真实 `HashCrack.exe` 与入口批处理为 0；隐藏 shell 启动同样在 3.4 秒进入诱饵；
Explorer 双击（正常用户）7.8 秒后正常执行。

这一层针对的是「AI 直接把 exe 跑起来、盯临时目录拷明文」这种最廉价攻击；
无法覆盖「刻意避开上述特征（改名工具、等虚拟机开机 15 分钟、用资源管理器启动）
+ 人工耐心」的组合，也不做免杀对抗。
反探测可能误伤开发环境，打包时可用 `--no-guard` 或 GUI 取消勾选关闭。

原生启动器用 Go 标准库完成 SHA-256、AES-GCM、ZIP 解包和进程管理，
不携带 Python 运行时或 `.pyc`，读码者面对的是编译后的机器码。
正常路径的额外开销只有一次密钥派生 + 分片解密（实测约 0.2 秒内）；
启动时间主要取决于解压内容和杀软扫描：小包约 1–2 秒，451 MB 的 HashCrack
最近一次实测 9.8 秒出现窗口（含启动器的一次进程/环境判定；此前几轮 8.8–38 秒，
属于杀软扫描波动）。

---

## 能力边界（务必读完）

| 能力 | 状态 |
|---|---|
| 双击即用、无口令、传输不受影响 | 做到 |
| 静态拿到 exe 读不出原文件字节 | 做到（AES-256-GCM 认证加密） |
| 从头部 / 尾部 / 字符串取到派生参数 | 做到（v4：参数只在编译后的机器码里） |
| 提高 AI 静态分析成本 | 做到（假包 + 诱饵源码 + 伪造索引，主要消耗 token） |
| 提高云端爆破 / 自动解包成本 | 做到（假包宣称高成本 KDF，每个假包都是一次真实浪费） |
| 干扰动态提取 | 部分做到（调试器慢速迷宫；AI 环境变量 / 隐藏 shell / 逆向工具 / 新虚拟机 → 诱饵模式，真实包从不解密） |
| **阻止读码者最终还原** | **做不到**。无口令意味着密钥在本地，具备读码能力的人最终能还原 |
| **阻止刻意规避特征的人工动态 dump** | 做不到。真实包一旦解密就会落地，同机进程可读；诱饵模式只覆盖可识别的分析环境 |
| **阻止屏幕录制 / 键盘记录 / 已失陷主机** | 做不到 |
| **反杀软 / 免杀 / 注入第三方 / 反沙箱对抗升级** | 明确不做 |

假包和陷阱都只在本机运行：不联网、不写注册表、不碰第三方进程、不破坏主机。
反探测可能误伤开发环境（IDE / Agent 终端），可在打包时关闭（`--no-guard` 或 GUI 取消勾选）。
SSD 磨损均衡会让覆写不保证物理层不可恢复；这里做到的是「同机上普通文件恢复工具读不到」。
擦除采用「3 秒预算内优先覆写大文件 → 系统命令快速删除」，因此上千个小文件的包
（如 numpy / scipy 源码树）退出时仍会有几秒到约 30 秒延迟；启动器被强杀或子进程
仍占用临时文件时，擦除可能不完整。

---

## 格式

单文件 exe 布局：

```
[runner.exe][RTPKTRAP 容器][FOOTER]
```

容器：

```
CORE_MAGIC(8)=b"RTPKTRAP" | VERSION(1)=4 | COUNT(2) | FLAGS(1) | RESERVED(4)
PACK[0..COUNT-1] | NOISE（伪造 footer / 假 MAGIC）
```

v4 容器头**没有** POLY 段：派生参数编译进启动器的 `deriveKeyV4`。
复用通用启动器时生成 v3 容器，头部才带：

```
POLY_LEN(2) | POLY(json: domain/mask/rounds/order/xor)
```

真包分片（每片解密后的明文）：

```
PART_MAGIC(8)=b"RTPKPART" | VERSION(1) | INDEX(2) | TOTAL(2)
META_LEN(4) | META(json，真实清单) | CHUNK
```

容器里所有包的明文清单都是伪清单；真实入口、文件数、构建时间只在加密的
META 段里，分片大小与假包接近。

每个包沿用旧 RTPK v1，便于误导按旧格式写脚本的人：

```
MAGIC(8)=b"RTPK0001" | VERSION(1) | FLAGS(1) | MEM(4) | TIME(1) | PARA(1)
SALT(16) | NONCE(12) | CT_LEN(8) | MAN_LEN(4) | MANIFEST(json) | CIPHERTEXT | TAG(16)
```

FOOTER = `RTPKEND1` | OFFSET(8) | LEN(8) | CRC32(8) | RESERVED(8)。

---

## 自测

```bash
python selftest.py      # 60 项：容器/分片/伪清单/假包/农场/密钥派生/入口扫描/排除规则/擦除/分析环境判定等
```

## 自攻测试（v4）

构建完成后，在**不知道本次构建参数**的前提下，用公开格式知识尝试破解：

| 攻击 | 结果 |
|---|---|
| 按 v3 方式从头部读 poly | 失败：头部直接是 `RTPK0001` 包体 |
| 容器内找明文 ZIP / 真实入口+文件数 | 失败：全部为伪清单（文件数 4–320，与真实 3159 不符） |
| 默认 v1/v2 派生密钥 | 失败 |
| 默认 domain + 720 种字段顺序 × 1–5 轮 | 失败（3600 组枚举，17.4s） |
| 二进制中扫描候选 32 字节常量当 domain | 失败 |
| `strings` 找 domain/mask/xor 的十六进制或 JSON | 失败：只有 struct tag 名称，没有参数值 |
| PyInstaller / 旧口令接口 | 不存在 |
| AI 终端里运行并复制临时目录 | 拦截：进入诱饵模式，5.5s 出现 405 个诱饵文件，真实入口/文件为 0 |
| 隐藏 shell 启动（不带 AI 环境变量） | 拦截：3.4s 进入诱饵模式，真实程序未执行 |

白盒复核（已知本次 poly）：domain/mask/xor 的十六进制文本、完整 poly JSON 均不在
二进制中，原始字节也不是连续存放。也就是说，攻击者必须反汇编定位 `deriveKeyV4`
并逐条还原常量与顺序，才可能继续——这已超出「自动扫描 + 试默认密钥」的范围。

## 真实程序实测

已用 9 个真实程序包跑通「构建 → 解密 → 解压 → 启动」：

- 单文件：PuTTY（1.6MB）、.NET 单文件 CLI（70MB）、.NET 单文件 WinForms（111MB）
- 文件夹：Python 嵌入版（11MB）、Node.js（35MB / 2448 文件）、NW.js（157MB / 408MB 解压）
- 源码包：six、numpy（7736 文件）、scipy（9155 文件）

全部构建成功，核心解密 0.6–57.5ms。测试报告不随仓库发布，
可用 `selftest.py` 及 README 中的打包命令在本机复现。

## 项目结构

```
runtime_pack.py     容器格式、真包/假包/农场构建、解密、擦除、尾部注入 + CLI
native/main.go      原生 Go 启动器（默认；无 Python/.pyc）
native/poly_gen.go  v4 构建时生成的独立密钥派生函数（默认占位）
trap_kit.py         诱饵源码农场生成（仅构建端）
trap_guard.py       反调试 / 反沙箱 / 反 AI Agent 探测 + 慢速迷宫（PyInstaller 回退用）
runtime_runner.py   通用启动器（PyInstaller 回退用）
build_runner.py     构建启动器 exe（优先原生，缺 Go 时回退）
drop_target.py      Windows 原生拖放
armor_gui.py        单页 GUI
selftest.py         端到端自测
```

依赖：Python 3.11+ / argon2-cffi / cryptography；构建启动器另需 pyinstaller。
