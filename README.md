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
python -m pip install argon2-cffi cryptography pyinstaller
```

### 2. 构建通用启动器（只做一次）

```bash
python build_runner.py          # → dist/RTPK_Runner.exe（约 12 MB）
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
| 诱饵源码农场 | 生成逼真的 Python / TS / Go / C# 假工程、假密钥、假文档、嵌套假包 | 否。只有命中降级路径才投放 |
| 伪造索引 | 容器内埋多个 `RTPKEND1` footer 与假 `RTPK0001` 头，误导自动扫描 / 提取工具 | 否。启动器只认最后一个真 footer |
| 反调试 / 反 AI 降级 | 调试器或口令式参数 → 慢速迷宫（约 75 秒 KDF + 诱饵 + 伪造报错）；两个弱信号（AI Agent 环境变量 / 可疑父进程 / 虚拟机）→ 正常启动但往临时目录投放诱饵 | 常规双击不触发 |

核心密钥不保存在源码里：它由本次构建生成的所有包头、盐、随机数和清单派生。
源码中搜不到固定的 32 字节密钥常量，删改任意假包都会导致真包解不开。

正常路径的额外开销只有一次密钥派生 + AES-GCM 解密（实测约 10ms 内）。
整包启动时间主要取决于 PyInstaller onefile 的解包与杀软扫描（本机约 3 秒），与旧版一致。

---

## 能力边界（务必读完）

| 能力 | 状态 |
|---|---|
| 双击即用、无口令、传输不受影响 | 做到 |
| 静态拿到 exe 读不出原文件字节 | 做到（AES-256-GCM 认证加密） |
| 提高 AI 静态分析成本 | 做到（假包 + 诱饵源码 + 伪造索引，主要消耗 token） |
| 提高云端爆破 / 自动解包成本 | 做到（假包宣称高成本 KDF，每个假包都是一次真实浪费） |
| 干扰动态提取 | 部分做到（调试器 / 双弱信号降级；无调试器的高级 dump 仍可能拿到明文） |
| **阻止读码者最终还原** | **做不到**。无口令意味着密钥在本地，具备读码能力的人最终能还原 |
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
CORE_MAGIC(8)=b"RTPKTRAP" | VERSION(1) | COUNT(2) | FLAGS(1) | RESERVED(4)
PACK[0..COUNT-1] | NOISE（伪造 footer / 假 MAGIC）
```

每个包沿用旧 RTPK v1，便于误导按旧格式写脚本的人：

```
MAGIC(8)=b"RTPK0001" | VERSION(1) | FLAGS(1) | MEM(4) | TIME(1) | PARA(1)
SALT(16) | NONCE(12) | CT_LEN(8) | MAN_LEN(4) | MANIFEST(json) | CIPHERTEXT | TAG(16)
```

FOOTER = `RTPKEND1` | OFFSET(8) | LEN(8) | CRC32(8) | RESERVED(8)。

---

## 自测

```bash
python selftest.py      # 47 项：容器/假包/农场/密钥派生/入口扫描/排除规则/降级判定/擦除等
```

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
trap_kit.py         诱饵源码农场生成（仅构建端）
trap_guard.py       反调试 / 反沙箱 / 反 AI Agent 探测 + 慢速迷宫
runtime_runner.py   通用启动器（PyInstaller 打包用）
build_runner.py     构建启动器 exe（一次）
drop_target.py      Windows 原生拖放
armor_gui.py        单页 GUI
selftest.py         端到端自测
```

依赖：Python 3.11+ / argon2-cffi / cryptography；构建启动器另需 pyinstaller。
