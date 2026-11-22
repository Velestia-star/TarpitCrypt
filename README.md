# TarpitCrypt

**把程序包加密成「双击即可运行」的单文件 exe。**

明文不长期留盘：双击 → 输口令 → 内存解密 → 临时目录运行 → 退出后覆写擦除。
逆向者从分发包里读不到任何原文件字节。

---

## 快速开始

### 1. 装依赖

```bash
python -m pip install argon2-cffi cryptography pyinstaller
```

### 2. 构建通用启动器（只做一次）

```bash
python armor/build_runner.py          # → armor/dist/RTPK_Runner.exe（约 14 MB）
```

### 3. 生成加密 exe

GUI 方式（推荐）：

```bash
python armor/armor_gui.py
```

单页界面：把程序包（文件或文件夹）拖进去 → 填两次口令 → 选启动器 → 点「生成加密 exe」。

命令行方式：

```bash
python armor/runtime_pack.py build MyApp -o MyApp_protected.exe \
    --password '你的口令' --profile 中 --runner armor/dist/RTPK_Runner.exe
python armor/runtime_pack.py inspect MyApp_protected.exe    # 查看包信息，不解密
```

每个程序包只是把加密数据追加到通用启动器尾部，**秒级完成，无需重新 PyInstaller**。

### 4. 分发与运行

只分发 `MyApp_protected.exe`。对方双击 → 输入口令 → 原程序照常运行 →
退出后临时目录被覆写擦除。

---

## 能力边界（务必读完）

| 能力 | 状态 |
|---|---|
| 静态拿到分发 exe 读不出原文件字节 | 做到（AES-256-GCM 认证加密） |
| 无口令无法运行 / 解出原文 | 做到（Argon2id 派生 + 认证标签） |
| 磁盘上不长期留明文 | 做到（临时目录运行，退出覆写擦除） |
| 篡改 exe 尾部数据被检出 | 做到（CRC32 + AEAD 双重校验） |
| 路径穿越（Zip Slip） | 做到（解压前拒绝绝对路径 / `..`） |
| **运行中阻止调试器 dump 内存** | **做不到**。明文必然在内存出现 |
| **阻止屏幕录制 / 键盘记录 / 已失陷主机** | **做不到** |
| **反杀软检测 / 免杀 / 注入第三方 / 反沙箱** | **明确不做** |

免密模式（`--no-password`）把固定密钥写进工具源码，等价于**混淆壳**，挡不住
定向逆向，仅供演示，不要在真实分发里使用。

SSD 磨损均衡会让覆写不保证物理层不可恢复；这里做到的是「同机上普通文件恢复
工具读不到」。`RTPK_DEBUG=1` 可保留临时目录供调试，`RTPK_PASSWORD` 可预填口令
供自动化测试——两者都不写进分发包。

仅用于加固你自己拥有或已获授权的程序包。

---

## 格式

`RTPK v1`，详见 `armor/runtime_pack.py` 模块文档。

```
MAGIC(8)=b"RTPK0001" | VERSION(1) | FLAGS(1) | MEM(4) | TIME(1) | PARA(1)
SALT(16) | NONCE(12) | PAYLOAD_LEN(8) | MANIFEST_LEN(4)
MANIFEST(json) | CIPHERTEXT | TAG(16)
```

单文件 exe 布局：`[runner.exe][RTPK 包][FOOTER]`。
FOOTER = `MAGIC(8)=b"RTPKEND1" | PACK_OFFSET(8) | PACK_LEN(8) | CRC32(8) | RESERVED(8)`。
PE loader 忽略 overlay 之后的数据，追加不影响 exe 执行。

## 自测

```bash
python armor/selftest.py      # 19 项：编译/加密/错口令/解密/擦除/篡改/拖放等
```

## 项目结构

```
armor/
  runtime_pack.py     加密格式、打包/解密/擦除/尾部注入核心 + CLI
  runtime_runner.py   通用启动器（PyInstaller 打包用）
  build_runner.py     构建启动器 exe（一次）
  drop_target.py      Windows 原生拖放（整棵 HWND 树）
  armor_gui.py        极简单页 GUI
  selftest.py         端到端自测
```

依赖：Python 3.11+ / argon2-cffi / cryptography；构建启动器另需 pyinstaller。
