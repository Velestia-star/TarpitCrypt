# TarpitCrypt Armor

把程序包加密成单文件 exe，双击输口令即可运行原程序，明文不长期留盘。

| 文件 | 作用 |
|---|---|
| `runtime_pack.py` | 核心：RTPK v1 加密格式、打包/解密/擦除/尾部注入，含 CLI |
| `runtime_runner.py` | 通用启动器源码，PyInstaller 打包用 |
| `build_runner.py` | 构建启动器 exe（只需一次） |
| `drop_target.py` | Windows 原生拖放，覆盖整棵 HWND 树 |
| `armor_gui.py` | 极简单页 GUI |
| `selftest.py` | 端到端自测（19 项） |

## 用法

```bash
python build_runner.py          # → dist/RTPK_Runner.exe（一次）
python armor_gui.py             # GUI；或下面 CLI
python runtime_pack.py build MyApp -o MyApp_protected.exe \
    --password '...' --runner dist/RTPK_Runner.exe
```

## 边界

静态读分发包拿不到原文件；无口令无法解密；退出后覆写擦除临时目录。
运行时明文必进内存，无法阻止调试器 dump。不做免杀、注入、反沙箱。
免密模式仅混淆，保护极弱。

详见仓库根 README。
