# 更新日志

## 0.4.0 —— 彻底精简为「加密后直接运行」

删除全部「加密 → 还原到磁盘才能用」的旧逻辑，项目只保留一条链路：
把程序包加密成单文件 exe，双击输口令即可运行。

### 删除
- v1 文件加密工具 `tarpitcrypt.py`、Web/桌面版 `tarpitcrypt_server.py` /
  `desktop_web.py`、在线版前端 `docs/`、旧测试 `tests/`、旧文档。
- armor 的容器 / 还原 / 诱饵 / 伴生 / 报告逻辑：
  `armor_core.py` `decoy_kit.py` `content_probe.py` `probe_agent.py`
  `agent_eval.py` `container_benchmark.py` `runtime_check.py`
  `armor_metrics.py` `console_utf8.py` `build_exe.py`。
- 旧构建脚本、旧 `打包一件套/`（含 18 MB 旧 exe）。

### 保留并强化
- `runtime_pack.py`（RTPK v1）、`runtime_runner.py`、`build_runner.py`。
- 新增 `check_password()`，核心自包含，不再依赖旧模块。
- 新增 `drop_target.py`：Windows 原生拖放，覆盖整棵 HWND 树，消息只入队列。

### 重写 GUI
- `armor_gui.py` 改为极简单页：拖入程序包 → 口令/确认/强度 → 选启动器 →
  生成加密 exe。移除全部旧页签。
- 启动器可直接在 GUI 内构建。

### 自测
- `selftest.py` 重写为 19 项，覆盖编译、加密、错口令、解密、Zip Slip、
  擦除、尾部注入、篡改检测、拖放、GUI 结构。19/19 通过。

## 0.3.x（历史）
运行时加固初版：在旧 armor 容器之外新增第 4 页签，加密包追加到通用启动器
尾部。该版本已完成历史使命，0.4.0 起旧逻辑整体移除。
