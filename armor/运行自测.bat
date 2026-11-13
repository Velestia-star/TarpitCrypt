@echo off
chcp 936 >nul
setlocal enabledelayedexpansion
cd /d "%~dp0"

rem 通用 Python 探测：环境变量 -> 同目录便携版 -> PATH -> py 启动器 -> 常见安装路径
rem 逐一预检依赖，选第一个能跑的；全失败才尝试自动补装。
set "PY="
set "FIRST="
set "PRECHECK=import os,sys;sys.path.insert(0,os.getcwd());import argon2,cryptography,armor_core"

call :TRY "%TARPITCRYPT_PYTHON%"
call :TRY "%~dp0python.exe"
for /f "delims=" %%i in ('where python 2^>nul') do call :TRY "%%i"
if not defined PY (
  where py >nul 2>nul
  if not errorlevel 1 (
    for /f "delims=" %%i in ('py -3 -c "import sys;print(sys.executable)" 2^>nul') do call :TRY "%%i"
  )
)
call :TRY "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
call :TRY "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
call :TRY "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
call :TRY "C:\Python313\python.exe"
call :TRY "C:\Python312\python.exe"
call :TRY "C:\Python311\python.exe"
call :TRY "D:\app\py312\python.exe"

if not defined PY if defined FIRST (
  echo [提示] 候选环境均缺少依赖，尝试自动安装 argon2-cffi cryptography ...
  "!FIRST!" -m pip install --disable-pip-version-check argon2-cffi cryptography
  call :TRY "!FIRST!"
)
if not defined PY (
  echo [错误] 未找到可用的 Python 3.11+ 环境（需 argon2-cffi / cryptography）。
  echo   请安装 Python 并勾选 "Add Python to PATH"，然后执行：
  echo     python -m pip install argon2-cffi cryptography
  echo   或设置环境变量 TARPITCRYPT_PYTHON 指向已装好依赖的 python.exe。
  pause
  exit /b 1
)

echo === 端到端自测 ===
"!PY!" selftest.py
echo.
echo === 模拟逆向轮数对照 ===
"!PY!" probe_agent.py
echo.
echo === 多轮取样评估报告 ===
"!PY!" agent_eval.py --runs 3
echo.
pause

endlocal
exit /b 0

:TRY
if defined PY exit /b 0
if "%~1"=="" exit /b 0
if not exist "%~1" exit /b 0
if not defined FIRST set "FIRST=%~1"
"%~1" -c "%PRECHECK%" >nul 2>&1
if not errorlevel 1 set "PY=%~1"
exit /b 0
