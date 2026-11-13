@echo off
chcp 936 >nul
setlocal enabledelayedexpansion
cd /d "%~dp0"

rem ============================================================
rem  TarpitCrypt Armor 通用启动器（任意 Windows 环境）
rem  收集多个 Python 候选，逐一预检依赖，选第一个能跑的。
rem  顺序：环境变量 -> 同目录便携版 -> PATH -> py 启动器 -> 常见安装路径
rem  全失败才尝试自动补装 argon2-cffi / cryptography。
rem ============================================================

set "PY="
set "PYW="
set "FIRST="
set "PRECHECK=import os,sys;sys.path.insert(0,os.getcwd());import tkinter,argon2,cryptography,armor_core,decoy_kit,armor_gui"

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
  echo [错误] 未找到可用的 Python 3.11+ 环境（需 tkinter / argon2-cffi / cryptography）。
  echo   请安装 Python 3.11+，勾选 "Add Python to PATH" 与 "tcl/tk and IDLE"，然后执行：
  echo     python -m pip install argon2-cffi cryptography
  echo   也可设置环境变量 TARPITCRYPT_PYTHON 指向已装好依赖的 python.exe。
  pause
  exit /b 1
)

rem --- 由 python.exe 推导 pythonw.exe，避免黑窗口 ---
if defined TARPITCRYPT_PYTHONW if exist "%TARPITCRYPT_PYTHONW%" set "PYW=%TARPITCRYPT_PYTHONW%"
if not defined PYW if exist "%~dp0pythonw.exe" set "PYW=%~dp0pythonw.exe"
if not defined PYW (
  for %%i in ("!PY!") do if exist "%%~dpipythonw.exe" set "PYW=%%~dpipythonw.exe"
)
if not defined PYW set "PYW=!PY!"

start "" "!PYW!" -c "import sys,os;sys.path.insert(0,os.getcwd());import armor_gui;armor_gui.main()"
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
