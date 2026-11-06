@echo off
chcp 936 >nul
cd /d "%~dp0"
where pyw >nul 2>nul
if errorlevel 1 goto NOPY
start "" pyw -3 armor_gui.py
goto :EOF
:NOPY
echo 未找到 py 启动器，请安装 Python 3.11 及以上版本。
echo 安装后执行: pip install argon2-cffi cryptography
pause
