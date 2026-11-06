@echo off
chcp 936 >nul
cd /d "%~dp0"
echo 正在打包 TarpitCrypt Armor（首次需 pip install pyinstaller）...
py -3 build_exe.py %*
echo.
if errorlevel 1 (
  echo 打包未完成，请看上面的提示。
) else (
  echo 产物在 dist 目录。
)
pause
