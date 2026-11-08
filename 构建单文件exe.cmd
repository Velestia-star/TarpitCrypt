@echo off
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\build_exe.ps1" %*
if errorlevel 1 pause
