@echo off
cd /d "%~dp0"
python desktop_web.py %*
if errorlevel 1 pause
