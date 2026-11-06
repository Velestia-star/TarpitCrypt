@echo off
chcp 936 >nul
cd /d "%~dp0"
py -3 selftest.py
echo.
py -3 probe_agent.py
echo.
pause
