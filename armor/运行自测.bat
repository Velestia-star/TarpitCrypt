@echo off
chcp 936 >nul
cd /d "%~dp0"
echo === 端到端自测 ===
py -3 selftest.py
echo.
echo === 模拟逆向轮数对照 ===
py -3 probe_agent.py
echo.
echo === 多轮取样评估报告 ===
py -3 agent_eval.py --runs 3
echo.
pause
