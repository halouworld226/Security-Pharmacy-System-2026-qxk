@echo off
chcp 65001 >nul
title 安全加固验证

cd /d "%~dp0"
echo 正在执行安全验证...
echo.
bash verify_security.sh

echo.
echo 如需复制结果，请选中上方文字后按 Enter
pause
