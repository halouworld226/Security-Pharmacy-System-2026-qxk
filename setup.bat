@echo off
chcp 65001 >nul
title 连锁药房管理系统 - 一键部署与安全加固
setlocal enabledelayedexpansion

:: =============================================
::  连锁药房管理系统
::  一键部署与安全加固 - 主控制台
::  华南理工大学 · 计算机与数据安全课程项目
:: =============================================

:: 获取脚本所在目录并切换到该目录（解决 Git Bash Windows路径问题）
set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

:MENU
cls
echo =============================================
echo    连锁药房管理系统
echo    一键部署与安全加固
echo =============================================
echo.
echo  前置要求：
echo    - Docker Desktop 已安装并运行
echo    - Python 3.9+
echo    - Git Bash（执行 .sh 脚本必需）
echo.
echo =============================================
echo  请选择操作：
echo =============================================
echo.
echo    [1] 🚀 完整部署（数据库 + 安全加固 + 防火墙）
echo    [2] 📦 仅部署数据库（deploy.sh）
echo    [3] 🔐 部署 + 安全加固
echo    [4] 🔒 仅运行安全加固（security_hardening.sh）
echo    [5] 🛡️ 配置 Windows 防火墙
echo    [6] 💾 加密备份数据库
echo    [7] 🔄 容灾恢复演练
echo    [8] 📋 查看备份列表
echo.
echo    [0] ❌ 退出
echo.
echo =============================================
set /p choice="请输入选项 [0-8]: "

:: 去除空格
set "choice=%choice: =%"

if "%choice%"=="1" goto FULL_SETUP
if "%choice%"=="2" goto DEPLOY_ONLY
if "%choice%"=="3" goto DEPLOY_AND_HARDEN
if "%choice%"=="4" goto HARDEN_ONLY
if "%choice%"=="5" goto FIREWALL
if "%choice%"=="6" goto BACKUP
if "%choice%"=="7" goto RESTORE_DRILL
if "%choice%"=="8" goto LIST_BACKUPS
if "%choice%"=="0" goto EXIT

echo.
echo [错误] 无效选项，请重新输入
timeout /t 2 /nobreak >nul
goto MENU

:: =============================================
::  选项1：完整部署
:: =============================================
:FULL_SETUP
cls
echo =============================================
echo  🚀 完整部署
echo  步骤：部署数据库 → 安全加固 → 防火墙 → 备份说明
echo =============================================
echo.

:: 检查 Git Bash
where bash >nul 2>&1
if errorlevel 1 (
    echo [错误] 未检测到 Git Bash，请安装 Git for Windows
    echo 下载地址：https://git-scm.com/download/win
    pause
    goto MENU
)

:: Step 1: 部署数据库
echo [1/4] 部署 openGauss 数据库...
echo.
bash deploy.sh
if errorlevel 1 (
    echo.
    echo [错误] 数据库部署失败，请检查日志后重试
    pause
    goto MENU
)
echo.
echo ✅ 数据库部署完成
echo.
pause

:: Step 2: 安全加固
echo.
echo [2/4] 执行数据库安全加固...
echo.
bash security_hardening.sh
if errorlevel 1 (
    echo.
    echo [警告] 安全加固部分步骤未完成，但不影响数据库运行
)
echo.
echo ✅ 安全加固完成
echo.
pause

:: Step 3: 防火墙
cls
echo =============================================
echo [3/4] 配置 Windows 防火墙
echo =============================================
echo.
echo 即将配置数据库端口（5434）IP 白名单
echo 需要管理员权限，请在弹出 UAC 时点击"是"
echo.
echo 放行 IP 范围：
echo   - 127.0.0.1（本机）
echo   - 192.168.0.0/16（内网）
echo   - 172.16.0.0/12（Docker）
echo   - 其他 IP 默认阻止
echo.
pause

powershell -ExecutionPolicy Bypass -File "windows_firewall.ps1"
if errorlevel 1 (
    echo [警告] 防火墙配置未完成，可稍后手动运行选项 [5]
) else (
    echo ✅ 防火墙配置完成
)
echo.
pause

:: Step 4: 备份说明
cls
echo =============================================
echo [4/4] 备份配置说明
echo =============================================
echo.
echo 加密备份脚本已就绪：backup_dr.sh
echo.
echo  手动备份：      bash backup_dr.sh backup
echo  恢复演练：      bash backup_dr.sh restore
echo  查看备份：      bash backup_dr.sh list
echo.
echo  定时备份配置：  bash backup_dr.sh cron-setup
echo.
echo ⚠ 建议配置每天凌晨 2:00 自动备份
echo.
echo =============================================
echo  ✅ 完整部署完成！
echo  应用启动方式：双击 start.bat
echo  或执行：python app.py
echo =============================================
echo.
pause
goto MENU

:: =============================================
::  选项2：仅部署数据库
:: =============================================
:DEPLOY_ONLY
cls
echo =============================================
echo  📦 部署 openGauss 数据库
echo =============================================
echo.
where bash >nul 2>&1
if errorlevel 1 (
    echo [错误] 未检测到 Git Bash
    pause
    goto MENU
)
bash deploy.sh
if errorlevel 1 (
    pause
    goto MENU
)
echo.
echo ✅ 数据库部署完成！可直接执行 start.bat 启动应用
echo.
pause
goto MENU

:: =============================================
::  选项3：部署 + 安全加固
:: =============================================
:DEPLOY_AND_HARDEN
cls
echo =============================================
echo  🔐 部署数据库 + 安全加固
echo =============================================
echo.
where bash >nul 2>&1
if errorlevel 1 (
    echo [错误] 未检测到 Git Bash
    pause
    goto MENU
)
echo [1/2] 部署数据库...
bash deploy.sh
if errorlevel 1 (
    pause
    goto MENU
)
echo.
echo [2/2] 执行安全加固...
bash security_hardening.sh
echo.
echo ✅ 部署 + 安全加固完成
echo.
pause
goto MENU

:: =============================================
::  选项4：仅运行安全加固
:: =============================================
:HARDEN_ONLY
cls
echo =============================================
echo  🔒 数据库安全加固
echo =============================================
echo.
echo  ⚠ 请确保 openGauss 容器已运行（先执行 deploy.sh）
echo.
where bash >nul 2>&1
if errorlevel 1 (
    echo [错误] 未检测到 Git Bash
    pause
    goto MENU
)
bash security_hardening.sh
echo.
pause
goto MENU

:: =============================================
::  选项5：配置 Windows 防火墙
:: =============================================
:FIREWALL
cls
echo =============================================
echo  🛡️ Windows 防火墙配置
echo =============================================
echo.
echo 将配置数据库端口（5434）的 IP 白名单，
echo 需要管理员权限。
echo.
powershell -ExecutionPolicy Bypass -File "windows_firewall.ps1"
if errorlevel 1 (
    echo.
    echo [错误] 防火墙配置失败
    echo 请以管理员身份运行此脚本，或手动执行：
    echo   powershell -ExecutionPolicy Bypass -File windows_firewall.ps1
)
echo.
pause
goto MENU

:: =============================================
::  选项6：备份数据库
:: =============================================
:BACKUP
cls
echo =============================================
echo  💾 数据库加密备份
echo =============================================
echo.
where bash >nul 2>&1
if errorlevel 1 (
    echo [错误] 未检测到 Git Bash
    pause
    goto MENU
)
echo 开始执行加密备份（首次执行可能较慢）...
echo.
bash backup_dr.sh backup
if errorlevel 1 (
    echo.
    echo [错误] 备份失败，请检查 openGauss 容器是否运行
) else (
    echo.
    echo ✅ 备份完成
)
echo.
pause
goto MENU

:: =============================================
::  选项7：容灾恢复演练
:: =============================================
:RESTORE_DRILL
cls
echo =============================================
echo  🔄 容灾恢复演练
echo =============================================
echo.
echo ⚠ 恢复演练会创建一个临时数据库进行恢复验证，
echo   不影响正在运行的生产数据库。
echo.
set /p confirm="确认执行恢复演练？(y/n): "
if /i "!confirm!" neq "y" (
    echo 已取消
    timeout /t 1 /nobreak >nul
    goto MENU
)
echo.
where bash >nul 2>&1
if errorlevel 1 (
    echo [错误] 未检测到 Git Bash
    pause
    goto MENU
)
bash backup_dr.sh restore
echo.
pause
goto MENU

:: =============================================
::  选项8：查看备份列表
:: =============================================
:LIST_BACKUPS
cls
echo =============================================
echo  📋 备份文件列表
echo =============================================
echo.
where bash >nul 2>&1
if errorlevel 1 (
    echo [错误] 未检测到 Git Bash
    pause
    goto MENU
)
bash backup_dr.sh list
echo.
pause
goto MENU

:: =============================================
::  退出
:: =============================================
:EXIT
cls
echo.
echo 感谢使用连锁药房管理系统
echo.
timeout /t 1 /nobreak >nul
exit /b 0
