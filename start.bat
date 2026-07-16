@echo off
chcp 65001 >nul
echo =============================================
echo    连锁药房管理系统 - 启动脚本
echo =============================================
echo.

:: 检查 Python 是否安装
python --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未检测到 Python，请先安装 Python 3.9+
    pause
    exit /b 1
)
echo [信息] Python 已安装
echo.

:: 安装依赖
echo [信息] 正在安装项目依赖...
pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
if errorlevel 1 (
    echo [错误] 依赖安装失败
    echo 国内用户可使用清华镜像：pip install -r requirements.txt -i https://pypi.tuna.tsinghua.edu.cn/simple
    pause
    exit /b 1
)
echo [信息] 依赖安装完成
echo.

:: 启动应用
echo [信息] 正在启动 Web 服务器...
echo [提示] 请确保 openGauss 数据库已启动，且 init.sql 已执行
echo [地址] http://127.0.0.1:5000
echo.
python app.py

pause