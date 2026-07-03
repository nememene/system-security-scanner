@echo off
chcp 65001 >nul
set GIT="D:\Program Files\Git\bin\git.exe"
cd /d "%~dp0"

echo ========================================
echo   上传到 GitHub
echo ========================================
echo.

%GIT% remote get-url origin >nul 2>&1
if errorlevel 1 (
    %GIT% remote add origin https://github.com/nememene/system-security-scanner.git
)

echo 正在推送到 https://github.com/nememene/system-security-scanner ...
echo.
%GIT% push -u origin master

if errorlevel 1 (
    echo.
    echo [提示] 推送失败。请先在 GitHub 创建空仓库：
    echo   1. 打开 https://github.com/new
    echo   2. 仓库名填写: system-security-scanner
    echo   3. 不要勾选 "Add a README file"
    echo   4. 创建后重新双击本脚本，或在项目目录执行: git push -u origin master
    echo.
    pause
    exit /b 1
)

echo.
echo 上传成功！
echo 仓库地址: https://github.com/nememene/system-security-scanner
echo.
pause
