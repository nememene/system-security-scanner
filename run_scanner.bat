@echo off
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
cd /d "%~dp0"

for /f "delims=" %%i in ('powershell -noprofile -command "[Environment]::GetFolderPath('Desktop')"') do set DESKTOP=%%i

echo ========================================
echo   电脑安全监控扫描工具
echo ========================================
echo.

python main.py -o "%DESKTOP%"
if errorlevel 1 (
    echo.
    echo [错误] 运行失败。请确认已安装 Python 并执行：
    echo   pip install -r requirements.txt
    echo.
    pause
    exit /b 1
)

echo.
echo 扫描完成！报告已保存到桌面（security_report_*.txt）
echo 桌面路径: %DESKTOP%
echo.
pause
