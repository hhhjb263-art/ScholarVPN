@echo off
chcp 65001 >nul
echo ============================================
echo  ScholarVPN 浏览器代理 - 导入服务器证书
echo ============================================
echo.
net session >nul 2>&1
if errorlevel 1 (
    echo [错误] 请右键本文件 -^> "以管理员身份运行"
    pause
    exit /b 1
)
if not exist "%~dp0ca.cert.pem" (
    echo [错误] 未找到 ca.cert.pem
    echo         请把管理员给你的证书文件放到本脚本同一目录后重试
    pause
    exit /b 1
)
echo [*] 正在导入证书...
certutil -addstore -f Root "%~dp0ca.cert.pem"
if errorlevel 1 (
    echo [错误] 导入失败，请把上面的错误信息发给管理员
    pause
    exit /b 1
)
echo.
echo [完成] 证书已导入"受信任的根证书颁发机构"
echo        请【完全退出浏览器】（任务管理器确认没有 msedge.exe / chrome.exe）后重新打开
echo.
pause
