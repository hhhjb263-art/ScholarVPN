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

rem ---- 自动识别该导入哪一张证书 ----
rem 服务端证书有两种生成方式，客户端要导入的文件【不同】：
rem   CA + 叶证书模式（gen-self-signed-cert.sh 不带 --self-signed，默认）：
rem       ca.cert.pem     = 自建 CA，**客户端导入这一张**；服务器用的是 proxy.cert.pem（叶证书）
rem   单张自签模式（gen-self-signed-cert.sh --self-signed）：
rem       proxy.cert.pem  = 证书本身即根，**客户端导入这一张**；此时不存在 ca.cert.pem
rem 以前这里只认 ca.cert.pem，自签模式的用户会一直卡在"未找到 ca.cert.pem"，
rem 浏览器则报 ERR_PROXY_CERTIFICATE_INVALID / certificate unknown。
set "CERTFILE="
if exist "%~dp0ca.cert.pem"    set "CERTFILE=%~dp0ca.cert.pem"
if not defined CERTFILE if exist "%~dp0proxy.cert.pem" set "CERTFILE=%~dp0proxy.cert.pem"

if not defined CERTFILE (
    echo [错误] 本目录下既没有 ca.cert.pem 也没有 proxy.cert.pem
    echo.
    echo         请向管理员索取服务器上 server/keys/ 里的证书文件：
    echo           - CA 模式部署  ：要 ca.cert.pem（不要用服务器的 proxy.cert.pem）
    echo           - 自签模式部署：要 proxy.cert.pem
    echo         放到本脚本同一目录后重试。
    pause
    exit /b 1
)

for %%F in ("%CERTFILE%") do echo [*] 将导入证书: %%~nxF
echo [*] 正在导入到"受信任的根证书颁发机构"...
certutil -addstore -f Root "%CERTFILE%"
if errorlevel 1 (
    echo [错误] 导入失败，请把上面的错误信息发给管理员
    pause
    exit /b 1
)
echo.
echo [完成] 证书已导入"受信任的根证书颁发机构"
echo.
echo 提示 1：若以前导入过旧证书，建议先删掉再导入，避免新旧两张根证书并存：
echo          certutil -delstore Root ScholarVPN
echo 提示 2：必须【完全退出浏览器】后重开——任务管理器里确认 msedge.exe /
echo          chrome.exe 全部结束，否则代理仍会用旧的信任状态。
echo.
pause
