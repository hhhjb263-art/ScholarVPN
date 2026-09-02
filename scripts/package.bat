@echo off
rem ============================================================
rem ScholarVPN 一键打包：编译 Release -> 收集 Qt 依赖 -> 生成安装包
rem 前提：VS2022 / Qt 6.9.1 (D:\Qt) / Inno Setup 6 已安装（路径不对改下面变量）
rem 产物：x64\Release\ScholarVPNsetup.exe（目标机器无需任何环境）
rem ============================================================
setlocal
cd /d "%~dp0.."

set MSBUILD=C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe
set QT_BIN=D:\Qt\6.9.1\msvc2022_64\bin
set ISCC=D:\Program Files (x86)\Inno Setup 6\ISCC.exe

echo [1/3] 编译 Release x64 ...
"%MSBUILD%" VPN_.sln /p:Configuration=Release /p:Platform=x64 /m /v:m /nologo
if errorlevel 1 ( echo 编译失败 & pause & exit /b 1 )

echo [2/3] 收集 Qt 依赖 (windeployqt) ...
"%QT_BIN%\windeployqt.exe" --release --no-translations x64\Release\ScholarVPN.exe
if errorlevel 1 ( echo windeployqt 失败 & pause & exit /b 1 )

echo [3/3] 生成安装包 (Inno Setup) ...
"%ISCC%" ScholarVPN.iss
if errorlevel 1 ( echo 打包失败 & pause & exit /b 1 )

echo.
echo 完成：x64\Release\ScholarVPNsetup.exe
pause
