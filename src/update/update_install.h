#pragma once

// ============================================================================
// src/update/update_install.h —— 启动安装器
//
// 只负责"把已经校验过的安装包交给系统安装器"，不做等待：
// Windows 的 Inno 安装器带 /CLOSEAPPLICATIONS，会主动关掉本进程；
// 我们调用后立刻退出，让出文件锁。
// ============================================================================

#include <QString>

namespace update {

// 启动安装器（成功表示"已成功派发"，不代表安装完成）。
// exePath 必须是已完成 SHA-256 校验的本地文件。
// 参数用 QString：路径来自 Qt 侧（QFile），全程同一套堆，不跨 CRT。
bool launch_installer(const QString& exePath, QString& error);

// 统一安装入口：Windows=Inno 静默派发；Linux=解包 tar.gz 后 pkexec 安装
// （polkit 弹认证框，装到 /opt 并更新桌面入口——即「取代旧版」）。
// pkgPath：已完成 SHA-256 校验的安装包（Windows=.exe，Linux=.tar.gz）
bool install_package(const QString& pkgPath, QString& error);


} // namespace update
