#pragma once

// ============================================================================
// src/platform/cfgstr.h —— 配置字符串类型（跨平台）
//
// 为什么需要它：
//   配置里的"字符串"在 Windows 是 UTF-16（Win32 INI API 只吃 wchar_t），
//   在 Linux 上 std::ifstream 不接受 std::wstring 路径，locale/路径全是
//   UTF-8 字节流。两套类型混写的结果就是每个 .cpp 里都要 #ifdef。
//
// 约定：
//   cfgstr = Windows: std::wstring   | Linux: std::string(UTF-8)
//   字面量一律写 CS("...")            → Windows: L"..." | Linux: "..."
//   凡是要交给网络/OpenSSL/日志/文件内容的，一律 cfg_to_utf8()
//   凡是拼路径的，一律 cfg_path_join()（业务代码里禁止手写 '\\' 或 '/'）
//
// 注意：本头文件刻意不 include <windows.h>——
//   Config.h 会被 ClientApp.h / GUI 包含，而 Windows 下 windows.h 与
//   winsock2.h 的包含顺序极敏感。实现（cfgstr.cpp）自己按正确顺序包含。
// ============================================================================

#include <cstdint>
#include <string>

#if defined(_WIN32)
using cfgstr = std::wstring;
#define CS(s) L##s
#else
using cfgstr = std::string;
#define CS(s) s
#endif

// cfgstr <-> UTF-8：网络协议、日志、OpenSSL 接口统一用后者
std::string cfg_to_utf8(const cfgstr& s);
cfgstr     cfg_from_utf8(const std::string& s);

// 整数 -> cfgstr（替代 std::to_wstring，两端同名同义）
cfgstr cfg_num(long long value);

// 路径拼接：Windows 用 '\\'，Linux 用 '/'；dir 末尾带不带分隔符都可
cfgstr cfg_path_join(const cfgstr& dir, const cfgstr& name);

// 删除文件：Windows 走 DeleteFileW（支持中文路径），Linux 走 unlink。
// 不要用 std::remove —— 它在 Windows 上按 ANSI 解释路径，含中文的用户目录会静默失败。
bool cfg_unlink(const cfgstr& path);

// 收紧文件权限到"仅属主可读写"（0600）。Windows 分支为空操作（DPAPI 已保证机密性），
// Linux 上用于身份私钥：没有 DPAPI，靠文件权限兜底。
bool cfg_restrict_file(const cfgstr& path);

// 程序配置目录（含尾部路径分隔符）：
//   Windows：%APPDATA%\ScholarVPN\
//   Linux  ：$XDG_CONFIG_HOME/scholarvpn/（未设置则 ~/.config/scholarvpn/）
//   ⚠️ Linux 下若以 sudo 运行，会还原到 sudo 调用者的家目录——否则身份密钥
//      落在 /root 下，下次普通用户运行会生成新身份、服务端当新设备，必须重新注册。
cfgstr cfg_app_dir();

// Windows：%APPDATA%（CSIDL_APPDATA）；Linux：$XDG_CONFIG_HOME 或 ~/.config
// 保留此名是为了不动 Config::GetAppDataRoaming 的既有调用点
cfgstr cfg_config_root();
