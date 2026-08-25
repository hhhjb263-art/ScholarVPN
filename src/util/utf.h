#pragma once

// ============================================================================
// util/utf.h —— 通用辅助函数（编码转换 / 路径 / 校验 / 格式化）
// 全部 inline：任何 .cpp include 本头即可使用，不会产生重复定义。
// 使用：在目标文件里 #include "util/utf.h"
// ============================================================================

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// 编码转换
// ---------------------------------------------------------------------------

// UTF-16 (std::wstring) -> UTF-8 (std::string)
inline std::string narrow(const std::wstring& s) {
    if (s.empty()) return {};
    const int len = ::WideCharToMultiByte(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                                          nullptr, 0, nullptr, nullptr);
    std::string out(static_cast<size_t>(len), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                          &out[0], len, nullptr, nullptr);
    return out;
}

// UTF-8 (std::string) -> UTF-16 (std::wstring)
inline std::wstring to_wstring(const std::string& s) {
    if (s.empty()) return {};
    const int len = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                                          nullptr, 0);
    std::wstring out(static_cast<size_t>(len), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                          &out[0], len);
    return out;
}

// ---------------------------------------------------------------------------
// 路径辅助（管理员运行时 cwd 会变，一律用 exe 目录）
// ---------------------------------------------------------------------------

// 返回 exe 所在目录（带尾部反斜杠），失败返回空串
inline std::string get_exe_dir() {
    wchar_t buffer[MAX_PATH]{};
    const DWORD n = ::GetModuleFileNameW(nullptr, buffer, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return "";
    const std::wstring path(buffer, n);
    const std::size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return "";
    std::string result;
    result.reserve(slash + 1);
    for (std::size_t i = 0; i <= slash; ++i)
        result.push_back(static_cast<char>(path[i]));
    return result;
}

// 查找密钥文件：先 appdata keys 目录，再 exe 目录，最后 exe 目录下的 keys 子目录
inline std::string find_key_file(const std::string& appdata_keys_dir,
                                 const std::string& exe_dir,
                                 const std::string& filename) {
    const std::string candidates[] = {
        appdata_keys_dir + filename,
        exe_dir + filename,
        exe_dir + "keys\\" + filename
    };
    for (const auto& candidate : candidates) {
        std::ifstream probe(candidate, std::ios::binary);
        if (probe)
            return candidate;
    }
    return appdata_keys_dir + filename;
}

// ---------------------------------------------------------------------------
// 校验 / 解析
// ---------------------------------------------------------------------------

// IPv4 地址是否合法（如 "192.168.1.12"）
inline bool is_valid_ipv4(const std::string& ip) {
    IN_ADDR addr{};
    const std::wstring w(ip.begin(), ip.end());
    return ::InetPtonW(AF_INET, w.c_str(), &addr) == 1;
}

// 解析端口字符串 "1"~"65535"；合法返回 true 并写出 out
inline bool parse_port(const std::string& text, uint16_t& out) {
    try {
        const int v = std::stoi(text);
        if (v < 1 || v > 65535) return false;
        out = static_cast<uint16_t>(v);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

// ---------------------------------------------------------------------------
// 格式化
// ---------------------------------------------------------------------------

// 字节数 -> 可读字符串（自动 B/KB/MB/GB/TB）
inline std::string format_bytes(unsigned long long bytes) {
    static const char* units[] = { "B", "KB", "MB", "GB", "TB", "PB" };
    double value = static_cast<double>(bytes);
    int unit = 0;
    while (value >= 1024.0 && unit < 5) { value /= 1024.0; ++unit; }
    char buf[64]{};
    if (unit == 0) std::snprintf(buf, sizeof(buf), "%llu B", bytes);
    else           std::snprintf(buf, sizeof(buf), "%.2f %s", value, units[unit]);
    return buf;
}
