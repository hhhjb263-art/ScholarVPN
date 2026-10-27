#pragma once

// ============================================================================
// util/utf.h —— 通用辅助函数（编码转换 / 路径 / 校验 / 格式化）
// 全部 inline：任何 .cpp include 本头即可使用，不会产生重复定义。
//
// 跨平台约定（2026-10 起）：
//   配置/路径字符串一律 cfgstr（见 src/platform/cfgstr.h）：
//     Windows = std::wstring，Linux = std::string(UTF-8)
//   需要 UTF-8 字节（网络 / 日志 / OpenSSL / 文件名查找）时用 narrow() 或
//   cfg_to_utf8()；需要回转成配置字符串时用 to_cfgstr() / cfg_from_utf8()。
//   不要再在本头里写 std::wstring —— 那会把 Windows 类型泄漏到 Linux 编译单元。
// ============================================================================

#include "src/platform/cfgstr.h"

#include <cstdint>
#include <cstdio>
#include <fstream>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <arpa/inet.h>
#include <netdb.h>   // getaddrinfo / freeaddrinfo
#include <unistd.h>
#endif

// ---------------------------------------------------------------------------
// 编码转换（薄封装，保留旧调用名，减少改造面）
// ---------------------------------------------------------------------------

// cfgstr -> UTF-8（网络/日志/OpenSSL 只认 UTF-8）
inline std::string narrow(const cfgstr& s)
{
    return cfg_to_utf8(s);
}

// UTF-8 -> cfgstr
inline cfgstr to_cfgstr(const std::string& s)
{
    return cfg_from_utf8(s);
}

// ---------------------------------------------------------------------------
// 路径辅助（管理员运行时 cwd 会变，一律用 exe 目录）
// ---------------------------------------------------------------------------

// 返回 exe 所在目录（带尾部分隔符），失败返回空串
inline std::string get_exe_dir()
{
#if defined(_WIN32)
    wchar_t buffer[MAX_PATH]{};
    const DWORD n = ::GetModuleFileNameW(nullptr, buffer, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return "";
    const std::string path = cfg_to_utf8(cfgstr(buffer, n));
#else
    char buffer[4096]{};
    const ssize_t n = ::readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    if (n <= 0) return "";
    const std::string path(buffer, static_cast<std::size_t>(n));
#endif
    const std::size_t slash = path.find_last_of("\\/");
    if (slash == std::string::npos) return "";
    return path.substr(0, slash + 1);
}

// 查找密钥文件：先 appdata keys 目录，再 exe 目录，最后 exe 目录下的 keys 子目录
inline std::string find_key_file(const std::string& appdata_keys_dir,
                                 const std::string& exe_dir,
                                 const std::string& filename)
{
    const std::string candidates[] = {
        appdata_keys_dir + filename,
        exe_dir + filename,
        exe_dir + "keys/" + filename,
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
#if defined(_WIN32)
    IN_ADDR addr{};
    const cfgstr w = cfg_from_utf8(ip);
    return ::InetPtonW(AF_INET, w.c_str(), &addr) == 1;
#else
    struct in_addr addr{};
    return ::inet_pton(AF_INET, ip.c_str(), &addr) == 1;
#endif
}

// 服务器地址可以是 IPv4，也可以是域名：IP 被封时只需改 DNS 解析，用户不用动配置。
inline bool is_valid_host(const std::string& host)
{
    if (host.empty() || host.size() > 253)
    {
        return false;
    }
    if (is_valid_ipv4(host))
    {
        return true;
    }
    for (char c : host)
    {
        const bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                        (c >= '0' && c <= '9') || c == '-' || c == '.';
        if (!ok)
        {
            return false;
        }
    }
    if (host.front() == '.' || host.back() == '.' || host.front() == '-')
    {
        return false;
    }
    return host.find("..") == std::string::npos;
}

// 把 host（IPv4 字面量或域名）解析成一个 IPv4 点分字符串。
// 只取第一个 A 记录（多 IP 轮询留待后续）。
// ⚠️ 走系统 DNS：必须在默认路由指向 TUN **之前**调用，
//    否则查询会被送进隧道，解析结果可能是服务端出口视角的，甚至直接失败。
inline bool resolve_host(const std::string& host, std::string& outIP)
{
    if (is_valid_ipv4(host))
    {
        outIP = host;   // 已经是 IP，零开销
        return true;
    }
    addrinfo hints{};
    hints.ai_family = AF_INET;          // 只取 IPv4：隧道只承载 IPv4
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || res == nullptr)
    {
        return false;
    }
    char buf[INET_ADDRSTRLEN]{};
    const sockaddr_in* sa = reinterpret_cast<const sockaddr_in*>(res->ai_addr);
#if defined(_WIN32)
    // InetNtopA 的入参不是 const，这里只做格式化不会修改内容
    ::InetNtopA(AF_INET, const_cast<IN_ADDR*>(&sa->sin_addr), buf, sizeof(buf));
#else
    ::inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
#endif
    ::freeaddrinfo(res);
    outIP = buf;
    return !outIP.empty();
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
