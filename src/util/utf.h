#pragma once

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
#include <netdb.h>
#include <unistd.h>
#endif

inline std::string narrow(const cfgstr& s)
{
    return cfg_to_utf8(s);
}

inline cfgstr to_cfgstr(const std::string& s)
{
    return cfg_from_utf8(s);
}

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

inline bool resolve_host(const std::string& host, std::string& outIP)
{
    if (is_valid_ipv4(host))
    {
        outIP = host;
        return true;
    }
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || res == nullptr)
    {
        return false;
    }
    char buf[INET_ADDRSTRLEN]{};
    const sockaddr_in* sa = reinterpret_cast<const sockaddr_in*>(res->ai_addr);
#if defined(_WIN32)
    ::InetNtopA(AF_INET, const_cast<IN_ADDR*>(&sa->sin_addr), buf, sizeof(buf));
#else
    ::inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf));
#endif
    ::freeaddrinfo(res);
    outIP = buf;
    return !outIP.empty();
}

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
