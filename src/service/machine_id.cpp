#include "service/machine_id.h"

#include <openssl/evp.h>

#if defined(_WIN32)
// include 顺序照搬 route_manager.h：winsock2/ws2tcpip 必须先于 windows.h，
// 否则 iptypes/netioapi 里的 IP_ADAPTER_ADDRESSES 与 GAA_* 标志不声明
#include <winsock2.h>
#include <ws2tcpip.h>
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "advapi32.lib")
#else
#include <dirent.h>
#include <sys/utsname.h>
#include <fstream>
#endif

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <set>
#include <string>
#include <vector>

namespace service {

namespace {

const char* kFingerprintSalt = "ScholarVPN-Service-v1";

std::string to_hex(const unsigned char* data, unsigned int len)
{
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (unsigned int i = 0; i < len; ++i)
    {
        out.push_back(kHex[data[i] >> 4]);
        out.push_back(kHex[data[i] & 0x0F]);
    }
    return out;
}

// 一次性 SHA-256（OpenSSL 3 的 EVP_Q_digest；失败返回空串）
std::string sha256_hex(const std::string& data)
{
    unsigned char md[EVP_MAX_MD_SIZE]{};
    std::size_t mdLen = 0;
    if (EVP_Q_digest(nullptr, "SHA256", nullptr,
                     data.data(), data.size(), md, &mdLen) != 1)
    {
        return {};
    }
    return to_hex(md, static_cast<unsigned int>(mdLen));
}

std::string wide_to_utf8(const std::wstring& w)
{
    if (w.empty())
    {
        return {};
    }
    const int n = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1,
                                        nullptr, 0, nullptr, nullptr);
    if (n <= 0)
    {
        return {};
    }
    std::string out(static_cast<std::size_t>(n), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &out[0], n, nullptr, nullptr);
    while (!out.empty() && out.back() == '\0')
    {
        out.pop_back();
    }
    return out;
}

} // namespace

std::string fingerprint_of(const std::string& machine_id)
{
    // 只用系统级设备标识：同一台机器上恒定（不随网卡/系统补丁/外设变化）。
    // v1 曾混入 os/cpu/ram/mac——网卡切换（有线↔无线）或系统补丁都会让
    // 同一台机器变成"新设备"，违背"机器码必须是固定值"（2026-10-31 老板要求）。
    // 标识读不到（注册表/文件异常）时返回空指纹——绝不能退化为某个
    // 固定常量，否则所有读失败的机器会共用同一个"设备身份"。
    if (machine_id.empty())
        return {};
    std::string blob = kFingerprintSalt;
    blob += '|';
    blob += machine_id;
    return sha256_hex(blob);
}

std::string hash_macs(const std::vector<std::string>& macs_any_format)
{
    std::set<std::string> normalized;
    for (const std::string& raw : macs_any_format)
    {
        std::string mac;
        for (char c : raw)
        {
            if (c == ':' || c == '-')
            {
                continue;
            }
            mac.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
        if (mac.size() != 12)
        {
            continue;   // 非 EUI-48 长度（InfiniBand 20 位等），不参与指纹
        }
        if (mac == "000000000000")
        {
            continue;   // 未初始化/虚拟占位地址
        }
        normalized.insert(mac);
    }
    if (normalized.empty())
    {
        return {};
    }
    std::string joined;
    for (const std::string& mac : normalized)
    {
        if (!joined.empty())
        {
            joined += ',';
        }
        joined += mac;
    }
    return sha256_hex(joined);
}

#if defined(_WIN32)

namespace {

// RtlGetVersion 不在 SDK 头文件里暴露结构（winnt.h 不一定带），自带同布局定义。
struct OsVersionInfoEx {
    unsigned long dwOSVersionInfoSize;
    unsigned long dwMajorVersion;
    unsigned long dwMinorVersion;
    unsigned long dwBuildNumber;
    unsigned long dwPlatformId;
    wchar_t szCSDVersion[128];
};

std::string collect_os()
{
    using RtlGetVersionFn = long(__stdcall*)(OsVersionInfoEx*);
    const HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    const auto fn = ntdll
        ? reinterpret_cast<RtlGetVersionFn>(::GetProcAddress(ntdll, "RtlGetVersion"))
        : nullptr;
    OsVersionInfoEx vi{};
    vi.dwOSVersionInfoSize = sizeof(vi);
    if (fn == nullptr || fn(&vi) != 0)
    {
        return "Windows";
    }
    // 仅版本号与架构，不含安装路径/用户信息。
    // Windows 11 的主/次版本仍是 10.0，只能按 build 号区分（22000 = 21H2 起）
    const char* family = (vi.dwBuildNumber >= 22000) ? "Windows 11" : "Windows 10";
    return std::string(family) + " build " + std::to_string(vi.dwBuildNumber) + " x64";
}

std::string collect_cpu()
{
    wchar_t buf[256]{};
    DWORD sz = sizeof(buf);
    if (::RegGetValueW(HKEY_LOCAL_MACHINE,
                       L"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
                       L"ProcessorNameString", RRF_RT_REG_SZ,
                       nullptr, buf, &sz) != ERROR_SUCCESS)
    {
        return {};
    }
    return wide_to_utf8(buf);
}

std::uint64_t collect_ram_mb()
{
    MEMORYSTATUSEX ms{};
    ms.dwLength = sizeof(ms);
    if (!::GlobalMemoryStatusEx(&ms))
    {
        return 0;
    }
    return ms.ullTotalPhys / (1024ull * 1024ull);
}

// 只取"物理网卡"的 MAC：以太网(6) 与 Wi-Fi(71)，处于 Up 状态。
// 虚拟网卡（Wintun/虚拟机交换机）的 IfType 不在这两类里，天然被排除，
// 避免装/卸 VPN 虚拟网卡导致指纹漂移。
std::vector<std::string> collect_macs()
{
    std::vector<std::string> macs;
    ULONG bufLen = 16 * 1024;
    std::vector<char> buf(bufLen);
    for (;;)
    {
        const ULONG rc = ::GetAdaptersAddresses(
            AF_UNSPEC,
            GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST |
                GAA_FLAG_SKIP_DNS_SERVER | GAA_FLAG_SKIP_FRIENDLY_NAME,
            nullptr, reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data()), &bufLen);
        if (rc == ERROR_BUFFER_OVERFLOW)
        {
            buf.resize(bufLen);
            continue;
        }
        if (rc != NO_ERROR)
        {
            return macs;
        }
        for (auto ad = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
             ad != nullptr; ad = ad->Next)
        {
            if ((ad->IfType != IF_TYPE_ETHERNET_CSMACD && ad->IfType != IF_TYPE_IEEE80211) ||
                ad->OperStatus != IfOperStatusUp ||
                ad->PhysicalAddressLength == 0)
            {
                continue;
            }
            char hex[3]{};
            std::string mac;
            for (ULONG i = 0; i < ad->PhysicalAddressLength; ++i)
            {
                std::snprintf(hex, sizeof(hex), "%02x", ad->PhysicalAddress[i]);
                mac += hex;
            }
            if (mac.size() == 12)
            {
                macs.push_back(mac);
            }
        }
        break;
    }
    return macs;
}

// 系统级设备标识：HKLM\SOFTWARE\Microsoft\Cryptography\MachineGuid
// （系统安装时生成；重启/功能更新/换网卡/插拔外设都不变）
std::string collect_machine_id()
{
    wchar_t buf[128] = { 0 };
    DWORD sz = sizeof(buf);
    const LSTATUS rc = ::RegGetValueW(HKEY_LOCAL_MACHINE,
                       L"SOFTWARE\\Microsoft\\Cryptography",
                       L"MachineGuid", RRF_RT_REG_SZ,
                       nullptr, buf, &sz);
    if (rc != ERROR_SUCCESS)
    {
        return {};
    }
    const std::string out = wide_to_utf8(buf);
    return out;
}

} // namespace

MachineInfo collect_machine_info()
{
    MachineInfo info;
    info.os = collect_os();
    info.cpu = collect_cpu();
    info.ram_mb = collect_ram_mb();
    const std::string macHash = hash_macs(collect_macs());
    info.mac_hash = macHash;
    info.machine_id = collect_machine_id();
    info.fp = fingerprint_of(info.machine_id);
    return info;
}

#else // ---------------- POSIX / Linux ----------------

namespace {

std::string collect_os()
{
    utsname u{};
    if (::uname(&u) != 0)
    {
        return "Linux";
    }
    return std::string("Linux ") + u.release + " " + u.machine;
}

// /proc/cpuinfo 第一段 "model name"
std::string collect_cpu()
{
    std::ifstream in("/proc/cpuinfo");
    std::string line;
    while (std::getline(in, line))
    {
        const std::string key = "model name";
        if (line.compare(0, key.size(), key) == 0)
        {
            const std::size_t colon = line.find(':');
            if (colon == std::string::npos)
            {
                continue;
            }
            std::string val = line.substr(colon + 1);
            while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
            {
                val.erase(val.begin());
            }
            return val;
        }
    }
    return {};
}

std::uint64_t collect_ram_mb()
{
    std::ifstream in("/proc/meminfo");
    std::string line;
    while (std::getline(in, line))
    {
        if (line.compare(0, 8, "MemTotal") == 0)
        {
            const std::size_t colon = line.find(':');
            if (colon == std::string::npos)
            {
                break;
            }
            const std::uint64_t kb = std::strtoull(line.c_str() + colon + 1, nullptr, 10);
            return kb / 1024ull;
        }
    }
    return 0;
}

// /sys/class/net/*（跳过 lo）的 address 文件
std::vector<std::string> collect_macs()
{
    std::vector<std::string> macs;
    DIR* dir = ::opendir("/sys/class/net");
    if (dir == nullptr)
    {
        return macs;
    }
    while (const dirent* ent = ::readdir(dir))
    {
        const std::string name = ent->d_name;
        if (name == "." || name == ".." || name == "lo")
        {
            continue;
        }
        std::ifstream in("/sys/class/net/" + name + "/address");
        std::string mac;
        std::getline(in, mac);
        if (!mac.empty())
        {
            macs.push_back(mac);
        }
    }
    ::closedir(dir);
    return macs;
}

} // namespace

// 系统级设备标识：/etc/machine-id（fallback /var/lib/dbus/machine-id）
std::string collect_machine_id()
{
    for (const char* path : { "/etc/machine-id", "/var/lib/dbus/machine-id" }) {
        std::ifstream in(path);
        std::string line;
        if (std::getline(in, line)) {
            while (!line.empty() && (line.back() == '\r' || line.back() == '\n'
                                     || line.back() == ' '))
                line.pop_back();
            if (!line.empty())
                return line;
        }
    }
    return {};
}

MachineInfo collect_machine_info()
{
    MachineInfo info;
    info.os = collect_os();
    info.cpu = collect_cpu();
    info.ram_mb = collect_ram_mb();
    const std::string macHash = hash_macs(collect_macs());
    info.mac_hash = macHash;
    info.machine_id = collect_machine_id();
    info.fp = fingerprint_of(info.machine_id);
    return info;
}

#endif // _WIN32

} // namespace service
