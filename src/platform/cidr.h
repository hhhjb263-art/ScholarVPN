#pragma once

// ============================================================================
// src/platform/cidr.h —— IPv4 CIDR 解析与规范化
//
// 刻意不依赖 inet_pton：
//   - Windows 是 InetPtonA、Linux 是 inet_pton，名字与错误语义都不同；
//   - 这里只需要"点分十进制 + 可选前缀"，手写 40 行比包一层更省事，
//     而且能给出明确的失败原因（哪一段非法），便于跳过脏数据并计数。
//
// 地址统一用【主机字节序的 uint32】保存：
//   便于按数值排序、做按位与（规范化）；真正下发给路由 API 时再转网络序。
// ============================================================================

#include <cstdint>
#include <cstdio>
#include <string>

namespace cidr {

struct Cidr {
    uint32_t addr = 0;      // 主机字节序
    uint8_t prefix = 0;     // 0..32
};

// 前缀长度对应的掩码（前缀 0 时返回 0，前缀 32 时返回 0xFFFFFFFF）
inline uint32_t mask_of(uint8_t prefix)
{
    return prefix == 0 ? 0u : (0xFFFFFFFFu << (32 - prefix));
}

namespace detail {

inline bool parse_octet(const char*& p, const char* end, uint32_t& out)
{
    if (p >= end || *p < '0' || *p > '9')
    {
        return false;
    }
    uint32_t v = 0;
    int digits = 0;
    while (p < end && *p >= '0' && *p <= '9')
    {
        v = v * 10 + static_cast<uint32_t>(*p - '0');
        if (++digits > 3 || v > 255)
        {
            return false;
        }
        ++p;
    }
    out = v;
    return true;
}

} // namespace detail

// 解析 "1.2.3.0/24" 或 "1.2.3.4"（无前缀按 /32）。
// 容忍首尾空白；拒绝：段数不对、段值越界、前缀越界、尾随垃圾、空串。
inline bool parse(const std::string& text, Cidr& out)
{
    const std::size_t b = text.find_first_not_of(" \t\r\n");
    if (b == std::string::npos)
    {
        return false;
    }
    const std::size_t e = text.find_last_not_of(" \t\r\n");
    const std::string s = text.substr(b, e - b + 1);

    const char* p = s.c_str();
    const char* const end = p + s.size();

    uint32_t oct[4]{};
    for (int i = 0; i < 4; ++i)
    {
        if (!detail::parse_octet(p, end, oct[i]))
        {
            return false;
        }
        if (i < 3)
        {
            if (p >= end || *p != '.')
            {
                return false;
            }
            ++p;
        }
    }

    const uint32_t addr = (oct[0] << 24) | (oct[1] << 16) | (oct[2] << 8) | oct[3];

    uint8_t prefix = 32;
    if (p < end)
    {
        if (*p != '/')
        {
            return false;
        }
        ++p;
        if (p >= end || *p < '0' || *p > '9')
        {
            return false;
        }
        uint32_t v = 0;
        while (p < end && *p >= '0' && *p <= '9')
        {
            v = v * 10 + static_cast<uint32_t>(*p - '0');
            if (v > 32)
            {
                return false;
            }
            ++p;
        }
        if (p != end)
        {
            return false;   // "/24x" 这类尾随垃圾
        }
        prefix = static_cast<uint8_t>(v);
    }

    out.addr = addr;
    out.prefix = prefix;
    return true;
}

// 清掉主机位："1.2.3.4/24" → "1.2.3.0/24"
inline void normalize(Cidr& c)
{
    c.addr &= mask_of(c.prefix);
}

// 输出 "1.2.3.0/24"
inline std::string to_string(const Cidr& c)
{
    char buf[24]{};
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u/%u",
                  static_cast<unsigned>((c.addr >> 24) & 0xFF),
                  static_cast<unsigned>((c.addr >> 16) & 0xFF),
                  static_cast<unsigned>((c.addr >> 8) & 0xFF),
                  static_cast<unsigned>(c.addr & 0xFF),
                  static_cast<unsigned>(c.prefix));
    return buf;
}

// 该网段包含的地址数（/0 = 2^32，必须用 64 位）
inline uint64_t size(const Cidr& c)
{
    return 1ull << (32 - c.prefix);
}

// ip 是否落在 net 内（测试与去重时用）
inline bool contains(const Cidr& net, uint32_t ip)
{
    return (ip & mask_of(net.prefix)) == (net.addr & mask_of(net.prefix));
}

// 数值排序：前缀短的在前（与路由表的最长前缀匹配直觉一致）
inline bool less(const Cidr& a, const Cidr& b)
{
    if (a.addr != b.addr)
    {
        return a.addr < b.addr;
    }
    return a.prefix < b.prefix;
}

} // namespace cidr
