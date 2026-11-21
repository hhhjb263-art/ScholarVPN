#pragma once

#include <cstdint>
#include <cstdio>
#include <string>

namespace cidr {

struct Cidr {
    uint32_t addr = 0;
    uint8_t prefix = 0;
};

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

}

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
            return false;
        }
        prefix = static_cast<uint8_t>(v);
    }

    out.addr = addr;
    out.prefix = prefix;
    return true;
}

inline void normalize(Cidr& c)
{
    c.addr &= mask_of(c.prefix);
}

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

inline uint64_t size(const Cidr& c)
{
    return 1ull << (32 - c.prefix);
}

inline bool contains(const Cidr& net, uint32_t ip)
{
    return (ip & mask_of(net.prefix)) == (net.addr & mask_of(net.prefix));
}

inline bool less(const Cidr& a, const Cidr& b)
{
    if (a.addr != b.addr)
    {
        return a.addr < b.addr;
    }
    return a.prefix < b.prefix;
}

}
