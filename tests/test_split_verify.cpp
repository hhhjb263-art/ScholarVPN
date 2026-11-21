#include "route_manager.h"
#include "platform/iplist.h"

#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <iphlpapi.h>
#endif

namespace {

FILE* g_out = nullptr;

void out(const char* fmt, ...)
{
    char buf[1024]{};
    va_list ap;
    va_start(ap, fmt);
    std::vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    std::printf("%s\n", buf);
    if (g_out != nullptr)
    {
        std::fprintf(g_out, "%s\n", buf);
        std::fflush(g_out);
    }
}

int count_in_table(const std::vector<cidr::Cidr>& cidrs, std::size_t* matchedIndex = nullptr)
{
    PMIB_IPFORWARD_TABLE2 table = nullptr;
    if (::GetIpForwardTable2(AF_INET, &table) != NO_ERROR)
    {
        return -1;
    }
    int n = 0;
    for (ULONG i = 0; i < table->NumEntries; ++i)
    {
        const MIB_IPFORWARD_ROW2& r = table->Table[i];
        if (r.DestinationPrefix.Prefix.si_family != AF_INET)
        {
            continue;
        }
        const uint32_t d = r.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr;
        const uint8_t p = static_cast<uint8_t>(r.DestinationPrefix.PrefixLength);
        for (std::size_t k = 0; k < cidrs.size(); ++k)
        {
            if (cidrs[k].prefix == p && ::htonl(cidrs[k].addr) == d)
            {
                ++n;
                if (matchedIndex != nullptr && k == 0)
                {
                    *matchedIndex = k;
                }
                break;
            }
        }
    }
    ::FreeMibTable(table);
    return n;
}

bool find_one(const cidr::Cidr& c, MIB_IPFORWARD_ROW2& found)
{
    PMIB_IPFORWARD_TABLE2 table = nullptr;
    if (::GetIpForwardTable2(AF_INET, &table) != NO_ERROR)
    {
        return false;
    }
    bool ok = false;
    for (ULONG i = 0; i < table->NumEntries; ++i)
    {
        const MIB_IPFORWARD_ROW2& r = table->Table[i];
        if (r.DestinationPrefix.Prefix.si_family != AF_INET)
        {
            continue;
        }
        if (r.DestinationPrefix.PrefixLength != c.prefix)
        {
            continue;
        }
        if (r.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr != ::htonl(c.addr))
        {
            continue;
        }
        found = r;
        ok = true;
        break;
    }
    ::FreeMibTable(table);
    return ok;
}

std::string next_hop_str(const MIB_IPFORWARD_ROW2& r)
{
    const ULONG nh = r.NextHop.Ipv4.sin_addr.S_un.S_addr;
    char buf[32]{};
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  static_cast<unsigned>(nh & 0xFF),
                  static_cast<unsigned>((nh >> 8) & 0xFF),
                  static_cast<unsigned>((nh >> 16) & 0xFF),
                  static_cast<unsigned>((nh >> 24) & 0xFF));
    return buf;
}

}

int main()
{
#if defined(_WIN32)
    ::SetConsoleOutputCP(CP_UTF8);
#endif

    char path[MAX_PATH]{};
    ::GetTempPathA(MAX_PATH, path);
    std::strcat(path, "split_verify.txt");
    g_out = std::fopen(path, "w");
    out("结果文件: %s", path);

    std::vector<cidr::Cidr> list;
    iplist::Stats st;
    if (!iplist::load_file(CS("chnroute.txt"), list, &st))
    {
        out("FAIL: 当前目录没有 chnroute.txt");
        return 1;
    }
    out("国内网段: %zu 条（坏行 %zu）", list.size(), st.malformed);

    RouteManager rm(tun_id_t{});

    const int before = count_in_table(list);
    out("== 注入前，路由表里已有 %d 条 ==  (非 0 说明上次没清干净)", before);

    const auto t0 = std::chrono::steady_clock::now();
    const int injected = rm.add_bypass_routes(list, CS("8.8.8.8"));
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - t0).count();
    out("== 注入 API 返回 %d / %zu，耗时 %lld ms ==", injected, list.size(),
        static_cast<long long>(ms));

    const int after = count_in_table(list);
    out("== 注入后，路由表里实际有 %d 条 ==  (明显少于 %d = API 假成功)",
        after, injected);

    if (!list.empty())
    {
        MIB_IPFORWARD_ROW2 row{};
        if (find_one(list[0], row))
        {
            out("抽查 %s -> 下一跳 %s, Metric=%lu, IfIndex=%lu",
                cidr::to_string(list[0]).c_str(), next_hop_str(row).c_str(),
                static_cast<unsigned long>(row.Metric),
                static_cast<unsigned long>(row.InterfaceIndex));
            out("        （Metric 必须是 1，否则会被隧道的 0.0.0.0/1 抢走）");
        }
        else
        {
            out("抽查 %s -> 路由表里找不到（注入未真正生效）",
                cidr::to_string(list[0]).c_str());
        }
    }

    rm.remove_split_routes();
    const int afterDelete = count_in_table(list);
    out("== 撤销后，路由表里剩 %d 条 ==  (应为 0)", afterDelete);

    if (g_out != nullptr)
    {
        std::fclose(g_out);
    }

    const bool pass = (after >= injected) && (afterDelete == 0);
    std::printf("\n%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}
