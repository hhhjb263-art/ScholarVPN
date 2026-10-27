// ============================================================================
// tests/diag_split_readonly.cpp —— 分流状态只读诊断【不需要管理员】
//
// 只读系统路由表，不修改任何东西。用法：
//   1. 客户端连接成功（选「智能分流」）
//   2. 双击本程序（任意权限都可）
// 输出：国内段路由是否真的进了路由表、metric 是否低于隧道、隧道默认路由是否存在。
// ============================================================================

#include "platform/iplist.h"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
// netioapi.h 里 PMIB_IPFORWARD_TABLE2 / GetIpForwardTable2 在
// `#if (NTDDI_VERSION >= NTDDI_VISTA)` 内，不显式抬高版本就取不到声明
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#ifndef NTDDI_VERSION
#define NTDDI_VERSION 0x0A000000
#endif
#include <winsock2.h>
#include <ws2tcpip.h>   // SOCKADDR_INET 等类型是 MIB_IPFORWARD_ROW2 的前提
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>   // PMIB_IPFORWARD_TABLE2 / GetIpForwardTable2
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#endif

namespace {

std::string ip_str(uint32_t net_order)
{
    const uint32_t h = ::ntohl(net_order);
    char buf[32]{};
    std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u",
                  (h >> 24) & 0xFF, (h >> 16) & 0xFF, (h >> 8) & 0xFF, h & 0xFF);
    return buf;
}

} // namespace

int main()
{
#if defined(_WIN32)
    ::SetConsoleOutputCP(CP_UTF8);
#endif

    std::vector<cidr::Cidr> want;
    const std::string candidates[] = { "chnroute.txt", "..\\chnroute.txt",
                                       "x64\\Debug\\chnroute.txt", "x64\\Release\\chnroute.txt" };
    bool loaded = false;
    for (const auto& p : candidates)
    {
        iplist::Stats st;
        if (iplist::load_file(cfg_from_utf8(p), want, &st) && !want.empty())
        {
            std::printf("网段列表: %s（%zu 条）\n", p.c_str(), want.size());
            loaded = true;
            break;
        }
        want.clear();
    }
    if (!loaded)
    {
        std::printf("找不到 chnroute.txt。请把本程序放到 exe 同目录（x64\\Debug 或 Release）再运行。\n");
        return 2;
    }

    PMIB_IPFORWARD_TABLE2 table = nullptr;
    if (::GetIpForwardTable2(AF_INET, &table) != NO_ERROR || table == nullptr)
    {
        std::printf("读取路由表失败\n");
        return 3;
    }

    // 建立"国内段"索引：addr 主机序 + prefix
    int splitHits = 0;
    int tunnelDefault = 0;
    std::string tunnelDev;
    MIB_IPFORWARD_ROW2 sample{};
    cidr::Cidr sampleCidr{};
    bool hasSample = false;
    int sampleMetric = 0;
    uint32_t sampleNh = 0;

    for (ULONG i = 0; i < table->NumEntries; ++i)
    {
        const MIB_IPFORWARD_ROW2& r = table->Table[i];
        if (r.DestinationPrefix.Prefix.si_family != AF_INET)
        {
            continue;
        }
        const uint32_t net = ::ntohl(r.DestinationPrefix.Prefix.Ipv4.sin_addr.S_un.S_addr);
        const uint8_t p = static_cast<uint8_t>(r.DestinationPrefix.PrefixLength);

        // 隧道的两条半路由
        if ((net == 0u && p == 1) || (net == 0x80000000u && p == 1))
        {
            ++tunnelDefault;
            continue;
        }

        for (const auto& c : want)
        {
            if (c.prefix == p && c.addr == net)
            {
                ++splitHits;
                if (!hasSample)
                {
                    sample = r;
                    sampleCidr = c;
                    sampleMetric = static_cast<int>(r.Metric);
                    sampleNh = r.NextHop.Ipv4.sin_addr.S_un.S_addr;
                    hasSample = true;
                }
                break;
            }
        }
    }
    ::FreeMibTable(table);

    std::printf("\n=== 分流状态 ===\n");
    std::printf("国内段匹配数量 : %d / %zu\n", splitHits, want.size());
    std::printf("隧道默认路由   : %d 条（应为 2：0.0.0.0/1 与 128.0.0.0/1）\n",
                tunnelDefault);

    if (hasSample)
    {
        std::printf("抽查路由       : %s -> 下一跳 %s, Metric=%d\n",
                    cidr::to_string(sampleCidr).c_str(),
                    ip_str(sampleNh).c_str(), sampleMetric);
    }
    else
    {
        std::printf("抽查路由       : 无（国内段一条都不在路由表里）\n");
    }

    std::printf("\n=== 结论 ===\n");
    if (splitHits == 0)
    {
        std::printf("  [X] 分流未生效：国内段路由一条都没有\n");
        std::printf("      可能原因：未连接 / 选了『全局』模式 / 客户端不是管理员\n");
    }
    else if (splitHits < static_cast<int>(want.size()) / 2)
    {
        std::printf("  [!] 只注入了一部分（%d/%zu），可能中途失败\n", splitHits, want.size());
    }
    else if (sampleMetric > 5)
    {
        std::printf("  [!] 路由存在但 Metric=%d 偏高，可能被隧道路由抢走\n", sampleMetric);
    }
    else
    {
        std::printf("  [OK] 分流已生效：%d 条国内段指向物理出口，Metric=%d\n",
                    splitHits, sampleMetric);
    }
    if (tunnelDefault != 2)
    {
        std::printf("  [!] 隧道默认路由不是 2 条（实际 %d），当前可能未连接\n", tunnelDefault);
    }

    std::printf("\n按回车退出...\n");
    (void)std::getchar();
    return 0;
}
