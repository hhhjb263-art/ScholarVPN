// ============================================================================
// tests/test_probe_route.cpp —— 验证"查到物理出口"这半段（只读，不需要管理员）
//
// 路由注入本身要用 CreateIpForwardEntry2（需要管理员），这里只验证：
//   - probe IP 能否解析为 SOCKADDR_INET
//   - GetBestRoute2 能否返回物理网卡 LUID 与下一跳
// 这两步错了，后面的注入一定是错的，而且现象很隐蔽（路由加到了 TUN 上）。
//
// 编译运行（MinGW）：
//   g++ -std=c++17 tests/test_probe_route.cpp -o test_probe.exe -liphlpapi -lws2_32
// ============================================================================

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include <cstdio>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

namespace {

bool probe_best_route(const char* ip, MIB_IPFORWARD_ROW2& best)
{
    SOCKADDR_INET dest{};
    dest.Ipv4.sin_family = AF_INET;
    if (::InetPtonA(AF_INET, ip, &dest.Ipv4.sin_addr) != 1)
    {
        std::printf("  InetPtonA 失败: %s\n", ip);
        return false;
    }

    SOCKADDR_INET src{};
    const NETIO_STATUS st = ::GetBestRoute2(nullptr, 0, nullptr, &dest, 0, &best, &src);
    if (st != NO_ERROR)
    {
        std::printf("  GetBestRoute2 失败: %s err=%lu\n", ip, static_cast<unsigned long>(st));
        return false;
    }
    return true;
}

} // namespace

int main()
{
    WSADATA wsa{};
    if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        std::printf("WSAStartup 失败\n");
        return 1;
    }

    int fail = 0;
    const char* probes[] = { "8.8.8.8", "223.5.5.5" };

    for (const char* ip : probes)
    {
        std::printf("探测 %s:\n", ip);
        MIB_IPFORWARD_ROW2 best{};
        if (!probe_best_route(ip, best))
        {
            ++fail;
            continue;
        }

        const ULONG nh = best.NextHop.Ipv4.sin_addr.S_un.S_addr;
        std::printf("  出口 LUID = %llu\n", static_cast<unsigned long long>(best.InterfaceLuid.Value));
        std::printf("  下一跳    = %lu.%lu.%lu.%lu\n",
                    static_cast<unsigned long>(nh & 0xFF),
                    static_cast<unsigned long>((nh >> 8) & 0xFF),
                    static_cast<unsigned long>((nh >> 16) & 0xFF),
                    static_cast<unsigned long>((nh >> 24) & 0xFF));
        std::printf("  前缀长度  = %u, metric = %lu\n",
                    static_cast<unsigned>(best.DestinationPrefix.PrefixLength),
                    static_cast<unsigned long>(best.Metric));

        if (best.InterfaceLuid.Value == 0)
        {
            std::printf("  FAIL: 出口 LUID 为 0，注入会把路由加到错误网卡\n");
            ++fail;
        }
    }

    ::WSACleanup();
    std::printf("\n%s\n", fail == 0 ? "探测正常" : "存在失败项");
    return fail == 0 ? 0 : 1;
}
