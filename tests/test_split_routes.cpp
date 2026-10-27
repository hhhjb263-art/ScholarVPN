// ============================================================================
// tests/test_split_routes.cpp —— 分流路由注入的实机测试【需要管理员权限】
//
// 会真的往系统路由表写入 3 条 /24（指向当前物理网关，等价于"把它们指回原路"，
// 不会影响正常上网），测完立即撤销。
//
// 编译（MinGW）：
//   g++ -std=c++17 -Isrc tests/test_split_routes.cpp src/route_manager.cpp \
//       src/platform/cfgstr.cpp src/logger.cpp -o test_split.exe -liphlpapi -lws2_32
//
// 运行：右键"以管理员身份运行" test_split.exe
// 非管理员会返回 0 条成功，并提示原因。
// ============================================================================

#include "route_manager.h"

#include <cstdio>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

int main()
{
#if defined(_WIN32)
    ::SetConsoleOutputCP(CP_UTF8);   // 否则中文在 GBK 控制台是乱码
#endif
    RouteManager rm(tun_id_t{});   // 分流注入不使用 m_tunnelId

    std::vector<cidr::Cidr> list;
    for (const char* s : { "1.0.1.0/24", "1.0.2.0/23", "223.5.5.0/24" })
    {
        cidr::Cidr c{};
        if (!cidr::parse(s, c))
        {
            std::printf("解析失败: %s\n", s);
            return 2;
        }
        list.push_back(c);
    }

    std::printf("== 首次注入 %zu 条 ==\n", list.size());
    const int n1 = rm.add_bypass_routes(list, CS("8.8.8.8"));
    std::printf("  成功 %d 条，记录 %zu 条\n", n1, rm.split_route_count());

    if (n1 == 0)
    {
        std::printf("\n  注入全部失败：最常见原因是当前不是管理员。\n"
                    "  请右键 test_split.exe →「以管理员身份运行」后重试。\n");
        return 1;
    }

    std::printf("== 重复注入（应被去重，不新增记录）==\n");
    const int n2 = rm.add_bypass_routes(list, CS("8.8.8.8"));
    std::printf("  成功 %d 条，记录 %zu 条\n", n2, rm.split_route_count());

    std::printf("== 撤销 ==\n");
    rm.remove_split_routes();
    std::printf("  撤销后记录 %zu 条\n", rm.split_route_count());

    const bool ok = (n1 == static_cast<int>(list.size())) && (n2 == 0) &&
                    (rm.split_route_count() == 0);
    std::printf("\n%s\n", ok ? "PASS" : "FAIL");
    return ok ? 0 : 1;
}
