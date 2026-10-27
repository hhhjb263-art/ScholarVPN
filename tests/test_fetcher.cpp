// ============================================================================
// tests/test_fetcher.cpp —— HTTP 拉取的基本验证（需要外网）
//
// 编译（MSVC）：
//   cl /std:c++20 /utf-8 /I. /Isrc tests\test_fetcher.cpp src\update\update_fetcher.cpp
// ============================================================================

#include "update/update_fetcher.h"

#include <cstdio>

#if defined(_WIN32)
#include <windows.h>
#endif

int main()
{
#if defined(_WIN32)
    ::SetConsoleOutputCP(CP_UTF8);
#endif

    std::printf("== 正常 HTTPS 请求 ==\n");
    {
        const auto r = update::fetch_text("https://www.baidu.com", 6000);
        std::printf("  ok=%d status=%d size=%zu error=%s\n",
                    r.ok ? 1 : 0, r.status, r.body.size(), r.error.c_str());
    }

    std::printf("== 404 应判定失败 ==\n");
    {
        const auto r = update::fetch_text("https://www.baidu.com/__nope__", 6000);
        std::printf("  ok=%d status=%d error=%s\n",
                    r.ok ? 1 : 0, r.status, r.error.c_str());
    }

    std::printf("== 非法 URL ==\n");
    {
        const auto r = update::fetch_text("ftp://example.com/x", 2000);
        std::printf("  ok=%d error=%s\n", r.ok ? 1 : 0, r.error.c_str());
    }

    std::printf("== 不存在的主机（应超时或失败，不应崩）==\n");
    {
        const auto r = update::fetch_text("https://no-such-host.invalid/x", 3000);
        std::printf("  ok=%d error=%s\n", r.ok ? 1 : 0, r.error.c_str());
    }

    std::printf("\n完成（本测试只验证不崩、不挂起，具体成败取决于网络）\n");
    return 0;
}
