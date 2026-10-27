// ============================================================================
// tests/test_resolve_host.cpp —— 域名校验与解析的单元测试（不需要管理员）
//
// 编译运行（MinGW）：
//   g++ -std=c++17 -Isrc tests/test_resolve_host.cpp -o test_resolve.exe -lws2_32
// ============================================================================

#include "util/utf.h"

#include <cstdio>
#include <string>

namespace {

int g_pass = 0;
int g_fail = 0;

void check(bool ok, const std::string& what)
{
    if (ok)
    {
        ++g_pass;
        return;
    }
    ++g_fail;
    std::printf("  FAIL  %s\n", what.c_str());
}

} // namespace

int main()
{
#if defined(_WIN32)
    ::SetConsoleOutputCP(CP_UTF8);
    // Windows 上 getaddrinfo 依赖 Winsock 已初始化（否则返回 WSANOTINITIALISED）
    WSADATA wsa{};
    ::WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    std::printf("== 地址合法性（IPv4 或域名）==\n");
    check(is_valid_host("8.8.8.8"), "8.8.8.8 应合法");
    check(is_valid_host("192.168.1.1"), "192.168.1.1 应合法");
    check(is_valid_host("vpn.example.com"), "普通域名应合法");
    check(is_valid_host("a-b.c-d.org"), "带连字符的域名应合法");
    check(is_valid_host("localhost"), "localhost 应合法");
    check(!is_valid_host(""), "空串应非法");
    check(!is_valid_host("my_vpn.example.com"), "下划线应非法");
    check(!is_valid_host("a..b"), "连续点应非法");
    check(!is_valid_host(".example.com"), "以点开头应非法");
    check(!is_valid_host("example.com."), "以点结尾应非法");
    check(!is_valid_host("-bad.com"), "以连字符开头应非法");
    check(!is_valid_host("has space.com"), "含空格应非法");
    check(!is_valid_host(std::string(300, 'a')), "超长应非法");

    std::printf("== 字面量 IP：原样返回，不查 DNS ==\n");
    {
        std::string out;
        check(resolve_host("1.2.3.4", out), "1.2.3.4 应解析成功");
        check(out == "1.2.3.4", "应原样返回，实际=" + out);
    }

    std::printf("== 本地域名解析（不依赖外网）==\n");
    {
        std::string out;
        const bool ok = resolve_host("localhost", out);
        check(ok, "localhost 应解析成功");
        if (ok)
        {
            std::printf("  localhost -> %s\n", out.c_str());
            check(out == "127.0.0.1", "localhost 应解析到 127.0.0.1，实际=" + out);
        }
    }

    std::printf("== 不存在的域名应失败 ==\n");
    {
        std::string out;
        check(!resolve_host("no-such-host.invalid", out), "保留域名 .invalid 应解析失败");
    }

    std::printf("\n结果: %d 通过, %d 失败\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
