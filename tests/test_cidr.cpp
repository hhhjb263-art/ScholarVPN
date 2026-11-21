#include "platform/cidr.h"

#include <cstdio>
#include <string>
#include <vector>

namespace {

int g_pass = 0;
int g_fail = 0;

void check(bool ok, const char* what, const std::string& detail = {})
{
    if (ok)
    {
        ++g_pass;
        return;
    }
    ++g_fail;
    std::printf("  FAIL  %s%s%s\n", what, detail.empty() ? "" : "  ->  ", detail.c_str());
}

void expect_ok(const std::string& input, const std::string& expect, bool normalize_first = false)
{
    cidr::Cidr c;
    if (!cidr::parse(input, c))
    {
        check(false, "应解析成功", input);
        return;
    }
    if (normalize_first)
    {
        cidr::normalize(c);
    }
    const std::string got = cidr::to_string(c);
    check(got == expect, "结果不符", input + "  got=" + got + " want=" + expect);
}

void expect_bad(const std::string& input)
{
    cidr::Cidr c;
    check(!cidr::parse(input, c), "应解析失败", input.empty() ? "<空串>" : input);
}

}

int main()
{
    std::printf("== cidr 解析 ==\n");

    expect_ok("1.2.3.4", "1.2.3.4/32");
    expect_ok("1.2.3.0/24", "1.2.3.0/24");
    expect_ok("0.0.0.0/0", "0.0.0.0/0");
    expect_ok("255.255.255.255/32", "255.255.255.255/32");
    expect_ok("223.5.5.0/24", "223.5.5.0/24");
    expect_ok("10.8.0.1/8", "10.8.0.1/8", false);

    expect_ok("  1.2.3.0/24  ", "1.2.3.0/24");
    expect_ok("\t114.114.114.114\r\n", "114.114.114.114/32");

    expect_ok("1.2.3.4/24", "1.2.3.0/24", true);
    expect_ok("192.168.255.255/16", "192.168.0.0/16", true);
    expect_ok("255.255.255.255/0", "0.0.0.0/0", true);

    std::printf("== cidr 拒绝非法输入 ==\n");
    expect_bad("");
    expect_bad("   ");
    expect_bad("1.2.3");
    expect_bad("1.2.3.4.5");
    expect_bad("1.2.3.256");
    expect_bad("1.2.3.4/33");
    expect_bad("1.2.3.4/");
    expect_bad("1.2.3.4/24x");
    expect_bad("abc");
    expect_bad("1..3.4");
    expect_bad("1.2.3.-1");
    expect_bad("1.2.3.4/-1");

    std::printf("== 地址数与包含判断 ==\n");
    {
        cidr::Cidr c{};
        cidr::parse("0.0.0.0/0", c);
        check(cidr::size(c) == 4294967296ull, "/0 应为 2^32");

        cidr::parse("192.168.1.0/24", c);
        check(cidr::size(c) == 256ull, "/24 应为 256");

        cidr::parse("1.2.3.4/32", c);
        check(cidr::size(c) == 1ull, "/32 应为 1");

        cidr::Cidr net{};
        cidr::parse("10.8.0.0/24", net);
        check(cidr::contains(net, 0x0A080001u), "10.8.0.1 应在 10.8.0.0/24 内");
        check(cidr::contains(net, 0x0A0800FFu), "10.8.0.255 应在内");
        check(!cidr::contains(net, 0x0A080100u), "10.8.1.0 不应在内");
    }

    std::printf("\n结果: %d 通过, %d 失败\n", g_pass, g_fail);
    if (g_fail != 0)
    {
        std::printf("有失败用例，返回 1\n");
        return 1;
    }
    std::printf("全部通过\n");
    return 0;
}
