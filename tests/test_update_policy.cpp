// ============================================================================
// tests/test_update_policy.cpp —— 版本比较与更新决策的单元测试（纯逻辑）
//
// 编译运行：
//   g++ -std=c++17 -Isrc tests/test_update_policy.cpp src/update/update_policy.cpp -o t.exe
// ============================================================================

#include "update/update_policy.h"

#include <cstdio>
#include <string>

using namespace update;

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
    std::printf("== 版本比较（按数值，不按字符串）==\n");
    check(compare_version("1.6.0", "1.7.0") == -1, "1.6.0 < 1.7.0");
    check(compare_version("1.7.0", "1.6.0") == 1, "1.7.0 > 1.6.0");
    check(compare_version("1.6.0", "1.6.0") == 0, "相等");
    check(compare_version("1.10.0", "1.9.0") == 1, "1.10.0 > 1.9.0（字符串比较会判反）");
    check(compare_version("1.10.0", "1.10.0") == 0, "1.10.0 == 1.10.0");
    check(compare_version("1.6", "1.6.0") == 0, "缺段按 0 处理");
    check(compare_version("2", "1.99.99") == 1, "大版本优先");
    check(compare_version("", "1.0") == -2, "空串解析失败");
    check(compare_version("1.x", "1.0") == -2, "非数字解析失败");
    check(compare_version("1..2", "1.0") == -2, "空段解析失败");

    std::printf("== 策略解析 ==\n");
    const std::string text =
        "# 客户端更新策略\n"
        "latest = 1.7.0\n"
        "minimum = 1.6.0\n"
        "notes = 修复认证边界问题\n"
        "win-x64_url = https://dl.example.com/x.exe\n"
        "win-x64_sha256 = abc123\n"
        "win-x64_size = 48213000\n"
        "linux-x64_url = https://dl.example.com/x.tar.gz\n"
        "linux-x64_sha256 = def456\n"
        "linux-x64_size = 6124000\n"
        "generated = 1792540800\n"
        "这行没有等号，应被跳过\n";
    {
        Policy p;
        check(parse_policy(text, "win-x64", p), "window 策略应解析成功");
        check(p.latest == "1.7.0", "latest");
        check(p.minimum == "1.6.0", "minimum");
        check(p.url == "https://dl.example.com/x.exe", "按平台选 url");
        check(p.size == 48213000ull, "按平台选 size");
        check(p.generated == 1792540800ull, "generated");
        check(p.valid, "有 url + sha256 才算有效");
    }
    {
        Policy p;
        check(parse_policy(text, "linux-x64", p), "linux 策略应解析成功");
        check(p.url == "https://dl.example.com/x.tar.gz", "linux url");
        check(p.size == 6124000ull, "linux size");
    }
    {
        Policy p;
        check(!parse_policy("notes = 没有 latest\n", "win-x64", p), "缺 latest 应视为无效");
    }
    {
        Policy p;
        check(parse_policy("latest=1.9.0\nurl=u\nsha256=s\n", "win-x64", p), "紧凑写法也应解析");
        check(p.url == "u", "紧凑写法 url");
    }

    std::printf("== 决策 ==\n");
    {
        Policy p;
        p.latest = "1.7.0";
        p.minimum = "1.6.0";
        p.url = "u";
        p.sha256 = "s";
        p.valid = true;

        check(decide(p, "1.5.9").action == Action::Forced, "低于 minimum → 强制");
        check(decide(p, "1.6.0").action == Action::Optional, "等于 minimum → 可选");
        check(decide(p, "1.6.9").action == Action::Optional, "介于两者之间 → 可选");
        check(decide(p, "1.7.0").action == Action::None, "等于 latest → 无需更新");
        check(decide(p, "1.8.0").action == Action::None, "高于 latest → 无需更新");
        check(decide(p, "1.10.0").action == Action::None, "1.10.0 比 1.7.0 新");
    }
    {
        Policy p;
        p.latest = "1.7.0";
        p.minimum = "";           // 没配最低版本
        p.url = "u";
        p.sha256 = "s";
        p.valid = true;
        check(decide(p, "1.0.0").action == Action::Optional, "无 minimum 时不该强制");
    }
    {
        Policy p;   // 默认无效
        check(decide(p, "1.0.0").action == Action::None, "策略未配置 → 不更新");
    }
    {
        Policy p;
        p.latest = "1.7.0";
        p.minimum = "abc";        // 服务端笔误
        p.url = "u";
        p.sha256 = "s";
        p.valid = true;
        const Decision d = decide(p, "1.0.0");
        check(d.action != Action::Forced, "minimum 解析失败不能把用户锁死");
        check(d.action == Action::Optional, "降级为可选");
    }

    std::printf("\n结果: %d 通过, %d 失败\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
