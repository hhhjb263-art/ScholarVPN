// ============================================================================
// tests/verify_policy_file.exe —— 发布自检工具：验证策略文件与签名的匹配
//
// 用法：
//   verify_policy_file.exe <policy.ini> <policy.ini.sig> <release_pub.pem> [os] [current]
//
// 发布流程中把它跑在"上传之前"：签名与文件哪怕差一个字节，这里都过不去。
// 与 Python 侧 scripts/sign-update-policy.py 的 verify 是双向校验：
//   Python 签 → C++ 验（本工具）——证明两端对格式约定的理解一致。
// ============================================================================

#include "update/update_checker.h"

#include <cstdio>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace {

std::string read_file(const char* path)
{
    // 签名对象是文件原始字节，必须按二进制读（不能做任何行尾转换）
    FILE* f = std::fopen(path, "rb");
    if (f == nullptr)
    {
        return std::string();
    }
    std::string out;
    char buf[4096];
    std::size_t n = 0;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0)
    {
        out.append(buf, n);
    }
    std::fclose(f);
    return out;
}

} // namespace

int main(int argc, char** argv)
{
#if defined(_WIN32)
    ::SetConsoleOutputCP(CP_UTF8);
#endif
    if (argc < 4)
    {
        std::printf("用法: %s <policy.ini> <policy.ini.sig> <release_pub.pem> [os] [current]\n",
                    argv[0]);
        return 2;
    }

    const std::string policy = read_file(argv[1]);
    const std::string sig = read_file(argv[2]);
    const std::string pub = read_file(argv[3]);
    const std::string os = (argc > 4) ? argv[4] : "win-x64";
    const std::string current = (argc > 5) ? argv[5] : "0.0.0";

    if (policy.empty() || sig.empty() || pub.empty())
    {
        std::printf("读文件失败（路径错误？）\n");
        return 2;
    }

    const auto r = update::check_text(policy, sig, pub, os, current);

    if (r.status == update::CheckStatus::Ok)
    {
        std::printf("PASS  签名有效\n");
        std::printf("  action   = %s\n", update::action_name(r.decision.action));
        std::printf("  latest   = %s\n", r.decision.policy.latest.c_str());
        std::printf("  minimum  = %s\n", r.decision.policy.minimum.c_str());
        std::printf("  url      = %s\n", r.decision.policy.url.c_str());
        std::printf("  generated= %llu\n",
                    static_cast<unsigned long long>(r.generated));
        return 0;
    }
    std::printf("FAIL  %s: %s\n", update::status_name(r.status), r.error.c_str());
    return 1;
}
