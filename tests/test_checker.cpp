// ============================================================================
// tests/test_checker.cpp —— 策略验签与决策的离线测试（不联网）
//
// 用项目自己的 Ed25519 实现现场生成密钥、签名，再喂给 check_text，
// 重点验证「篡改必须被拒」——这是"验签失败即拒绝使用"的地基。
//
// 编译（MSVC，需要 OpenSSL）：
//   cl /std:c++20 /EHsc /utf-8 /I. /Isrc /Ithird_party\openssl\include ^
//      tests\test_checker.cpp src\update\update_checker.cpp src\update\update_policy.cpp ^
//      src\update\update_fetcher.cpp Crypt.cpp ^
//      /link /LIBPATH:third_party\openssl\lib libcrypto.lib ws2_32.lib
// ============================================================================

#include "update/update_checker.h"
#include "Crypt.h"

#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

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

std::string b64encode(const std::vector<std::uint8_t>& in)
{
    static const char* T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    std::size_t i = 0;
    while (i + 2 < in.size())
    {
        const std::uint32_t n = (in[i] << 16) | (in[i + 1] << 8) | in[i + 2];
        out += T[(n >> 18) & 63];
        out += T[(n >> 12) & 63];
        out += T[(n >> 6) & 63];
        out += T[n & 63];
        i += 3;
    }
    if (i + 1 == in.size())
    {
        const std::uint32_t n = static_cast<std::uint32_t>(in[i]) << 16;
        out += T[(n >> 18) & 63];
        out += T[(n >> 12) & 63];
        out += "==";
    }
    else if (i + 2 == in.size())
    {
        const std::uint32_t n = (static_cast<std::uint32_t>(in[i]) << 16) |
                                (static_cast<std::uint32_t>(in[i + 1]) << 8);
        out += T[(n >> 18) & 63];
        out += T[(n >> 12) & 63];
        out += T[(n >> 6) & 63];
        out += '=';
    }
    return out;
}

std::string sign_to_b64(EVP_PKEY* priv, const std::string& body)
{
    const auto sig = ed25519_sign(priv,
                                  reinterpret_cast<const std::uint8_t*>(body.data()),
                                  body.size());
    return b64encode(sig);
}

const char* kPolicy =
    "latest = 1.7.0\n"
    "minimum = 1.6.0\n"
    "notes = fix auth edge cases\n"
    "url = https://dl.example.com/x.exe\n"
    "sha256 = abc123\n"
    "size = 48213000\n"
    "generated = 1792540800\n";

} // namespace

int main()
{
#if defined(_WIN32)
    ::SetConsoleOutputCP(CP_UTF8);
#endif

    const std::string privPath = "test_chk_priv.pem";
    const std::string pubPath = "test_chk_pub.pem";
    std::string pubPem;
    if (!generate_ed25519_keypair(privPath, pubPath, pubPem))
    {
        std::printf("生成测试密钥失败\n");
        return 2;
    }
    EVP_PKEY* priv = load_ed25519_private_key(privPath);
    if (priv == nullptr)
    {
        std::printf("加载测试私钥失败\n");
        return 2;
    }

    std::printf("== 正常签名应通过 ==\n");
    {
        const std::string sig = sign_to_b64(priv, kPolicy);
        const auto r = update::check_text(kPolicy, sig, pubPem, "win-x64", "1.6.0");
        check(r.status == update::CheckStatus::Ok, "签名有效应 Ok");
        check(r.decision.action == update::Action::Optional, "1.6.0 应为可选更新");
        check(r.generated == 1792540800ull, "generated 应解析出来");
    }

    std::printf("== 篡改策略正文必须被拒 ==\n");
    {
        const std::string sig = sign_to_b64(priv, kPolicy);
        std::string tampered = kPolicy;
        const std::size_t pos = tampered.find("minimum = 1.6.0");
        tampered.replace(pos, 15, "minimum = 0.0.1");   // 把门槛改低，企图绕过强制
        const auto r = update::check_text(tampered, sig, pubPem, "win-x64", "1.6.0");
        check(r.status == update::CheckStatus::SignatureInvalid, "改正文应验签失败");
    }

    std::printf("== 篡改签名必须被拒 ==\n");
    {
        std::string sig = sign_to_b64(priv, kPolicy);
        sig[10] = (sig[10] == 'A') ? 'B' : 'A';
        const auto r = update::check_text(kPolicy, sig, pubPem, "win-x64", "1.6.0");
        check(r.status == update::CheckStatus::SignatureInvalid, "改签名应失败");
    }

    std::printf("== 换一把公钥必须被拒 ==\n");
    {
        const std::string sig = sign_to_b64(priv, kPolicy);
        std::string otherPub;
        const std::string p2 = "test_chk_priv2.pem";
        const std::string q2 = "test_chk_pub2.pem";
        generate_ed25519_keypair(p2, q2, otherPub);
        const auto r = update::check_text(kPolicy, sig, otherPub, "win-x64", "1.6.0");
        check(r.status == update::CheckStatus::SignatureInvalid, "公钥不匹配应失败");
        std::remove(p2.c_str());
        std::remove(q2.c_str());
    }

    std::printf("== 签名格式非法 ==\n");
    {
        const auto r1 = update::check_text(kPolicy, "", pubPem, "win-x64", "1.6.0");
        check(r1.status == update::CheckStatus::SignatureInvalid, "空签名应失败");
        const auto r2 = update::check_text(kPolicy, "not-base64!!!", pubPem, "win-x64", "1.6.0");
        check(r2.status == update::CheckStatus::SignatureInvalid, "非 base64 应失败");
    }

    std::printf("== 签名有效但内容残缺 ==\n");
    {
        const std::string partial = "minimum = 1.6.0\nurl = u\nsha256 = s\n";   // 没有 latest
        const std::string sig = sign_to_b64(priv, partial);
        const auto r = update::check_text(partial, sig, pubPem, "win-x64", "1.6.0");
        check(r.status == update::CheckStatus::PolicyInvalid, "缺 latest 应判内容无效");
    }

    std::printf("== 强制门槛 ==\n");
    {
        const std::string sig = sign_to_b64(priv, kPolicy);
        const auto r = update::check_text(kPolicy, sig, pubPem, "win-x64", "1.5.9");
        check(r.decision.action == update::Action::Forced, "1.5.9 低于 minimum 应强制");
    }

    EVP_PKEY_free(priv);
    std::remove(privPath.c_str());
    std::remove(pubPath.c_str());

    std::printf("\n结果: %d 通过, %d 失败\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
