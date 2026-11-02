// ============================================================================
// tests/test_service_client.cpp —— 受管服务客户端纯逻辑的离线测试（不联网）
//
// 覆盖：凭据 INI 解析 / 闸门判定（到期/超量/拒绝/放行）/ 响应签名验签
// （现场生成 Ed25519 密钥对签名，篡改与换钥必须被拒——与 test_checker 同思路）。
//
// 编译运行（MSVC，需 OpenSSL）：
//   cl /nologo /MD /DNDEBUG /std:c++20 /EHsc /utf-8 /Zc:__cplusplus /I. /Isrc ^
//      /Ithird_party\openssl\include ^
//      tests\test_service_client.cpp src\service\service_client.cpp ^
//      src\service\machine_id.cpp src\update\update_fetcher.cpp Crypt.cpp ^
//      /link /LIBPATH:third_party\openssl\lib libcrypto.lib ws2_32.lib
//      iphlpapi.lib advapi32.lib winhttp.lib
// ============================================================================

#include "service/service_client.h"
#include "Crypt.h"

#include <cstdio>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>   // PEM_read_bio_PrivateKey

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdio>
#endif

namespace {

int g_pass = 0;
int g_fail = 0;

void check(bool ok, const char* what)
{
    if (ok)
    {
        ++g_pass;
        return;
    }
    ++g_fail;
    std::printf("  FAIL  %s\n", what);
}

// 服务公钥 PEM → SPKI DER base64 单行（verify_signature 的输入格式）
std::string pem_to_der_b64(const std::string& pem)
{
    std::string b64body;
    std::size_t pos = 0;
    while (pos < pem.size())
    {
        std::size_t nl = pem.find('\n', pos);
        if (nl == std::string::npos)
        {
            nl = pem.size();
        }
        std::string line = pem.substr(pos, nl - pos);
        pos = nl + 1;
        if (!line.empty() && line.back() == '\r')
        {
            line.pop_back();
        }
        if (line.find("-----") != std::string::npos || line.empty())
        {
            continue;
        }
        b64body += line;
    }
    // base64 → DER → base64（重编码，顺便验证剥头尾的正确性）
    std::vector<std::uint8_t> der;
    std::uint32_t buf = 0;
    int bits = 0;
    for (char c : b64body)
    {
        int v = -1;
        if (c >= 'A' && c <= 'Z') v = c - 'A';
        else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
        else if (c >= '0' && c <= '9') v = c - '0' + 52;
        else if (c == '+') v = 62;
        else if (c == '/') v = 63;
        else continue;
        buf = (buf << 6) | static_cast<std::uint32_t>(v);
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            der.push_back(static_cast<std::uint8_t>((buf >> bits) & 0xFF));
        }
    }
    static const char* T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    std::size_t i = 0;
    while (i + 2 < der.size())
    {
        const std::uint32_t n = (der[i] << 16) | (der[i + 1] << 8) | der[i + 2];
        out += T[(n >> 18) & 63];
        out += T[(n >> 12) & 63];
        out += T[(n >> 6) & 63];
        out += T[n & 63];
        i += 3;
    }
    if (i + 1 == der.size())
    {
        const std::uint32_t n = der[i] << 16;
        out += T[(n >> 18) & 63];
        out += T[(n >> 12) & 63];
        out += "==";
    }
    else if (i + 2 == der.size())
    {
        const std::uint32_t n = (der[i] << 16) | (der[i + 1] << 8);
        out += T[(n >> 18) & 63];
        out += T[(n >> 12) & 63];
        out += T[(n >> 6) & 63];
        out += "=";
    }
    return out;
}

// 私钥 PEM → EVP_PKEY（签测试响应用）
EVP_PKEY* load_priv(const std::string& pem)
{
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    EVP_PKEY* k = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    return k;
}

std::string sign_b64(EVP_PKEY* priv, const std::string& data)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    std::vector<std::uint8_t> sig(64);
    std::size_t sigLen = sig.size();   // 入参必须=缓冲区长度（Ed25519 恒 64）
    const int ok = EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, priv) == 1
                   && EVP_DigestSign(ctx, sig.data(), &sigLen,
                                     reinterpret_cast<const std::uint8_t*>(data.data()),
                                     data.size()) == 1;
    EVP_MD_CTX_free(ctx);
    if (!ok || sigLen != 64)
    {
        return {};   // 签名失败：返回空串让下游按"空签名"失败
    }
    static const char* T = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    std::size_t i = 0;
    while (i + 2 < sigLen)
    {
        const std::uint32_t n = (sig[i] << 16) | (sig[i + 1] << 8) | sig[i + 2];
        out += T[(n >> 18) & 63];
        out += T[(n >> 12) & 63];
        out += T[(n >> 6) & 63];
        out += T[n & 63];
        i += 3;
    }
    if (i + 1 == sigLen)
    {
        // 尾部剩 1 字节：2 个字符 + "=="（64 字节签名 = 21 组 + 1 字节余数）
        const std::uint32_t n = static_cast<std::uint32_t>(sig[i]) << 16;
        out += T[(n >> 18) & 63];
        out += T[(n >> 12) & 63];
        out += "==";
    }
    return out;
}

} // namespace

int main()
{
    std::printf("== 凭据解析 ==\n");

    const std::string ini1 =
        "# ScholarVPN service credentials\n"
        "fp          = aabb\n"
        "client_id   = trial-ab12cd34\n"
        "token       = 1122334455667788\n"
        "status      = trial\n"
        "expire_at   = 1790000000\n"
        "quota_bytes = 2147483648\n"
        "used_bytes  = 1024\n"
        "issued      = 1789000000\n";
    const service::Credentials c1 = service::parse_credentials(ini1);
    check(c1.valid, "完整凭据解析 valid");
    check(c1.client_id == "trial-ab12cd34", "client_id 正确");
    check(c1.token == "1122334455667788", "token 正确");
    check(c1.quota_bytes == 2147483648ull, "quota 2GB 无 int32 截断");
    check(c1.used_bytes == 1024, "used 正确");

    check(service::parse_credentials("status = trial\n").valid == false,
          "缺 client_id = 无效凭据");

    std::printf("== 闸门判定 ==\n");

    const std::uint64_t NOW = 1789000100;   // 早于 c1.expire_at（试用中）
    // 试用中、未超量 → 放行
    check(service::evaluate(c1, NOW).blocked == false, "试用中放行");
    // 到期 → 阻断
    service::Credentials c2 = c1;
    c2.expire_at = 1789000000;   // < NOW
    check(service::evaluate(c2, NOW).blocked == true, "试用到期阻断");
    // 超量 → 阻断
    service::Credentials c3 = c1;
    c3.used_bytes = c3.quota_bytes;
    check(service::evaluate(c3, NOW).blocked == true, "配额耗尽阻断");
    // rejected → 阻断
    service::Credentials c4 = c1;
    c4.status = "rejected";
    check(service::evaluate(c4, NOW).blocked == true, "rejected 阻断");
    // 正式（expire=quota=0）→ 放行
    service::Credentials c5 = c1;
    c5.status = "approved";
    c5.expire_at = 0;
    c5.quota_bytes = 0;
    check(service::evaluate(c5, NOW).blocked == false, "approved 放行");
    // 同步失败（invalid）→ 不阻断（查不到→放行）
    service::Credentials c6;
    c6.error = "网络失败";
    check(service::evaluate(c6, NOW).blocked == false, "同步失败放行");

    std::printf("== 响应签名验签 ==\n");

    // 现场生成 service 密钥对（与 broker README 同流程）
    const std::string dir = ".";
    const std::string privPath = "test_service_priv.tmp";
    const std::string pubPath = "test_service_pub.tmp";
    std::string pubPem;
    check(generate_ed25519_keypair(privPath, pubPath, pubPem),
          "现场生成 Ed25519 密钥对");
    std::string privPem;
    {
        FILE* f = std::fopen(privPath.c_str(), "rb");
        char buf[4096];
        std::size_t n = 0;
        while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0)
        {
            privPem.append(buf, n);
        }
        std::fclose(f);
        std::remove(privPath.c_str());
        std::remove(pubPath.c_str());
    }
    EVP_PKEY* priv = load_priv(privPem);
    check(priv != nullptr, "私钥加载");

    const std::string pubB64 = pem_to_der_b64(pubPem);
    check(pubB64.size() == 60, "SPKI DER base64 单行（60 字符 Ed25519）");

    const std::string body1 =
        "# ScholarVPN service credentials\nfp = aabb\nclient_id = trial-ab12cd34\n"
        "status = trial\nexpire_at = 1790000000\nquota_bytes = 2147483648\n"
        "used_bytes = 0\nissued = 1789000000\n";
    const std::string sig = sign_b64(priv, body1);

    // 对照组：PEM 直连链路（排除 pem_to_der_b64/pubkey 包装的问题）
    {
        EVP_PKEY* pubDirect = load_ed25519_public_key_pem(pubPem);
        std::vector<std::uint8_t> sigRaw;
        {
            std::uint32_t buf = 0; int bits = 0;
            for (char ch : sig) {
                int v = -1;
                if (ch >= 'A' && ch <= 'Z') v = ch - 'A';
                else if (ch >= 'a' && ch <= 'z') v = ch - 'a' + 26;
                else if (ch >= '0' && ch <= '9') v = ch - '0' + 52;
                else if (ch == '+') v = 62;
                else if (ch == '/') v = 63;
                else continue;
                buf = (buf << 6) | (std::uint32_t)v; bits += 6;
                if (bits >= 8) { bits -= 8; sigRaw.push_back((std::uint8_t)((buf >> bits) & 0xFF)); }
            }
        }
        const bool direct = pubDirect != nullptr && ed25519_verify(
            pubDirect, reinterpret_cast<const std::uint8_t*>(body1.data()),
            body1.size(), sigRaw.data(), sigRaw.size());
        if (pubDirect) EVP_PKEY_free(pubDirect);
        check(direct, "对照：PEM 直连验签通过（签名完整）");
    }

    check(service::verify_signature(body1, sig, pubB64), "正确签名通过");
    check(service::verify_signature(body1 + "x", sig, pubB64) == false,
          "篡改一个字节必须被拒");
    check(service::verify_signature(body1, sig, pubB64.substr(0, 40)) == false,
          "换一把公钥必须被拒");
    check(service::verify_signature(body1, "", pubB64) == false, "空签名被拒");
    EVP_PKEY_free(priv);

    std::printf("== 地址解析 ==\n");

    std::string ip;
    int port = 0;
    check(service::split_addr("203.0.113.7:51820", ip, port) && ip == "203.0.113.7"
              && port == 51820, "ip:port 解析");
    check(service::split_addr("203.0.113.7", ip, port) == false, "无端口被拒");
    check(service::split_addr("bad:0", ip, port) == false, "非法端口被拒");

    std::printf("\n结果: %d 通过, %d 失败\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
