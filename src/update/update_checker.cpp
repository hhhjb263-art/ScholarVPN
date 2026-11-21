#include "update/update_checker.h"
#include "update/update_fetcher.h"
#include "Crypt.h"

#include <openssl/evp.h>

#include <vector>

namespace update {

namespace {

bool base64_decode(const std::string& in, std::vector<std::uint8_t>& out)
{
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };

    out.clear();
    std::uint32_t buf = 0;
    int bits = 0;
    int pad = 0;
    for (char c : in)
    {
        if (c == '\r' || c == '\n' || c == ' ' || c == '\t')
        {
            continue;
        }
        if (c == '=')
        {
            ++pad;
            continue;
        }
        const int v = val(c);
        if (v < 0)
        {
            return false;
        }
        buf = (buf << 6) | static_cast<std::uint32_t>(v);
        bits += 6;
        if (bits >= 8)
        {
            bits -= 8;
            out.push_back(static_cast<std::uint8_t>((buf >> bits) & 0xFF));
        }
    }
    if (pad > 2)
    {
        return false;
    }
    return !out.empty();
}

}

CheckResult check_text(const std::string& policyBody,
                       const std::string& signatureBase64,
                       const std::string& releasePublicKeyPem,
                       const std::string& os,
                       const std::string& currentVersion)
{
    CheckResult r;

    std::vector<std::uint8_t> sig;
    if (!base64_decode(signatureBase64, sig) || sig.size() != 64)
    {
        r.status = CheckStatus::SignatureInvalid;
        r.error = "签名格式非法（应为 64 字节 Ed25519 签名的 base64）";
        return r;
    }

    EVP_PKEY* pub = nullptr;
    try
    {
        pub = load_ed25519_public_key_pem(releasePublicKeyPem);
    }
    catch (...)
    {
        pub = nullptr;
    }
    if (pub == nullptr)
    {
        r.status = CheckStatus::SignatureInvalid;
        r.error = "发布公钥无法加载（格式错误或损坏）";
        return r;
    }

    bool ok = false;
    try
    {
        ok = ed25519_verify(pub,
                            reinterpret_cast<const std::uint8_t*>(policyBody.data()),
                            policyBody.size(),
                            sig.data(), sig.size());
    }
    catch (...)
    {
        ok = false;
    }
    EVP_PKEY_free(pub);

    if (!ok)
    {
        r.status = CheckStatus::SignatureInvalid;
        r.error = "策略签名验证失败";
        return r;
    }

    Policy p;
    if (!parse_policy(policyBody, os, p))
    {
        r.status = CheckStatus::PolicyInvalid;
        r.error = "策略内容不完整（缺少 latest）";
        return r;
    }

    r.status = CheckStatus::Ok;
    r.decision = decide(p, currentVersion);
    r.generated = p.generated;
    return r;
}

// 拉取策略并验签：签名不通过一律视为检查失败，不采信内容
CheckResult check(const std::string& policyUrl,
                  const std::string& signatureUrl,
                  const std::string& releasePublicKeyPem,
                  const std::string& os,
                  const std::string& currentVersion,
                  int timeoutMs)
{
    CheckResult r;

    auto dbg = [&policyUrl](const std::string& m) {
        FILE* f = std::fopen("/tmp/scholarvpn-check-debug.log", "a");
        if (f != nullptr)
        {
            std::fprintf(f, "[%s] %s\n", policyUrl.c_str(), m.c_str());
            std::fclose(f);
        }
    };
    dbg("start");

    const FetchResult pf = fetch_text(policyUrl, timeoutMs);
    dbg("policy fetched ok=" + std::to_string(pf.ok ? 1 : 0) +
        " status=" + std::to_string(pf.status) + " err=" + pf.error);
    if (!pf.ok)
    {
        r.status = CheckStatus::NetworkFailed;
        r.error = "拉取策略失败：" + pf.error;
        return r;
    }

    dbg("fetching signature");
    const FetchResult sf = fetch_text(signatureUrl, timeoutMs);
    dbg("signature fetched ok=" + std::to_string(sf.ok ? 1 : 0) + " err=" + sf.error);
    if (!sf.ok)
    {
        r.status = CheckStatus::NetworkFailed;
        r.error = "拉取签名失败：" + sf.error;
        return r;
    }

    dbg("verifying");
    const CheckResult cr = check_text(pf.body, sf.body, releasePublicKeyPem, os, currentVersion);
    dbg("verified status=" + std::string(status_name(cr.status)));
    return cr;
}

const char* status_name(CheckStatus s)
{
    switch (s)
    {
    case CheckStatus::Ok:               return "ok";
    case CheckStatus::SignatureInvalid: return "signature-invalid";
    case CheckStatus::NetworkFailed:    return "network-failed";
    case CheckStatus::PolicyInvalid:    return "policy-invalid";
    }
    return "unknown";
}

}
