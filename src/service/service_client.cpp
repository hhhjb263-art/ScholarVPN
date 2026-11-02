#include "service/service_client.h"

#include "update/update_fetcher.h"
#include "Crypt.h"

#include <cctype>
#include <cstdio>
#include <map>
#include <string>
#include <vector>

#include <openssl/evp.h>

namespace service {

namespace {

std::string trim(const std::string& s)
{
    const std::size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos)
    {
        return {};
    }
    const std::size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

// 服务公钥（SPKI DER 的 base64 单行）→ PEM（OpenSSL 只吃 PEM）
// 与 AppBridge::check_update 对 config.ini ServerPubKey 的处理同语义
std::string pubkey_b64_to_pem(const std::string& b64)
{
    if (b64.find("BEGIN") != std::string::npos)
    {
        return b64;   // 已是完整 PEM
    }
    // 重新按 64 列折行
    std::string compact;
    for (char c : b64)
    {
        if (c != '\n' && c != '\r' && c != ' ' && c != '\t')
        {
            compact.push_back(c);
        }
    }
    std::string pem = "-----BEGIN PUBLIC KEY-----\n";
    for (std::size_t i = 0; i < compact.size(); i += 64)
    {
        pem += compact.substr(i, 64);
        pem += '\n';
    }
    pem += "-----END PUBLIC KEY-----\n";
    return pem;
}

bool is_hex64(const std::string& s)
{
    if (s.size() != 64)
    {
        return false;
    }
    for (char c : s)
    {
        if (!std::isxdigit(static_cast<unsigned char>(c)))
        {
            return false;
        }
    }
    return true;
}

// 名字统一小写后取头
std::string header_get(const std::map<std::string, std::string>& headers,
                       const char* name)
{
    const auto it = headers.find(name);
    return (it == headers.end()) ? std::string() : it->second;
}

} // namespace

Credentials parse_credentials(const std::string& iniText)
{
    Credentials c;
    std::map<std::string, std::string> kv;
    std::size_t pos = 0;
    while (pos <= iniText.size())
    {
        std::size_t nl = iniText.find('\n', pos);
        if (nl == std::string::npos)
        {
            nl = iniText.size();
        }
        const std::string line = trim(iniText.substr(pos, nl - pos));
        pos = nl + 1;
        if (line.empty() || line[0] == '#' || line[0] == ';')
        {
            continue;
        }
        const std::size_t eq = line.find('=');
        if (eq == std::string::npos)
        {
            continue;
        }
        kv[trim(line.substr(0, eq))] = trim(line.substr(eq + 1));
    }

    auto get = [&kv](const char* k) -> std::string {
        const auto it = kv.find(k);
        return (it == kv.end()) ? std::string() : it->second;
    };
    auto get_u64 = [&get](const char* k) -> std::uint64_t {
        const std::string v = get(k);
        return v.empty() ? 0 : std::strtoull(v.c_str(), nullptr, 10);
    };

    c.fp = get("fp");
    c.client_id = get("client_id");
    c.token = get("token");
    c.status = get("status");
    c.expire_at = get_u64("expire_at");
    c.quota_bytes = get_u64("quota_bytes");
    c.limit_kind = get("limit_kind");
    c.remaining = get_u64("remaining");
    c.used_bytes = get_u64("used_bytes");
    // client_id 缺失 = broker 返回了不完整凭据，视为无效
    c.valid = !c.client_id.empty();
    if (!c.valid)
    {
        c.error = "凭据内容不完整（缺少 client_id）";
    }
    return c;
}

Verdict evaluate(const Credentials& c, std::uint64_t nowUnix)
{
    Verdict v;
    if (!c.valid)
    {
        // 拉不到/解析不了 ≠ 违规：放行（与更新系统"查不到→放行"同语义）
        v.blocked = false;
        v.reason = c.error.empty() ? "服务状态未知" : c.error;
        return v;
    }
    if (c.status == "rejected")
    {
        v.blocked = true;
        v.reason = "该设备的服务申请已被拒绝，请联系服务方";
        return v;
    }
    if (c.status == "revoked")
    {
        v.blocked = true;
        v.reason = "该设备的授权已被服务方取消，请联系服务方";
        return v;
    }
    // 服务器已选定限制维度并算好剩余量：remaining=0 即超限（统一文案）
    if (!c.limit_kind.empty() && c.limit_kind != "none")
    {
        if (c.remaining == 0)
        {
            v.blocked = true;
            v.reason = "已超出使用范围，请联系管理员";
        }
        return v;
    }
    // 旧 broker 兼容：无新字段时按原始字段判定（文案统一）
    if (c.expire_at != 0 && nowUnix >= c.expire_at)
    {
        v.blocked = true;
        v.reason = "已超出使用范围，请联系管理员";
        return v;
    }
    if (c.quota_bytes != 0 && c.used_bytes >= c.quota_bytes)
    {
        v.blocked = true;
        v.reason = "已超出使用范围，请联系管理员";
        return v;
    }
    v.blocked = false;
    return v;
}

bool verify_signature(const std::string& body, const std::string& sigBase64,
                      const std::string& pubKeyBase64)
{
    // base64 解码（签名是 64 字节 Ed25519；与 update_checker 同规则，容忍换行空白）
    std::vector<std::uint8_t> sig;
    {
        std::uint32_t buf = 0;
        int bits = 0;
        for (char ch : sigBase64)
        {
            int v = -1;
            if (ch >= 'A' && ch <= 'Z') v = ch - 'A';
            else if (ch >= 'a' && ch <= 'z') v = ch - 'a' + 26;
            else if (ch >= '0' && ch <= '9') v = ch - '0' + 52;
            else if (ch == '+') v = 62;
            else if (ch == '/') v = 63;
            else if (ch == '\r' || ch == '\n' || ch == ' ' || ch == '\t') continue;
            else if (ch == '=') break;
            else return false;
            buf = (buf << 6) | static_cast<std::uint32_t>(v);
            bits += 6;
            if (bits >= 8)
            {
                bits -= 8;
                sig.push_back(static_cast<std::uint8_t>((buf >> bits) & 0xFF));
            }
        }
    }
    if (sig.size() != 64)
    {
        return false;
    }

    EVP_PKEY* pub = nullptr;
    try
    {
        pub = load_ed25519_public_key_pem(pubkey_b64_to_pem(pubKeyBase64));
    }
    catch (...)
    {
        pub = nullptr;
    }
    if (pub == nullptr)
    {
        return false;
    }
    const bool ok = ed25519_verify(pub,
                                   reinterpret_cast<const std::uint8_t*>(body.data()),
                                   body.size(), sig.data(), sig.size());
    EVP_PKEY_free(pub);
    return ok;
}

namespace {

// 签名头缺失/验签失败统一报错文案：绝不使用未验签的内容
Credentials checked_credentials(const update::FetchResult& r,
                                const std::string& pubKeyBase64)
{
    Credentials c;
    if (!r.ok)
    {
        // broker 对未登记指纹返回 404 unknown fp——这不是故障，是「尚未申请试用」：
        // 机器码规则升级/新设备首次使用都会走到这里。识别为空状态（非错误），
        // UI 据此显示「尚未申请试用」并引导点「申请试用」，而不是吓人的网络失败。
        if (r.status == 404 && r.body.find("unknown fp") != std::string::npos)
        {
            c.error.clear();
            return c;
        }
        // 429 = 触发同 IP 防刷限频（24h 上限）：给可执行的人话提示
        if (r.status == 429)
        {
            c.error = "申请过于频繁：同一 IP 24 小时内限 3 次，"
                      "请稍后再试或联系服务方解除限频";
            return c;
        }
        c.error = "网络请求失败：" + r.error;
        return c;
    }
    const std::string sig = header_get(r.headers, "x-service-signature");
    if (sig.empty())
    {
        c.error = "响应缺少服务签名头";
        return c;
    }
    if (!verify_signature(r.body, sig, pubKeyBase64))
    {
        c.error = "服务凭据签名验证失败";
        return c;
    }
    c = parse_credentials(r.body);
    return c;
}

} // namespace

Credentials register_trial(const std::string& url, const std::string& pubKeyBase64,
                           const MachineInfo& info, int timeoutMs)
{
    std::string q = url;
    if (q.find('?') == std::string::npos)
    {
        q += '?';
    }
    else
    {
        q += '&';
    }
    // 查询参数只含非隐私硬件事实与哈希；percent 编码最简手写（空格/保留字）
    auto enc = [](const std::string& s) {
        std::string out;
        char b[4];
        for (unsigned char ch : s)
        {
            if (std::isalnum(ch) || ch == '-' || ch == '.' || ch == '_' || ch == '~')
            {
                out.push_back(static_cast<char>(ch));
            }
            else
            {
                std::snprintf(b, sizeof(b), "%%%02X", ch);
                out += b;
            }
        }
        return out;
    };
    q += "fp=" + enc(info.fp);
    q += "&os=" + enc(info.os);
    q += "&cpu=" + enc(info.cpu);
    q += "&ram=" + std::to_string(info.ram_mb);
    if (!info.mac_hash.empty())
    {
        q += "&mac=" + enc(info.mac_hash);   // 已是哈希，非明文 MAC
    }
    return checked_credentials(update::fetch_text(q, timeoutMs), pubKeyBase64);
}

Credentials fetch_status(const std::string& url, const std::string& pubKeyBase64,
                         int timeoutMs)
{
    return checked_credentials(update::fetch_text(url, timeoutMs), pubKeyBase64);
}

bool split_addr(const std::string& addr, std::string& ip, int& port)
{
    const std::size_t colon = addr.rfind(':');
    if (colon == std::string::npos || colon == 0 || colon + 1 >= addr.size())
    {
        return false;
    }
    ip = addr.substr(0, colon);
    port = std::atoi(addr.c_str() + colon + 1);
    if (port < 1 || port > 65535)
    {
        return false;
    }
    // 简单 IPv4/域名校验：非空且无空白
    if (ip.empty() || ip.find(' ') != std::string::npos)
    {
        return false;
    }
    return true;
}

std::vector<ManagedServer> fetch_server_list(const std::string& listUrl,
                                             const std::string& sigUrl,
                                             const std::string& pubKeyBase64,
                                             std::string& error,
                                             int timeoutMs)
{
    error.clear();
    const update::FetchResult ini = update::fetch_text(listUrl, timeoutMs);
    if (!ini.ok)
    {
        if (ini.status == 403)
            error = "设备未登记：请先在「申请试用」中完成申请，再获取服务器列表";
        else
            error = "拉取服务器列表失败：" + ini.error;
        return {};
    }
    const update::FetchResult sig = update::fetch_text(sigUrl, timeoutMs);
    if (!sig.ok)
    {
        error = "拉取列表签名失败：" + sig.error;
        return {};
    }
    if (!verify_signature(ini.body, sig.body, pubKeyBase64))
    {
        error = "服务器列表签名验证失败";
        return {};
    }

    // 解析：serverN / pubkeyN / remarkN
    std::map<int, ManagedServer> byIdx;
    std::size_t pos = 0;
    while (pos <= ini.body.size())
    {
        std::size_t nl = ini.body.find('\n', pos);
        if (nl == std::string::npos)
        {
            nl = ini.body.size();
        }
        const std::string line = trim(ini.body.substr(pos, nl - pos));
        pos = nl + 1;
        if (line.empty() || line[0] == '#' || line[0] == ';')
        {
            continue;
        }
        const std::size_t eq = line.find('=');
        if (eq == std::string::npos)
        {
            continue;
        }
        const std::string key = trim(line.substr(0, eq));
        const std::string val = trim(line.substr(eq + 1));
        // key 形如 server1 / pubkey2 / remark3
        std::size_t i = 0;
        while (i < key.size() && !std::isdigit(static_cast<unsigned char>(key[i])))
        {
            ++i;
        }
        if (i == 0 || i >= key.size())
        {
            continue;
        }
        const std::string name = key.substr(0, i);
        const int idx = std::atoi(key.c_str() + i);
        if (idx <= 0)
        {
            continue;
        }
        if (name == "server")
        {
            byIdx[idx].addr = val;
        }
        else if (name == "pubkey")
        {
            byIdx[idx].pubkey_b64 = val;
        }
        else if (name == "remark")
        {
            byIdx[idx].remark = val;
        }
    }

    std::vector<ManagedServer> out;
    for (auto& [idx, srv] : byIdx)
    {
        (void)idx;
        std::string ip;
        int port = 0;
        if (srv.addr.empty() || !split_addr(srv.addr, ip, port))
        {
            continue;   // 坏行跳过，不让一条脏数据废掉整份列表
        }
        out.push_back(srv);
    }
    if (out.empty())
    {
        error = "服务器列表为空或格式非法";
    }
    return out;
}

} // namespace service
