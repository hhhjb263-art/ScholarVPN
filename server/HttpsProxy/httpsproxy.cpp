#include "httpsproxy.h"

#include "../Proxy/proxy_common.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <string>
#include <system_error>
#include <vector>

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

namespace {

using proxy_common::constant_time_eq;
using proxy_common::sanitize_for_log;
using proxy_common::set_io_timeout;
using proxy_common::Stream;
using proxy_common::stream_read_headers;
using proxy_common::stream_write;

constexpr int kHandshakeTimeoutMs = 15'000;   // TLS 握手 / 读请求头单步超时
constexpr int kIdleTimeoutMs = 300'000;       // 中继空闲上限（5 分钟）
constexpr int kIoTimeoutSec = 30;             // 阻塞读写上限
constexpr size_t kMaxHeaderBytes = 8 * 1024;  // 请求头上限（防大头攻击）
constexpr uint16_t kDefaultHttpPort = 80;

std::string base64_encode(const std::string& in)
{
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve((in.size() + 2) / 3 * 4);
    size_t i = 0;
    while (i + 2 < in.size()) {
        const uint32_t v = (static_cast<uint8_t>(in[i]) << 16) |
                           (static_cast<uint8_t>(in[i + 1]) << 8) |
                           static_cast<uint8_t>(in[i + 2]);
        out.push_back(tbl[(v >> 18) & 63]);
        out.push_back(tbl[(v >> 12) & 63]);
        out.push_back(tbl[(v >> 6) & 63]);
        out.push_back(tbl[v & 63]);
        i += 3;
    }
    const size_t rem = in.size() - i;
    if (rem == 1) {
        const uint32_t v = static_cast<uint8_t>(in[i]) << 16;
        out.push_back(tbl[(v >> 18) & 63]);
        out.push_back(tbl[(v >> 12) & 63]);
        out.push_back('=');
        out.push_back('=');
    } else if (rem == 2) {
        const uint32_t v = (static_cast<uint8_t>(in[i]) << 16) |
                           (static_cast<uint8_t>(in[i + 1]) << 8);
        out.push_back(tbl[(v >> 18) & 63]);
        out.push_back(tbl[(v >> 12) & 63]);
        out.push_back(tbl[(v >> 6) & 63]);
        out.push_back('=');
    }
    return out;
}

// 打印 OpenSSL 错误队列（TLS 握手失败必须能看到具体原因，否则排障只能猜）
void log_ssl_errors(const char* prefix)
{
    unsigned long e = 0;
    bool any = false;
    while ((e = ERR_get_error()) != 0) {
        char buf[256] = {0};
        ERR_error_string_n(e, buf, sizeof(buf));
        fprintf(stderr, "%s%s\n", prefix, buf);
        any = true;
    }
    if (!any)
        fprintf(stderr, "%s(无 OpenSSL 错误详情)\n", prefix);
}

std::string to_lower(std::string s){
    for (char& c : s)
        c = static_cast<char>(tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string trim(const std::string& s)
{
    const size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos)
        return "";
    const size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

struct HttpRequest
{
    std::string method;
    std::string target;              // CONNECT 的 authority，或绝对形式 URI
    std::string version;             // "HTTP/1.1" 等
    std::vector<std::string> header_lines;   // 原样保留（转发时按需过滤）
    bool has_proxy_authorization = false;
    std::string proxy_authorization;
};

// 解析头块（首行 + 头部行）。返回 false = 格式不合法
bool parse_request(const std::string& raw, HttpRequest& out)
{
    const size_t line_end = raw.find("\r\n");
    const size_t line_end2 = raw.find('\n');
    const size_t e1 = (line_end == std::string::npos) ? raw.size() : line_end;
    const size_t e2 = (line_end2 == std::string::npos) ? raw.size() : line_end2;
    const size_t first_end = (e1 < e2) ? e1 : e2;   // 不用 std::min：MSVC 的 min 宏会干扰
    if (first_end == raw.size())
        return false;
    const std::string first = trim(raw.substr(0, first_end));
    const size_t sp1 = first.find(' ');
    const size_t sp2 = (sp1 == std::string::npos) ? std::string::npos : first.find(' ', sp1 + 1);
    if (sp1 == std::string::npos || sp2 == std::string::npos)
        return false;
    out.method = first.substr(0, sp1);
    out.target = first.substr(sp1 + 1, sp2 - sp1 - 1);
    out.version = first.substr(sp2 + 1);
    if (out.method.empty() || out.target.empty())
        return false;

    // 跳过首行行尾（\r\n 或 \n）后再逐行读头部
    size_t pos = first_end;
    if (pos < raw.size() && raw[pos] == '\r')
        ++pos;
    if (pos < raw.size() && raw[pos] == '\n')
        ++pos;
    while (pos < raw.size()) {
        size_t e = raw.find('\n', pos);
        if (e == std::string::npos)
            e = raw.size();
        const std::string line = trim(raw.substr(pos, e - pos));
        pos = e + 1;
        if (line.empty())
            break;
        out.header_lines.push_back(line);
        const size_t colon = line.find(':');
        if (colon == std::string::npos)
            continue;
        if (to_lower(trim(line.substr(0, colon))) == "proxy-authorization") {
            out.has_proxy_authorization = true;
            out.proxy_authorization = trim(line.substr(colon + 1));
        }
    }
    return true;   // 允许无自定义头（CONNECT 可能有也可以没有额外头）
}

bool header_filtered_out(const std::string& line)
{
    const size_t colon = line.find(':');
    if (colon == std::string::npos)
        return true;                  // 异常行不转发
    // 含控制字符（除制表符）的头部一律不转发：防请求走私/畸形转发
    for (unsigned char c : line) {
        if ((c < 0x20 && c != '\t') || c == 0x7F)
            return true;
    }
    const std::string name = to_lower(trim(line.substr(0, colon)));
    // 代理专属头不转发给目标服务器
    return name == "proxy-authorization" || name == "proxy-connection";
}

// 取 URL 的 host/port（绝对形式 http://host[:port]/path）
bool parse_absolute_uri(const std::string& uri, std::string& host, uint16_t& port,
                        std::string& origin_form)
{
    const std::string lower = to_lower(uri);
    if (lower.compare(0, 7, "http://") != 0)
        return false;                 // 仅支持明文 HTTP 绝对形式
    const size_t host_begin = 7;
    const size_t slash = uri.find('/', host_begin);
    const std::string authority =
        uri.substr(host_begin, (slash == std::string::npos) ? std::string::npos
                                                           : slash - host_begin);
    origin_form = (slash == std::string::npos) ? "/" : uri.substr(slash);
    if (authority.empty())
        return false;
    if (authority[0] == '[') {        // IPv6 字面量 [::1]:8080
        const size_t close = authority.find(']');
        if (close == std::string::npos)
            return false;
        host = authority.substr(1, close - 1);
        if (close + 1 < authority.size() && authority[close + 1] == ':') {
            const long p = std::strtol(authority.c_str() + close + 2, nullptr, 10);
            if (p <= 0 || p > 65535)
                return false;
            port = static_cast<uint16_t>(p);
        } else {
            port = kDefaultHttpPort;
        }
        return true;
    }
    const size_t colon = authority.rfind(':');
    if (colon != std::string::npos) {
        const long p = std::strtol(authority.c_str() + colon + 1, nullptr, 10);
        if (p <= 0 || p > 65535)
            return false;
        port = static_cast<uint16_t>(p);
        host = authority.substr(0, colon);
    } else {
        host = authority;
        port = kDefaultHttpPort;
    }
    return !host.empty();
}

// CONNECT 目标 authority → host/port（支持 [v6]:port）
bool parse_authority(const std::string& authority, std::string& host, uint16_t& port)
{
    if (authority.empty())
        return false;
    if (authority[0] == '[') {
        const size_t close = authority.find(']');
        if (close == std::string::npos)
            return false;
        host = authority.substr(1, close - 1);
        if (close + 1 >= authority.size() || authority[close + 1] != ':')
            return false;
        const long p = std::strtol(authority.c_str() + close + 2, nullptr, 10);
        if (p <= 0 || p > 65535)
            return false;
        port = static_cast<uint16_t>(p);
        return !host.empty();
    }
    const size_t colon = authority.rfind(':');
    if (colon == std::string::npos)
        return false;
    const long p = std::strtol(authority.c_str() + colon + 1, nullptr, 10);
    if (p <= 0 || p > 65535)
        return false;
    host = authority.substr(0, colon);
    port = static_cast<uint16_t>(p);
    return !host.empty();
}

// 目标主机名合法性：长度上限（DNS 253）且不含控制字符/空白
// （主机名来自对端请求，直接用于 getaddrinfo 与日志都必须先校验）
bool host_is_valid(const std::string& h)
{
    if (h.empty() || h.size() > 253)
        return false;
    for (unsigned char c : h) {
        if (c <= 0x20 || c == 0x7F)
            return false;
    }
    return true;
}

void send_error(Stream& s, const char* status, const char* extra_header = nullptr)
{
    std::string resp = std::string("HTTP/1.1 ") + status + "\r\n";
    if (extra_header != nullptr)
        resp += std::string(extra_header) + "\r\n";
    resp += "Content-Length: 0\r\nConnection: close\r\n\r\n";
    stream_write(s, reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
}

} // namespace

HttpConnectProxy::HttpConnectProxy()
    : m_auth_throttle(new proxy_common::AuthThrottle()),
      m_log_limiter(new proxy_common::LogLimiter())
{
}

HttpConnectProxy::~HttpConnectProxy()
{
    stop();
}

bool HttpConnectProxy::start(const Config& cfg)
{
    if (m_running.load())
        return false;
    m_cfg = cfg;
    if (m_cfg.port == 0) {
        fprintf(stderr, "[HTTPS] 未启用（端口 0）\n");
        return true;                  // 未启用视为成功
    }
    if (m_cfg.bind_ip.empty())
        m_cfg.bind_ip = "0.0.0.0";
    m_cfg.max_conns = (m_cfg.max_conns > 0) ? m_cfg.max_conns : 256;

    // ---- TLS 上下文（use_tls 时必建，证书缺失/加载失败直接失败）----
    if (m_cfg.use_tls) {
        if (m_cfg.cert_path.empty() || m_cfg.key_path.empty()) {
            fprintf(stderr, "[HTTPS] 启用 TLS 必须提供 --https-proxy-cert / --https-proxy-key\n");
            return false;
        }
        SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
        if (ctx == nullptr) {
            fprintf(stderr, "[HTTPS] SSL_CTX_new failed\n");
            return false;
        }
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        // TLS 加固：
        //   - 禁压缩（CRIME）、禁重协商（防 DoS/降级类攻击）、禁重协商会话恢复
        //   - 安全级别 2（≥112-bit，排除 1024-bit RSA/弱曲线等）
        //   - 显式限定 AEAD 套件（TLS1.3 用 set_ciphersuites，TLS1.2 用 set_cipher_list）
        SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION |
                                     SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);
        SSL_CTX_set_security_level(ctx, 2);
        SSL_CTX_set_cipher_list(ctx,
            "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:"
            "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:"
            "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256");
        SSL_CTX_set_ciphersuites(ctx,
            "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256");
        if (SSL_CTX_use_certificate_chain_file(ctx, m_cfg.cert_path.c_str()) != 1) {
            fprintf(stderr, "[HTTPS] 加载证书失败 %s: ", m_cfg.cert_path.c_str());
            log_ssl_errors("");
            SSL_CTX_free(ctx);
            return false;
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, m_cfg.key_path.c_str(), SSL_FILETYPE_PEM) != 1) {
            fprintf(stderr, "[HTTPS] 加载私钥失败 %s: ", m_cfg.key_path.c_str());
            log_ssl_errors("");
            fprintf(stderr, "[HTTPS] 提示：私钥若带口令保护，请先解密："
                            "openssl pkey -in key.pem -out key.plain.pem（然后 chmod 600）\n");
            SSL_CTX_free(ctx);
            return false;
        }
        if (SSL_CTX_check_private_key(ctx) != 1) {
            fprintf(stderr, "[HTTPS] 证书与私钥不匹配: ");
            log_ssl_errors("");
            SSL_CTX_free(ctx);
            return false;
        }
        // 证书有效期检查：已过期直接拒绝启动；剩余 <30 天给出续期告警
        // （自签证书到期会让所有客户端握手失败，必须提前发现）
        if (X509* cert = SSL_CTX_get0_certificate(ctx)) {
            const ASN1_TIME* not_before = X509_get0_notBefore(cert);
            const ASN1_TIME* not_after = X509_get0_notAfter(cert);
            if (not_after != nullptr && X509_cmp_current_time(not_after) < 0) {
                fprintf(stderr, "[HTTPS] 证书已过期（%s），拒绝启动。请重新签发并分发新证书\n",
                        m_cfg.cert_path.c_str());
                SSL_CTX_free(ctx);
                return false;
            }
            if (not_before != nullptr && X509_cmp_current_time(not_before) > 0) {
                fprintf(stderr, "[HTTPS] 警告：证书尚未生效（NotBefore 在未来），客户端会握手失败\n");
            }
            int days = 0;
            int secs = 0;
            if (not_after != nullptr && ASN1_TIME_diff(&days, &secs, nullptr, not_after) == 1 &&
                days < 30) {
                fprintf(stderr, "[HTTPS] 警告：证书将在 %d 天后过期，请尽快续期并重新分发\n", days);
            }
        }
        m_ssl_ctx = ctx;
    }
    if (!m_cfg.user.empty()) {
        m_expected_auth = "Basic " + base64_encode(m_cfg.user + ":" + m_cfg.pass);
    }

    // ---- 认证安全校验（防开放代理）----
    if (!m_cfg.user.empty() && m_cfg.pass.empty()) {
        fprintf(stderr, "[HTTPS] 拒绝启动：设置了 --proxy-user 但密码为空"
                        "（空密码等于无认证，请设置 --proxy-pass 或用 --proxy-pass-file）\n");
        if (m_ssl_ctx != nullptr) {
            SSL_CTX_free(static_cast<SSL_CTX*>(m_ssl_ctx));
            m_ssl_ctx = nullptr;
        }
        return false;
    }
    const bool loopback = (m_cfg.bind_ip == "127.0.0.1" || m_cfg.bind_ip == "::1" ||
                           m_cfg.bind_ip == "localhost");
    if (m_cfg.user.empty() && !loopback && !m_cfg.allow_noauth) {
        fprintf(stderr, "[HTTPS] 拒绝启动：监听 %s 但未配置认证。\n"
                        "        请加 --proxy-user/--proxy-pass；确需无认证（仅内网/前置 TLS）"
                        "再加 --proxy-allow-noauth\n", m_cfg.bind_ip.c_str());
        if (m_ssl_ctx != nullptr) {
            SSL_CTX_free(static_cast<SSL_CTX*>(m_ssl_ctx));
            m_ssl_ctx = nullptr;
        }
        return false;
    }
    if (m_cfg.user.empty() && !loopback) {
        fprintf(stderr, "[HTTPS] 警告：无认证代理监听 %s（已由 --proxy-allow-noauth 显式放行）\n",
                m_cfg.bind_ip.c_str());
    }
    if (!m_cfg.user.empty() && m_cfg.pass.size() < 8) {
        fprintf(stderr, "[HTTPS] 警告：代理密码长度仅 %zu，公网暴露建议 ≥8 位随机密码\n",
                m_cfg.pass.size());
    }

    m_listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (m_listen_fd < 0) {
        fprintf(stderr, "[HTTPS] socket() failed: %s\n", strerror(errno));
        return false;
    }
    int reuse = 1;
    setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    // 本监听面是 AF_INET：把 "localhost" / "::1" 归一化成 127.0.0.1。
    // 否则上面的回环判定（loopback）认了这两个写法，这里 inet_pton(AF_INET,...)
    // 却必然失败 → 代理入口直接起不来（表现为"配了 localhost 就没监听"）。
    std::string bind_ip4 = m_cfg.bind_ip;
    if (bind_ip4.empty() || bind_ip4 == "0.0.0.0") {
        bind_ip4 = "0.0.0.0";
    } else if (bind_ip4 == "localhost" || bind_ip4 == "::1") {
        bind_ip4 = "127.0.0.1";
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(m_cfg.port);
    if (bind_ip4 == "0.0.0.0") {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (inet_pton(AF_INET, bind_ip4.c_str(), &addr.sin_addr) != 1) {
        fprintf(stderr, "[HTTPS] 非法绑定地址 %s\n", m_cfg.bind_ip.c_str());
        ::close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }
    if (bind(m_listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        fprintf(stderr, "[HTTPS] bind(%s:%u) failed: %s\n", m_cfg.bind_ip.c_str(),
                static_cast<unsigned>(m_cfg.port), strerror(errno));
        ::close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }
    if (listen(m_listen_fd, 64) < 0) {
        fprintf(stderr, "[HTTPS] listen() failed: %s\n", strerror(errno));
        ::close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }

    // 目标 ACL：内网/回环 + 本机接口地址（防经公网 IP 回连本机服务）
    m_acl.reset(new proxy_common::TargetAcl());
    m_acl->allow_internal = m_cfg.allow_private;
    proxy_common::collect_local_addresses(*m_acl);
    // 每来源连接限制
    {
        proxy_common::ConnLimits lim;
        lim.max_concurrent = m_cfg.max_per_source;
        lim.rate_per_sec = m_cfg.conn_rate_per_sec;
        lim.rate_burst = m_cfg.conn_rate_per_sec * 30;
        m_conn_limiter.reset(new proxy_common::ConnLimiter(lim));
    }

    m_running.store(true);
    try {
        m_accept_thread = std::thread(&HttpConnectProxy::accept_work, this);
    } catch (const std::system_error& e) {
        fprintf(stderr, "[HTTPS] 启动 accept 线程失败: %s\n", e.what());
        m_running.store(false);
        ::close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }
    fprintf(stderr, "[HTTPS] %s代理监听 %s:%u（%s，上限 %zu 连接）\n",
            m_cfg.use_tls ? "HTTPS(TLS) " : "HTTP(明文) ",
            m_cfg.bind_ip.c_str(), static_cast<unsigned>(m_cfg.port),
            m_cfg.user.empty() ? "无认证——公网部署请加 --proxy-user/--proxy-pass"
                               : "Basic 认证",
            m_cfg.max_conns);
    return true;
}

void HttpConnectProxy::stop()
{
    if (!m_running.exchange(false)) {
        std::lock_guard<std::mutex> lock(m_workers_mutex);
        for (auto& w : m_workers) {
            if (w.thread.joinable())
                w.thread.join();
        }
        m_workers.clear();
        if (m_ssl_ctx != nullptr) {
            SSL_CTX_free(static_cast<SSL_CTX*>(m_ssl_ctx));
            m_ssl_ctx = nullptr;
        }
        return;
    }
    if (m_listen_fd >= 0) {
        ::shutdown(m_listen_fd, SHUT_RDWR);
        ::close(m_listen_fd);
        m_listen_fd = -1;
    }
    if (m_accept_thread.joinable())
        m_accept_thread.join();
    {
        std::lock_guard<std::mutex> lock(m_workers_mutex);
        for (auto& w : m_workers) {
            if (w.thread.joinable())
                w.thread.join();
        }
        m_workers.clear();
    }
    if (m_ssl_ctx != nullptr) {
        SSL_CTX_free(static_cast<SSL_CTX*>(m_ssl_ctx));
        m_ssl_ctx = nullptr;
    }
    fprintf(stderr, "[HTTPS] 代理已停止\n");
}

void HttpConnectProxy::join_finished()
{
    std::lock_guard<std::mutex> lock(m_workers_mutex);
    for (auto it = m_workers.begin(); it != m_workers.end(); ) {
        if (it->done && it->done->load()) {
            if (it->thread.joinable())
                it->thread.join();
            it = m_workers.erase(it);
        } else {
            ++it;
        }
    }
}

void HttpConnectProxy::accept_work()
{
    while (m_running.load()) {
        struct pollfd pfd{};
        pfd.fd = m_listen_fd;
        pfd.events = POLLIN;
        int pr;
        do {
            pr = poll(&pfd, 1, 500);
        } while (pr < 0 && errno == EINTR);
        if (!m_running.load())
            break;
        if (pr <= 0)
            continue;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
            continue;

        join_finished();

        sockaddr_in peer{};
        socklen_t plen = sizeof(peer);
        const int fd = accept4(m_listen_fd, reinterpret_cast<sockaddr*>(&peer), &plen,
                               SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                continue;
            if (errno == EMFILE || errno == ENFILE) {
                fprintf(stderr, "[HTTPS] fd 耗尽，暂停接收新连接\n");
                continue;
            }
            fprintf(stderr, "[HTTPS] accept() failed: %s\n", strerror(errno));
            continue;
        }
        if (m_conns.load() >= m_cfg.max_conns) {
            fprintf(stderr, "[HTTPS] 连接数达上限 %zu，拒绝新连接\n", m_cfg.max_conns);
            ::close(fd);
            continue;
        }
        set_io_timeout(fd, kIoTimeoutSec);

        char ipbuf[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &peer.sin_addr, ipbuf, sizeof(ipbuf));
        const std::string peer_ip = ipbuf;
        const std::string peer_str =
            peer_ip + ":" + std::to_string(ntohs(peer.sin_port));

        // 每来源连接限制：并发超限或新建过快直接拒绝
        if (!m_conn_limiter->try_acquire(peer_ip, proxy_common::now_ms())) {
            size_t suppressed = 0;
            if (m_log_limiter->allow(proxy_common::now_ms(), &suppressed)) {
                fprintf(stderr, "[HTTPS] %s 连接数/速率超限，拒绝（已抑制 %zu 条同类日志）\n",
                        sanitize_for_log(peer_ip).c_str(), suppressed);
            }
            ::close(fd);
            continue;
        }

        m_conns.fetch_add(1);
        auto done = std::make_shared<std::atomic<bool>>(false);
        try {
            std::lock_guard<std::mutex> lock(m_workers_mutex);
            m_workers.push_back(Worker{ std::thread([this, fd, peer_ip, peer_str, done] {
                handle_conn(fd, peer_ip, peer_str);
                m_conn_limiter->release(peer_ip);
                done->store(true);
            }), done });
        } catch (const std::system_error& e) {
            fprintf(stderr, "[HTTPS] 创建处理线程失败: %s\n", e.what());
            ::close(fd);
            m_conns.fetch_sub(1);
        }
    }
    join_finished();
}

void HttpConnectProxy::handle_conn(int fd, const std::string& peer_ip, const std::string& peer)
{
    SSL* ssl = nullptr;
    if (m_ssl_ctx != nullptr) {
        ssl = SSL_new(static_cast<SSL_CTX*>(m_ssl_ctx));
        if (ssl == nullptr) {
            fprintf(stderr, "[HTTPS] %s SSL_new 失败\n", sanitize_for_log(peer).c_str());
            ::close(fd);
            m_conns.fetch_sub(1);
            return;
        }
        SSL_set_accept_state(ssl);   // 明确服务端角色（避免"connection type not set"）
        if (SSL_set_fd(ssl, fd) != 1) {
            fprintf(stderr, "[HTTPS] %s SSL_set_fd 失败\n", sanitize_for_log(peer).c_str());
            log_ssl_errors("");
            SSL_free(ssl);
            ::close(fd);
            m_conns.fetch_sub(1);
            return;
        }
        if (!proxy_common::ssl_handshake_timed(ssl, fd, kHandshakeTimeoutMs)) {
            fprintf(stderr, "[HTTPS] %s TLS 握手失败: ", sanitize_for_log(peer).c_str());
            log_ssl_errors("");
            fflush(stderr);
            SSL_free(ssl);
            ::close(fd);
            m_conns.fetch_sub(1);
            return;
        }
    }
    Stream browser{ fd, ssl };

    // ---- 读请求头 ----
    std::string raw;
    if (!stream_read_headers(browser, raw, kMaxHeaderBytes, kHandshakeTimeoutMs)) {
        fprintf(stderr, "[HTTPS] %s 读取请求头失败\n", sanitize_for_log(peer).c_str());
        if (ssl != nullptr) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        ::close(fd);
        m_conns.fetch_sub(1);
        return;
    }
    HttpRequest req;
    if (!parse_request(raw, req)) {
        send_error(browser, "400 Bad Request");
        // 非 HTTP 数据：多半是"把 VPN 客户端/其它协议接到了代理端口"
        size_t suppressed = 0;
        if (m_log_limiter->allow(proxy_common::now_ms(), &suppressed)) {
            fprintf(stderr, "[HTTPS] %s 收到非 HTTP 数据（首行不是请求行）。"
                            "若这是 VPN 客户端，请把它的端口改回隧道端口（默认 51820）"
                            "（已抑制 %zu 条同类日志）\n",
                    sanitize_for_log(peer).c_str(), suppressed);
        }
        if (ssl != nullptr) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        ::close(fd);
        m_conns.fetch_sub(1);
        return;
    }

    // ---- 认证（可选 Basic）----
    if (!m_expected_auth.empty()) {
        // 防暴力破解：失败过多的来源在锁定期内直接回 407（与密码错误表现一致）
        if (!m_auth_throttle->allow(peer_ip, proxy_common::now_ms())) {
            send_error(browser, "407 Proxy Authentication Required",
                       "Proxy-Authenticate: Basic realm=\"ScholarVPN\"");
            fprintf(stderr, "[HTTPS] %s 认证失败次数过多，暂时拒绝\n",
                    sanitize_for_log(peer_ip).c_str());
            if (ssl != nullptr) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
            }
            ::close(fd);
            m_conns.fetch_sub(1);
            return;
        }
        const bool ok = req.has_proxy_authorization &&
                        constant_time_eq(req.proxy_authorization, m_expected_auth);
        if (!ok) {
            send_error(browser, "407 Proxy Authentication Required",
                       "Proxy-Authenticate: Basic realm=\"ScholarVPN\"");
            const uint64_t lock_ms = m_auth_throttle->on_failure(peer_ip, proxy_common::now_ms());
            if (lock_ms > 0) {
                fprintf(stderr, "[HTTPS] %s 认证失败，已锁定 %llu 秒（防暴力破解）\n",
                        sanitize_for_log(peer_ip).c_str(),
                        static_cast<unsigned long long>(lock_ms / 1000));
            } else {
                fprintf(stderr, "[HTTPS] %s 认证失败\n", sanitize_for_log(peer).c_str());
            }
            if (ssl != nullptr) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
            }
            ::close(fd);
            m_conns.fetch_sub(1);
            return;
        }
        m_auth_throttle->on_success(peer_ip);
    }

    // ---- 连接目标 ----
    std::string host;
    uint16_t port = 0;
    const bool is_connect = (req.method == "CONNECT");
    std::string forward_head;         // 非 CONNECT：改写为 origin-form 的请求头
    if (is_connect) {
        if (!parse_authority(req.target, host, port) || !host_is_valid(host)) {
            send_error(browser, "400 Bad Request");
            if (ssl != nullptr) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
            }
            ::close(fd);
            m_conns.fetch_sub(1);
            return;
        }
    } else {
        std::string origin_form;
        if (!parse_absolute_uri(req.target, host, port, origin_form) ||
            !host_is_valid(host)) {
            send_error(browser, "501 Not Implemented");   // 仅支持 http:// 绝对形式
            if (ssl != nullptr) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
            }
            ::close(fd);
            m_conns.fetch_sub(1);
            return;
        }
        // 请求走私加固（RFC 7230 §3.3.3）：Transfer-Encoding 与 Content-Length
        // 共存、或 TE 非 chunked 一律拒绝——转发这类歧义请求会把走私风险带给目标站点
        bool has_te = false;
        bool has_cl = false;
        bool te_bad = false;
        for (const auto& line : req.header_lines) {
            const size_t colon = line.find(':');
            if (colon == std::string::npos)
                continue;
            const std::string name = to_lower(trim(line.substr(0, colon)));
            if (name == "transfer-encoding") {
                has_te = true;
                if (to_lower(trim(line.substr(colon + 1))).find("chunked") == std::string::npos)
                    te_bad = true;
            } else if (name == "content-length") {
                has_cl = true;
            }
        }
        if (te_bad || (has_te && has_cl)) {
            send_error(browser, "400 Bad Request");
            if (ssl != nullptr) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
            }
            ::close(fd);
            m_conns.fetch_sub(1);
            return;
        }
        forward_head = req.method + " " + origin_form + " " + req.version + "\r\n";
        for (const auto& line : req.header_lines) {
            if (!header_filtered_out(line))
                forward_head += line + "\r\n";
        }
        forward_head += "\r\n";
    }

    // ACL：默认拒绝服务端内网/回环目标（防浏览器侧借代理访问服务端与其他
    // 客户端内网/TUN 网段）；--proxy-allow-private 可放行
    const proxy_common::ConnectResult cr =
        proxy_common::connect_target_checked(host, port, *m_acl);
    const int out_fd = cr.fd;
    if (out_fd < 0) {
        if (cr.blocked) {
            send_error(browser, "403 Forbidden");
            // ACL 拒绝日志可被高频触发 → 限速（附抑制计数），避免刷屏打满磁盘
            size_t suppressed = 0;
            if (m_log_limiter->allow(proxy_common::now_ms(), &suppressed)) {
                fprintf(stderr, "[HTTPS] %s → %s:%u 被目标 ACL 拒绝（服务端内网/回环/本机；"
                                "内网自用可加 --proxy-allow-private）（已抑制 %zu 条同类日志）\n",
                        sanitize_for_log(peer).c_str(), sanitize_for_log(host).c_str(), port,
                        suppressed);
            }
        } else {
            send_error(browser, "502 Bad Gateway");
            fprintf(stderr, "[HTTPS] %s → %s:%u 连接失败: %s\n", sanitize_for_log(peer).c_str(), host.c_str(),
                    port, strerror(cr.last_errno));
        }
        if (ssl != nullptr) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
        ::close(fd);
        m_conns.fetch_sub(1);
        return;
    }
    Stream target{ out_fd, nullptr };
    set_io_timeout(out_fd, kIoTimeoutSec);

    if (is_connect) {
        static const std::string kEstablished =
            "HTTP/1.1 200 Connection Established\r\n\r\n";
        if (!stream_write(browser, reinterpret_cast<const uint8_t*>(kEstablished.data()),
                          kEstablished.size())) {
            ::close(out_fd);
            if (ssl != nullptr) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
            }
            ::close(fd);
            m_conns.fetch_sub(1);
            return;
        }
    } else {
        if (!stream_write(target, reinterpret_cast<const uint8_t*>(forward_head.data()),
                          forward_head.size())) {
            ::close(out_fd);
            if (ssl != nullptr) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
            }
            ::close(fd);
            m_conns.fetch_sub(1);
            return;
        }
    }
    fprintf(stderr, "[HTTPS] %s → %s:%u 已建立（%s）\n", sanitize_for_log(peer).c_str(), sanitize_for_log(host).c_str(), port,
            m_cfg.use_tls ? "TLS 加密" : "明文");

    // ---- 双向中继 ----
    const auto relay_begin = std::chrono::steady_clock::now();
    proxy_common::relay_two_way(browser, target, kIdleTimeoutMs, m_running);
    const auto relay_secs = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - relay_begin).count();
    if (relay_secs >= kIdleTimeoutMs / 1000) {
        fprintf(stderr, "[HTTPS] %s 空闲超时，回收\n", sanitize_for_log(peer).c_str());
    }

    ::close(out_fd);
    if (ssl != nullptr) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    ::close(fd);
    m_conns.fetch_sub(1);
}
