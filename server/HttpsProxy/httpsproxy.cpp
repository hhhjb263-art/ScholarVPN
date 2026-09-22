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

namespace {

using proxy_common::constant_time_eq;
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

void send_error(Stream& s, const char* status, const char* extra_header = nullptr)
{
    std::string resp = std::string("HTTP/1.1 ") + status + "\r\n";
    if (extra_header != nullptr)
        resp += std::string(extra_header) + "\r\n";
    resp += "Content-Length: 0\r\nConnection: close\r\n\r\n";
    stream_write(s, reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
}

} // namespace

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
        SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION);
        if (SSL_CTX_use_certificate_chain_file(ctx, m_cfg.cert_path.c_str()) != 1) {
            fprintf(stderr, "[HTTPS] 加载证书失败 %s\n", m_cfg.cert_path.c_str());
            SSL_CTX_free(ctx);
            return false;
        }
        if (SSL_CTX_use_PrivateKey_file(ctx, m_cfg.key_path.c_str(), SSL_FILETYPE_PEM) != 1) {
            fprintf(stderr, "[HTTPS] 加载私钥失败 %s\n", m_cfg.key_path.c_str());
            SSL_CTX_free(ctx);
            return false;
        }
        if (SSL_CTX_check_private_key(ctx) != 1) {
            fprintf(stderr, "[HTTPS] 证书与私钥不匹配\n");
            SSL_CTX_free(ctx);
            return false;
        }
        m_ssl_ctx = ctx;
    }
    if (!m_cfg.user.empty()) {
        m_expected_auth = "Basic " + base64_encode(m_cfg.user + ":" + m_cfg.pass);
    }

    m_listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (m_listen_fd < 0) {
        fprintf(stderr, "[HTTPS] socket() failed: %s\n", strerror(errno));
        return false;
    }
    int reuse = 1;
    setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(m_cfg.port);
    if (m_cfg.bind_ip == "0.0.0.0") {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (inet_pton(AF_INET, m_cfg.bind_ip.c_str(), &addr.sin_addr) != 1) {
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
        const std::string peer_str =
            std::string(ipbuf) + ":" + std::to_string(ntohs(peer.sin_port));

        m_conns.fetch_add(1);
        auto done = std::make_shared<std::atomic<bool>>(false);
        try {
            std::lock_guard<std::mutex> lock(m_workers_mutex);
            m_workers.push_back(Worker{ std::thread([this, fd, peer_str, done] {
                handle_conn(fd, peer_str);
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

void HttpConnectProxy::handle_conn(int fd, const std::string& peer)
{
    SSL* ssl = nullptr;
    if (m_ssl_ctx != nullptr) {
        ssl = SSL_new(static_cast<SSL_CTX*>(m_ssl_ctx));
        if (ssl == nullptr) {
            fprintf(stderr, "[HTTPS] %s SSL_new 失败\n", peer.c_str());
            ::close(fd);
            m_conns.fetch_sub(1);
            return;
        }
        SSL_set_accept_state(ssl);   // 明确服务端角色（避免"connection type not set"）
        if (SSL_set_fd(ssl, fd) != 1) {
            fprintf(stderr, "[HTTPS] %s SSL_set_fd 失败\n", peer.c_str());
            log_ssl_errors("");
            SSL_free(ssl);
            ::close(fd);
            m_conns.fetch_sub(1);
            return;
        }
        if (!proxy_common::ssl_handshake_timed(ssl, fd, kHandshakeTimeoutMs)) {
            fprintf(stderr, "[HTTPS] %s TLS 握手失败: ", peer.c_str());
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
        fprintf(stderr, "[HTTPS] %s 读取请求头失败\n", peer.c_str());
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
        const bool ok = req.has_proxy_authorization &&
                        constant_time_eq(req.proxy_authorization, m_expected_auth);
        if (!ok) {
            send_error(browser, "407 Proxy Authentication Required",
                       "Proxy-Authenticate: Basic realm=\"ScholarVPN\"");
            fprintf(stderr, "[HTTPS] %s 认证失败\n", peer.c_str());
            if (ssl != nullptr) {
                SSL_shutdown(ssl);
                SSL_free(ssl);
            }
            ::close(fd);
            m_conns.fetch_sub(1);
            return;
        }
    }

    // ---- 连接目标 ----
    std::string host;
    uint16_t port = 0;
    const bool is_connect = (req.method == "CONNECT");
    std::string forward_head;         // 非 CONNECT：改写为 origin-form 的请求头
    if (is_connect) {
        if (!parse_authority(req.target, host, port)) {
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
        if (!parse_absolute_uri(req.target, host, port, origin_form)) {
            send_error(browser, "501 Not Implemented");   // 仅支持 http:// 绝对形式
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
        proxy_common::connect_target_checked(host, port, m_cfg.allow_private);
    const int out_fd = cr.fd;
    if (out_fd < 0) {
        if (cr.blocked) {
            send_error(browser, "403 Forbidden");
            fprintf(stderr, "[HTTPS] %s → %s:%u 被目标 ACL 拒绝（服务端内网/回环；"
                            "内网自用可加 --proxy-allow-private）\n",
                    peer.c_str(), host.c_str(), port);
        } else {
            send_error(browser, "502 Bad Gateway");
            fprintf(stderr, "[HTTPS] %s → %s:%u 连接失败: %s\n", peer.c_str(), host.c_str(),
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
    fprintf(stderr, "[HTTPS] %s → %s:%u 已建立（%s）\n", peer.c_str(), host.c_str(), port,
            m_cfg.use_tls ? "TLS 加密" : "明文");

    // ---- 双向中继 ----
    const auto relay_begin = std::chrono::steady_clock::now();
    proxy_common::relay_two_way(browser, target, kIdleTimeoutMs, m_running);
    const auto relay_secs = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - relay_begin).count();
    if (relay_secs >= kIdleTimeoutMs / 1000) {
        fprintf(stderr, "[HTTPS] %s 空闲超时，回收\n", peer.c_str());
    }

    ::close(out_fd);
    if (ssl != nullptr) {
        SSL_shutdown(ssl);
        SSL_free(ssl);
    }
    ::close(fd);
    m_conns.fetch_sub(1);
}
