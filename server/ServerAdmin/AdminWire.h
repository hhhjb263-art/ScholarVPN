// ============================================================================
// AdminWire.h —— 中转通道的极简线协议（vpn_controller ↔ admin_agent）
// ----------------------------------------------------------------------------
// 帧格式：[4 字节大端长度][JSON 载荷]，单帧上限 64KB。
// 只处理"扁平对象、值为字符串或整数"的 JSON——通道消息全是这个形状，
// 因此不引入任何 JSON 库，与项目零依赖风格一致（计划书 3.5）。
// 传输：支持明文 TCP（兼容旧部署）与 OpenSSL TLS（生产推荐）。
//       TLS 只负责传输层认证/加密；agent 的 Ed25519 指纹白名单准入不变。
// ============================================================================
#pragma once

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <climits>
#include <cstdint>
#include <cstdlib>     // strtoll
#include <cstring>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace wire {

constexpr size_t kMaxFrame = 64 * 1024;   // 单帧上限：装得下 1000 个令牌的 JSON
constexpr int    kTimeoutMs = 5000;       // 收发默认超时

// ---------------------------------------------------------------- JSON 生成
inline std::string escape(const std::string& s)
{
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

// 极简构造器：wire::Json().str("type","hello").num("id",1).done()
class Json {
public:
    Json& str(const std::string& k, const std::string& v)
    {
        sep();
        s_ += "\"" + k + "\":\"" + escape(v) + "\"";
        return *this;
    }
    Json& num(const std::string& k, long long v)
    {
        sep();
        s_ += "\"" + k + "\":" + std::to_string(v);
        return *this;
    }
    std::string done() const { return s_ + "}"; }

private:
    void sep() { if (!first_) s_ += ","; first_ = false; }
    std::string s_ = "{";
    bool first_ = true;
};

// ---------------------------------------------------------------- JSON 解析
// 定位 "key" 冒号之后的第一个非空白字符；找不到返回 npos
inline size_t find_value(const std::string& obj, const std::string& key)
{
    const std::string pat = "\"" + key + "\"";
    const size_t k = obj.find(pat);
    if (k == std::string::npos) return std::string::npos;
    const size_t c = obj.find(':', k + pat.size());
    if (c == std::string::npos) return std::string::npos;
    size_t i = c + 1;
    while (i < obj.size() && (obj[i] == ' ' || obj[i] == '\t' ||
                              obj[i] == '\n' || obj[i] == '\r'))
        ++i;
    return i;
}

// 取字符串字段（值须为 "..."，含转义还原）。成功返回 true。
inline bool get_string(const std::string& obj, const std::string& key, std::string& out)
{
    size_t i = find_value(obj, key);
    if (i == std::string::npos || i >= obj.size() || obj[i] != '"') return false;
    ++i;
    std::string v;
    while (i < obj.size()) {
        const char c = obj[i++];
        if (c == '"') { out = v; return true; }
        if (c == '\\' && i < obj.size()) {
            const char e = obj[i++];
            switch (e) {
                case 'n':  v += '\n'; break;
                case 'r':  v += '\r'; break;
                case 't':  v += '\t'; break;
                case '"':  v += '"';  break;
                case '\\': v += '\\'; break;
                case '/':  v += '/';  break;
                default:   v += e;    break;   // 其他转义原样保留
            }
        } else {
            v += c;
        }
    }
    return false;   // 引号没闭合
}

// 取整数字段。成功返回 true。
inline bool get_int(const std::string& obj, const std::string& key, long long& out)
{
    const size_t i = find_value(obj, key);
    if (i == std::string::npos || i >= obj.size()) return false;
    char* end = nullptr;
    const long long v = std::strtoll(obj.c_str() + i, &end, 10);
    if (end == obj.c_str() + i) return false;
    out = v;
    return true;
}

// ---------------------------------------------------------------- 分帧
// 写一帧（阻塞、处理部分写）。@return false = 连接已坏
inline bool send_frame(int fd, const std::string& payload)
{
    if (payload.size() > kMaxFrame) return false;
    uint8_t hdr[4];
    const uint32_t n = static_cast<uint32_t>(payload.size());
    hdr[0] = uint8_t(n >> 24);
    hdr[1] = uint8_t(n >> 16);
    hdr[2] = uint8_t(n >> 8);
    hdr[3] = uint8_t(n);
    const char* parts[2] = { reinterpret_cast<const char*>(hdr), payload.data() };
    const size_t lens[2] = { 4, payload.size() };
    for (int p = 0; p < 2; ++p) {
        size_t off = 0;
        while (off < lens[p]) {
            const ssize_t w = ::send(fd, parts[p] + off, lens[p] - off, MSG_NOSIGNAL);
            if (w > 0) { off += static_cast<size_t>(w); continue; }
            if (w < 0 && errno == EINTR) continue;
            return false;
        }
    }
    return true;
}

// 读缓冲：把 recv 到的字节喂进来，按 4 字节长度前缀逐帧取出
class Framer {
public:
    void feed(const char* data, size_t n) { buf_.append(data, n); }

    // 缓冲里凑齐一帧则取到 out 并返回 true；否则返回 false（继续喂）
    bool next(std::string& out)
    {
        if (buf_.size() < 4) return false;
        const uint8_t* h = reinterpret_cast<const uint8_t*>(buf_.data());
        const uint32_t len = (uint32_t(h[0]) << 24) | (uint32_t(h[1]) << 16) |
                             (uint32_t(h[2]) << 8)  |  uint32_t(h[3]);
        if (len > kMaxFrame) { bad_ = true; return false; }   // 超限：调用方应断开
        if (buf_.size() < 4 + len) return false;
        out.assign(buf_, 4, len);
        buf_.erase(0, 4 + len);
        return true;
    }

    bool bad() const { return bad_; }

private:
    std::string buf_;
    bool bad_ = false;
};

// ---------------------------------------------------------------- TLS 上下文
// 只用 OpenSSL 的公开 API；不实现任何密码学算法、不生成证书。
inline std::string tls_error()
{
    std::string out;
    unsigned long e = 0;
    while ((e = ERR_get_error()) != 0) {
        char buf[256]{};
        ERR_error_string_n(e, buf, sizeof(buf));
        if (!out.empty()) out += "; ";
        out += buf;
    }
    return out.empty() ? std::string("unknown TLS error") : out;
}

// 服务端证书/私钥（PEM）。cert 用 fullchain.pem，key 用 privkey.pem。
inline SSL_CTX* make_server_ctx(const std::string& cert, const std::string& key,
                                std::string& err)
{
    SSL_CTX* ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == nullptr) { err = tls_error(); return nullptr; }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
    if (SSL_CTX_use_certificate_chain_file(ctx, cert.c_str()) != 1) {
        err = "加载证书失败 " + cert + ": " + tls_error();
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key.c_str(), SSL_FILETYPE_PEM) != 1) {
        err = "加载私钥失败 " + key + ": " + tls_error();
        SSL_CTX_free(ctx);
        return nullptr;
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        err = "证书与私钥不匹配: " + tls_error();
        SSL_CTX_free(ctx);
        return nullptr;
    }
    return ctx;
}

// 客户端信任根：ca_file 非空时只信任该 PEM（自签/私有 CA 用）；
// 为空时使用系统 CA 仓库（Let's Encrypt 等公共 CA 用）。
inline SSL_CTX* make_client_ctx(const std::string& ca_file, std::string& err)
{
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == nullptr) { err = tls_error(); return nullptr; }
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_verify_depth(ctx, 10);
    if (ca_file.empty()) {
        if (SSL_CTX_set_default_verify_paths(ctx) != 1) {
            err = "加载系统 CA 失败: " + tls_error();
            SSL_CTX_free(ctx);
            return nullptr;
        }
    } else if (SSL_CTX_load_verify_locations(ctx, ca_file.c_str(), nullptr) != 1) {
        err = "加载 CA 失败 " + ca_file + ": " + tls_error();
        SSL_CTX_free(ctx);
        return nullptr;
    }
    return ctx;
}

// ---------------------------------------------------------------- 连接（TCP / TLS）
// 一个连接对象同时支持明文 TCP 与 TLS。socket 全程非阻塞：
// 超时由每次 poll 的 deadline 控制，避免慢对端把管理线程卡死。
class Conn {
public:
    Conn() = default;
    ~Conn() { close(); }
    Conn(const Conn&) = delete;
    Conn& operator=(const Conn&) = delete;
    Conn(Conn&& o) noexcept : fd_(o.fd_), ssl_(o.ssl_)
    {
        o.fd_ = -1;
        o.ssl_ = nullptr;
    }
    Conn& operator=(Conn&& o) noexcept
    {
        if (this != &o) {
            close();
            fd_ = o.fd_;
            ssl_ = o.ssl_;
            o.fd_ = -1;
            o.ssl_ = nullptr;
        }
        return *this;
    }

    int fd() const { return fd_; }
    bool is_tls() const { return ssl_ != nullptr; }

    // 接管一个已 accept 的 fd（所有权转移给 Conn）
    void adopt_fd(int fd)
    {
        close();
        fd_ = fd;
    }

    // 域名/IP 解析 + 非阻塞 connect。失败时 err 给出可读原因。
    bool connect_tcp(const std::string& host, uint16_t port, int timeout_ms,
                     std::string& err)
    {
        close();
        addrinfo hints{};
        // 服务端（vpn_controller/admin_server）只监听 AF_INET；
        // 这里强制 IPv4，避免双栈域名先解析到不可达的 IPv6 时把 5s 超时耗光。
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;
        addrinfo* res = nullptr;
        const std::string port_s = std::to_string(port);
        const int gai = ::getaddrinfo(host.c_str(), port_s.c_str(), &hints, &res);
        if (gai != 0) {
            err = "DNS 解析失败 " + host + ": " + std::string(gai_strerror(gai));
            return false;
        }

        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeout_ms);
        std::string last = "无可用地址";
        for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
            const int fd = ::socket(ai->ai_family,
                                    ai->ai_socktype | SOCK_CLOEXEC | SOCK_NONBLOCK,
                                    ai->ai_protocol);
            if (fd < 0) {
                last = std::string("socket: ") + strerror(errno);
                continue;
            }
            int rc = ::connect(fd, ai->ai_addr, ai->ai_addrlen);
            if (rc < 0 && errno != EINPROGRESS) {
                last = std::string("connect: ") + strerror(errno);
                ::close(fd);
                continue;
            }
            if (rc < 0) {
                const int remain = remaining_ms(deadline);
                if (remain <= 0) {
                    last = "连接超时";
                    ::close(fd);
                    break;
                }
                pollfd p{};
                p.fd = fd;
                p.events = POLLOUT;
                int pr = 0;
                do { pr = ::poll(&p, 1, remain); } while (pr < 0 && errno == EINTR);
                if (pr <= 0) {
                    last = (pr == 0) ? "连接超时" : strerror(errno);
                    ::close(fd);
                    continue;
                }
                int so_err = 0;
                socklen_t sl = sizeof(so_err);
                if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &sl) != 0 ||
                    so_err != 0) {
                    last = std::string("connect: ") +
                           strerror(so_err != 0 ? so_err : errno);
                    ::close(fd);
                    continue;
                }
            }
            int one = 1;
            ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            fd_ = fd;
            ::freeaddrinfo(res);
            return true;
        }
        ::freeaddrinfo(res);
        err = "无法连接 " + host + ":" + port_s + "（" + last + "）";
        return false;
    }

    // TLS 客户端握手：校验证书链 + 主机名/IP（SSL_VERIFY_PEER）。
    // server_name 是证书里的名字（通常是域名），不是连接地址。
    bool enable_tls_client(SSL_CTX* ctx, const std::string& server_name,
                           int timeout_ms, std::string& err)
    {
        if (fd_ < 0 || ctx == nullptr) { err = "TLS 配置无效"; return false; }
        if (ssl_ != nullptr) { err = "连接已启用 TLS"; return false; }

        ssl_ = SSL_new(ctx);
        if (ssl_ == nullptr) { err = tls_error(); return false; }
        if (SSL_set_fd(ssl_, fd_) != 1) {
            err = tls_error();
            drop_ssl();
            return false;
        }

        unsigned char addr[16]{};
        const bool is_ip = ::inet_pton(AF_INET, server_name.c_str(), addr) == 1 ||
                           ::inet_pton(AF_INET6, server_name.c_str(), addr) == 1;
        if (!is_ip) {
            if (SSL_set_tlsext_host_name(ssl_, server_name.c_str()) != 1 ||
                SSL_set1_host(ssl_, server_name.c_str()) != 1) {
                err = tls_error();
                drop_ssl();
                return false;
            }
        } else {
            X509_VERIFY_PARAM* param = SSL_get0_param(ssl_);
            X509_VERIFY_PARAM_set_hostflags(param, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS);
            if (X509_VERIFY_PARAM_set1_ip_asc(param, server_name.c_str()) != 1) {
                err = tls_error();
                drop_ssl();
                return false;
            }
        }

        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeout_ms);
        for (;;) {
            const int rc = SSL_connect(ssl_);
            if (rc == 1) break;
            const int e = SSL_get_error(ssl_, rc);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                const int remain = remaining_ms(deadline);
                if (remain <= 0) { err = "TLS 握手超时"; drop_ssl(); return false; }
                const int pr = wait_fd(fd_,
                                       e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT,
                                       remain);
                if (pr <= 0) {
                    err = (pr == 0) ? "TLS 握手超时" : strerror(errno);
                    drop_ssl();
                    return false;
                }
                continue;
            }
            const long vr = SSL_get_verify_result(ssl_);
            err = tls_error();
            if (vr != X509_V_OK)
                err += std::string("; 证书校验失败: ") +
                       X509_verify_cert_error_string(vr);
            drop_ssl();
            return false;
        }
        if (SSL_get_verify_result(ssl_) != X509_V_OK) {
            err = std::string("证书校验失败: ") +
                  X509_verify_cert_error_string(SSL_get_verify_result(ssl_));
            drop_ssl();
            return false;
        }
        return true;
    }

    // TLS 服务端握手（证书由 SSL_CTX 提供；不要求客户端证书，
    // agent 身份仍由现有的 Ed25519 challenge/hello 白名单校验）。
    bool enable_tls_server(SSL_CTX* ctx, int timeout_ms, std::string& err)
    {
        if (fd_ < 0 || ctx == nullptr) { err = "TLS 配置无效"; return false; }
        if (ssl_ != nullptr) { err = "连接已启用 TLS"; return false; }

        ssl_ = SSL_new(ctx);
        if (ssl_ == nullptr) { err = tls_error(); return false; }
        if (SSL_set_fd(ssl_, fd_) != 1) {
            err = tls_error();
            drop_ssl();
            return false;
        }

        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeout_ms);
        for (;;) {
            const int rc = SSL_accept(ssl_);
            if (rc == 1) return true;
            const int e = SSL_get_error(ssl_, rc);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE) {
                const int remain = remaining_ms(deadline);
                if (remain <= 0) { err = "TLS 握手超时"; drop_ssl(); return false; }
                const int pr = wait_fd(fd_,
                                       e == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT,
                                       remain);
                if (pr <= 0) {
                    err = (pr == 0) ? "TLS 握手超时" : strerror(errno);
                    drop_ssl();
                    return false;
                }
                continue;
            }
            err = tls_error();
            drop_ssl();
            return false;
        }
    }

    bool send_frame(const std::string& payload)
    {
        if (fd_ < 0 || payload.size() > kMaxFrame) return false;
        uint8_t hdr[4];
        const uint32_t n = static_cast<uint32_t>(payload.size());
        hdr[0] = uint8_t(n >> 24);
        hdr[1] = uint8_t(n >> 16);
        hdr[2] = uint8_t(n >> 8);
        hdr[3] = uint8_t(n);
        return send_all(reinterpret_cast<const char*>(hdr), 4, kTimeoutMs) &&
               send_all(payload.data(), payload.size(), kTimeoutMs);
    }

    // 收一帧：1=完整帧 0=超时 -1=连接坏（语义与下方 int fd 兼容接口一致）
    int recv_frame(Framer& fr, std::string& frame, int timeout_ms)
    {
        if (fd_ < 0) return -1;
        if (fr.next(frame)) return 1;
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeout_ms);
        short wait_events = POLLIN;
        char buf[4096];
        for (;;) {
            const bool buffered = (ssl_ != nullptr) && (SSL_pending(ssl_) > 0);
            if (!buffered) {
                const int remain = remaining_ms(deadline);
                if (remain <= 0) return 0;
                pollfd p{};
                p.fd = fd_;
                p.events = wait_events;
                int pr = 0;
                do { pr = ::poll(&p, 1, remain); } while (pr < 0 && errno == EINTR);
                if (pr == 0) return 0;
                if (pr < 0) return -1;
                if (p.revents & (POLLERR | POLLNVAL)) return -1;
            }

            ssize_t n = 0;
            if (ssl_ != nullptr) {
                n = SSL_read(ssl_, buf, static_cast<int>(sizeof(buf)));
                if (n <= 0) {
                    const int e = SSL_get_error(ssl_, static_cast<int>(n));
                    if (e == SSL_ERROR_WANT_READ) { wait_events = POLLIN; continue; }
                    if (e == SSL_ERROR_WANT_WRITE) { wait_events = POLLOUT; continue; }
                    return -1;
                }
                wait_events = POLLIN;
            } else {
                n = ::recv(fd_, buf, sizeof(buf), 0);
                if (n < 0) {
                    if (errno == EINTR) continue;
                    if (errno == EAGAIN || errno == EWOULDBLOCK) {
                        wait_events = POLLIN;
                        continue;
                    }
                    return -1;
                }
                if (n == 0) return -1;
            }

            fr.feed(buf, static_cast<size_t>(n));
            if (fr.bad()) return -1;
            if (fr.next(frame)) return 1;
        }
    }

    void close()
    {
        if (ssl_ != nullptr) {
            SSL_shutdown(ssl_);      // 尽力发送 close_notify；非阻塞，失败不重试
            SSL_free(ssl_);
            ssl_ = nullptr;
        }
        if (fd_ >= 0) {
            ::close(fd_);
            fd_ = -1;
        }
    }

private:
    static int remaining_ms(std::chrono::steady_clock::time_point deadline)
    {
        const auto d = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        return d > 0 ? static_cast<int>(d) : 0;
    }

    // @return >0=就绪 0=超时 <0=错误
    int wait_fd(int fd, short events, int timeout_ms)
    {
        pollfd p{};
        p.fd = fd;
        p.events = events;
        int pr = 0;
        do { pr = ::poll(&p, 1, timeout_ms); } while (pr < 0 && errno == EINTR);
        return pr;
    }

    bool send_all(const char* data, size_t len, int timeout_ms)
    {
        const auto deadline = std::chrono::steady_clock::now() +
                              std::chrono::milliseconds(timeout_ms);
        size_t off = 0;
        while (off < len) {
            ssize_t n = 0;
            if (ssl_ != nullptr) {
                const size_t chunk = (std::min)(len - off, size_t(1) << 20);
                n = SSL_write(ssl_, data + off, static_cast<int>(chunk));
                if (n <= 0) {
                    const int e = SSL_get_error(ssl_, static_cast<int>(n));
                    short ev = 0;
                    if (e == SSL_ERROR_WANT_READ) ev = POLLIN;
                    else if (e == SSL_ERROR_WANT_WRITE) ev = POLLOUT;
                    else return false;
                    const int remain = remaining_ms(deadline);
                    if (remain <= 0) return false;
                    if (wait_fd(fd_, ev, remain) <= 0) return false;
                    continue;
                }
            } else {
                n = ::send(fd_, data + off, len - off, MSG_NOSIGNAL);
                if (n <= 0) {
                    if (n < 0 && errno == EINTR) continue;
                    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                        const int remain = remaining_ms(deadline);
                        if (remain <= 0) return false;
                        if (wait_fd(fd_, POLLOUT, remain) <= 0) return false;
                        continue;
                    }
                    return false;
                }
            }
            off += static_cast<size_t>(n);
        }
        return true;
    }

    void drop_ssl()
    {
        if (ssl_ != nullptr) {
            SSL_free(ssl_);
            ssl_ = nullptr;
        }
    }

    int fd_ = -1;
    SSL* ssl_ = nullptr;
};

// ---------------------------------------------------------------- 收帧
// 收一帧：1=取到完整帧 0=timeout_ms 内没凑齐 -1=连接坏。
// 必须循环读而不是单次 recv：send_frame 的长度头(4B)与载荷是两个 send，
// TCP 可能分两段到达——只拿到半帧时不能当成连接故障，否则握手会随
// 分片时序随机失败（表现为 agent 连上瞬间断开、退避重连的死循环）。
// 另外对端"发完就关"（reject 后 close）时 revents 会带 POLLHUP：
// 不能见 HUP 就返回 -1，要把已到达的字节读出来；recv 返回 0 才算断开。
inline int recv_frame(int fd, Framer& fr, std::string& frame, int timeout_ms)
{
    if (fr.next(frame)) return 1;
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);
    for (;;) {
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) return 0;
        const auto remain =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        pollfd p{};
        p.fd = fd;
        p.events = POLLIN;
        const int pr = ::poll(&p, 1, remain > 0 ? static_cast<int>(remain) : 1);
        if (pr == 0) return 0;
        if (pr < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (p.revents & (POLLERR | POLLNVAL)) return -1;

        char buf[4096];
        const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n == 0) return -1;   // 对端关闭（缓冲数据已读完）
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) continue;
            return -1;
        }
        fr.feed(buf, static_cast<size_t>(n));
        if (fr.bad()) return -1;
        if (fr.next(frame)) return 1;
    }
}

}  // namespace wire
