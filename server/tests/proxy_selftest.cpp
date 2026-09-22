// ============================================================================
// 浏览器代理入口运行期自测（Windows 开发机可跑；服务端正式构建在 Linux）
//
// 覆盖三个入口：
//   1) SOCKS5（server/Socks5）：方法协商 / RFC1929 认证 / CONNECT（IPv4、域名）/
//      双向中继 / 拒绝路径
//   2) HTTP CONNECT（server/HttpsProxy，明文）：CONNECT 中继 / Basic 认证 407 /
//      绝对形式 GET 转发 / 非法请求
//   3) HTTPS CONNECT（server/HttpsProxy，TLS）：真实 TLS 握手（本地自签证书）+
//      CONNECT 中继；并验证"明文打到 TLS 端口不成立"（确认真的在加密）
//
// 做法：Winsock 兼容垫片（shim_include/ + socks5_win_shim.h）把 Linux 源码原样
// 编译到 Windows，用真实 socket + 真实 OpenSSL 跑端到端用例。
//
// 编译运行（VS2022 x64 Native Tools，cl 在 PATH；TLS 用例需 libssl）：
//   见 server/tests/README.md
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "httpsproxy.h"
#include "socks5.h"

namespace {

int g_fail = 0;

void check(const char* name, bool ok, const char* detail = "")
{
    if (ok) {
        printf("  [OK] %s\n", name);
    } else {
        printf("  [FAIL] %s %s\n", name, detail);
        ++g_fail;
    }
    fflush(stdout);
}

// ---------------------------------------------------------------------------
// 测试用连接抽象：明文 fd 或 TLS
// ---------------------------------------------------------------------------
struct Conn
{
    SOCKET fd = INVALID_SOCKET;
    SSL* ssl = nullptr;

    bool send_all(const void* buf, size_t n)
    {
        const char* p = static_cast<const char*>(buf);
        size_t off = 0;
        while (off < n) {
            const int w = (ssl != nullptr)
                              ? SSL_write(ssl, p + off, static_cast<int>(n - off))
                              : ::send(fd, p + off, static_cast<int>(n - off), 0);
            if (w <= 0)
                return false;
            off += static_cast<size_t>(w);
        }
        return true;
    }

    bool recv_all(void* buf, size_t n)
    {
        char* p = static_cast<char*>(buf);
        size_t off = 0;
        while (off < n) {
            const int r = (ssl != nullptr)
                              ? SSL_read(ssl, p + off, static_cast<int>(n - off))
                              : ::recv(fd, p + off, static_cast<int>(n - off), 0);
            if (r <= 0)
                return false;
            off += static_cast<size_t>(r);
        }
        return true;
    }

    // 读到 \r\n\r\n 为止（HTTP 响应头）
    bool recv_until_headers(std::string& out, size_t cap = 8192)
    {
        out.clear();
        char ch = 0;
        while (out.size() < cap) {
            if (!recv_all(&ch, 1))
                return false;
            out.push_back(ch);
            if (out.size() >= 4 && out.compare(out.size() - 4, 4, "\r\n\r\n") == 0)
                return true;
        }
        return false;
    }

    void close_all()
    {
        if (ssl != nullptr) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
            ssl = nullptr;
        }
        if (fd != INVALID_SOCKET) {
            closesocket(fd);
            fd = INVALID_SOCKET;
        }
    }
};

Conn tcp_connect(uint16_t port)
{
    Conn c;
    c.fd = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
    if (connect(c.fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        c.close_all();
        return c;
    }
    return c;
}

// ---------------------------------------------------------------------------
// 本地回显服务：循环 accept（每连接一线程），原样回写
// ---------------------------------------------------------------------------
class EchoServer
{
public:
    bool start()
    {
        m_listen = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = 0;
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        if (bind(m_listen, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0)
            return false;
        socklen_t len = sizeof(a);
        if (getsockname(m_listen, reinterpret_cast<sockaddr*>(&a), &len) != 0)
            return false;
        m_port = ntohs(a.sin_port);
        if (listen(m_listen, 16) != 0)
            return false;
        m_thread = std::thread([this] {
            for (;;) {
                const SOCKET s = accept(m_listen, nullptr, nullptr);
                if (s == INVALID_SOCKET)
                    return;
                std::thread([s] {
                    char buf[4096];
                    for (;;) {
                        const int r = recv(s, buf, sizeof(buf), 0);
                        if (r <= 0)
                            break;
                        send(s, buf, r, 0);
                    }
                    closesocket(s);
                }).detach();
            }
        });
        return true;
    }
    uint16_t port() const { return m_port; }
    ~EchoServer()
    {
        if (m_thread.joinable())
            m_thread.join();
        if (m_listen != INVALID_SOCKET)
            closesocket(m_listen);
    }

private:
    SOCKET m_listen = INVALID_SOCKET;
    uint16_t m_port = 0;
    std::thread m_thread;
};

// 极简 HTTP 服务：accept 后读请求，回固定报文（验证绝对形式转发）
class MiniHttpServer
{
public:
    bool start()
    {
        m_listen = socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_port = 0;
        inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
        if (bind(m_listen, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0)
            return false;
        socklen_t len = sizeof(a);
        if (getsockname(m_listen, reinterpret_cast<sockaddr*>(&a), &len) != 0)
            return false;
        m_port = ntohs(a.sin_port);
        if (listen(m_listen, 8) != 0)
            return false;
        m_thread = std::thread([this] {
            for (;;) {
                const SOCKET s = accept(m_listen, nullptr, nullptr);
                if (s == INVALID_SOCKET)
                    return;
                std::thread([s] {
                    // 读到请求头结束
                    std::string req;
                    char ch = 0;
                    while (req.size() < 8192) {
                        const int r = recv(s, &ch, 1, 0);
                        if (r <= 0)
                            break;
                        req.push_back(ch);
                        if (req.size() >= 4 && req.compare(req.size() - 4, 4, "\r\n\r\n") == 0)
                            break;
                    }
                    // 记录首行供断言（转储到全局由测试读取不必要：直接回显首行长度校验）
                    static const char body[] = "hello-from-http";
                    const std::string resp =
                        "HTTP/1.1 200 OK\r\nContent-Length: " +
                        std::to_string(sizeof(body) - 1) + "\r\nConnection: close\r\n\r\n" + body;
                    send(s, resp.data(), static_cast<int>(resp.size()), 0);
                    closesocket(s);
                }).detach();
            }
        });
        return true;
    }
    uint16_t port() const { return m_port; }
    ~MiniHttpServer()
    {
        if (m_thread.joinable())
            m_thread.join();
        if (m_listen != INVALID_SOCKET)
            closesocket(m_listen);
    }

private:
    SOCKET m_listen = INVALID_SOCKET;
    uint16_t m_port = 0;
    std::thread m_thread;
};

// ---------------------------------------------------------------------------
// SOCKS5 客户端
// ---------------------------------------------------------------------------
Conn socks5_connect(uint16_t proxy_port, const std::string& host, uint16_t target_port,
                    const std::string& user = "", const std::string& pass = "",
                    uint8_t* out_rep = nullptr)
{
    if (out_rep)
        *out_rep = 0xFF;
    Conn c = tcp_connect(proxy_port);
    if (c.fd == INVALID_SOCKET)
        return c;

    const bool need_auth = !user.empty();
    const uint8_t greet[3] = { 0x05, 0x01, static_cast<uint8_t>(need_auth ? 0x02 : 0x00) };
    uint8_t resp[2] = {0};
    if (!c.send_all(greet, sizeof(greet)) || !c.recv_all(resp, 2) ||
        resp[0] != 0x05 || resp[1] != greet[2]) {
        c.close_all();
        return c;
    }
    if (need_auth) {
        std::vector<uint8_t> ar{ 0x01, static_cast<uint8_t>(user.size()) };
        ar.insert(ar.end(), user.begin(), user.end());
        ar.push_back(static_cast<uint8_t>(pass.size()));
        ar.insert(ar.end(), pass.begin(), pass.end());
        uint8_t aresp[2] = {0};
        if (!c.send_all(ar.data(), ar.size()) || !c.recv_all(aresp, 2) ||
            aresp[0] != 0x01 || aresp[1] != 0x00) {
            if (out_rep)
                *out_rep = aresp[1];
            c.close_all();
            return c;
        }
    }
    std::vector<uint8_t> req{ 0x05, 0x01, 0x00 };
    sockaddr_in a{};
    if (inet_pton(AF_INET, host.c_str(), &a.sin_addr) == 1) {
        req.push_back(0x01);
        const uint8_t* ip = reinterpret_cast<const uint8_t*>(&a.sin_addr);
        req.insert(req.end(), ip, ip + 4);
    } else {
        req.push_back(0x03);
        req.push_back(static_cast<uint8_t>(host.size()));
        req.insert(req.end(), host.begin(), host.end());
    }
    req.push_back(static_cast<uint8_t>(target_port >> 8));
    req.push_back(static_cast<uint8_t>(target_port & 0xFF));
    if (!c.send_all(req.data(), req.size())) {
        c.close_all();
        return c;
    }
    uint8_t rep[10] = {0};
    if (!c.recv_all(rep, sizeof(rep)) || rep[0] != 0x05) {
        c.close_all();
        return c;
    }
    if (out_rep)
        *out_rep = rep[1];
    if (rep[1] != 0x00) {
        c.close_all();
        return c;
    }
    return c;
}

// ---------------------------------------------------------------------------
// HTTP CONNECT 代理客户端（Connection = 明文或 TLS）
// ---------------------------------------------------------------------------
std::string base64_creds(const std::string& u, const std::string& p);
Conn http_proxy_connect(Conn c, const std::string& host, uint16_t port,
                        const std::string& user = "", const std::string& pass = "",
                        int* out_status = nullptr)
{
    if (out_status)
        *out_status = 0;
    std::string req = "CONNECT " + host + ":" + std::to_string(port) + " HTTP/1.1\r\n";
    req += "Host: " + host + ":" + std::to_string(port) + "\r\n";
    if (!user.empty())
        req += "Proxy-Authorization: Basic " + base64_creds(user, pass) + "\r\n";
    req += "\r\n";
    if (!c.send_all(req.data(), req.size())) {
        c.close_all();
        return c;
    }
    std::string head;
    if (!c.recv_until_headers(head)) {
        c.close_all();
        return c;
    }
    const int status = (head.size() >= 12) ? atoi(head.c_str() + 9) : 0;
    if (out_status)
        *out_status = status;
    if (status != 200) {
        c.close_all();
        return c;
    }
    return c;
}

std::string base64_creds(const std::string& u, const std::string& p)
{
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const std::string in = u + ":" + p;
    std::string out;
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
        out += "==";
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

// ---------------------------------------------------------------------------
// 用例：SOCKS5（回归）
// ---------------------------------------------------------------------------
void test_socks5(uint16_t proxy_port, uint16_t auth_port, uint16_t echo_port)
{
    printf("SOCKS5 用例\n");
    {
        Conn c = socks5_connect(proxy_port, "127.0.0.1", echo_port);
        check("IPv4 CONNECT 成功", c.fd != INVALID_SOCKET);
        if (c.fd != INVALID_SOCKET) {
            const std::string msg = "socks5-ipv4-relay";
            bool ok = c.send_all(msg.data(), msg.size());
            std::vector<char> got(msg.size());
            ok = ok && c.recv_all(got.data(), got.size()) &&
                 memcmp(got.data(), msg.data(), msg.size()) == 0;
            check("双向中继回显一致", ok);
            c.close_all();
        }
    }
    {
        Conn c = socks5_connect(proxy_port, "localhost", echo_port);
        check("域名目标 CONNECT 成功", c.fd != INVALID_SOCKET);
        c.close_all();
    }
    {
        uint8_t rep = 0xFF;
        Conn c = socks5_connect(proxy_port, "127.0.0.1", 1, "", "", &rep);
        check("端口不可达 → 失败应答", c.fd == INVALID_SOCKET && rep != 0x00 && rep != 0xFF);
    }
    {
        Conn c = tcp_connect(proxy_port);
        const uint8_t greet[3] = { 0x05, 0x01, 0x00 };
        uint8_t resp[2] = {0};
        bool ok = c.fd != INVALID_SOCKET && c.send_all(greet, 3) && c.recv_all(resp, 2) &&
                  resp[1] == 0x00;
        const uint8_t bind_req[10] = { 0x05, 0x02, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x50 };
        uint8_t rep[10] = {0};
        ok = ok && c.send_all(bind_req, sizeof(bind_req)) && c.recv_all(rep, sizeof(rep)) &&
             rep[1] == 0x07;
        check("BIND 被拒（REP=0x07）", ok);
        c.close_all();
    }
    {
        uint8_t rep = 0xFF;
        Conn bad = socks5_connect(auth_port, "127.0.0.1", echo_port, "alice", "wrong", &rep);
        check("错误密码被拒（auth rep=0x01）", bad.fd == INVALID_SOCKET && rep == 0x01);
        Conn ok = socks5_connect(auth_port, "127.0.0.1", echo_port, "alice", "s3cret");
        check("正确密码完成 CONNECT", ok.fd != INVALID_SOCKET);
        ok.close_all();
    }
}

// ---------------------------------------------------------------------------
// 用例：HTTP CONNECT 代理（明文）
// ---------------------------------------------------------------------------
void test_http_proxy(uint16_t proxy_port, uint16_t auth_port, uint16_t echo_port,
                     uint16_t http_port)
{
    printf("HTTP 代理（明文）用例\n");
    {
        Conn c = tcp_connect(proxy_port);
        int status = 0;
        c = http_proxy_connect(c, "127.0.0.1", echo_port, "", "", &status);
        check("CONNECT 200 并建立隧道", c.fd != INVALID_SOCKET && status == 200);
        if (c.fd != INVALID_SOCKET) {
            const std::string msg = "http-connect-relay";
            bool ok = c.send_all(msg.data(), msg.size());
            std::vector<char> got(msg.size());
            ok = ok && c.recv_all(got.data(), got.size()) &&
                 memcmp(got.data(), msg.data(), msg.size()) == 0;
            check("CONNECT 后双向中继一致", ok);
            c.close_all();
        }
    }
    {
        // 未认证：应回 407 + Proxy-Authenticate
        Conn c = tcp_connect(auth_port);
        std::string req = "CONNECT 127.0.0.1:" + std::to_string(echo_port) +
                          " HTTP/1.1\r\nHost: x\r\n\r\n";
        c.send_all(req.data(), req.size());
        std::string head;
        const bool got = c.recv_until_headers(head);
        check("无凭据 → 407 Proxy Authentication Required",
              got && head.find("407") != std::string::npos &&
                  head.find("Proxy-Authenticate: Basic") != std::string::npos);
        c.close_all();
    }
    {
        Conn c = tcp_connect(auth_port);
        int status = 0;
        c = http_proxy_connect(c, "127.0.0.1", echo_port, "wrong", "creds", &status);
        check("错误凭据 → 407", status == 407);
        c.close_all();
    }
    {
        Conn c = tcp_connect(auth_port);
        int status = 0;
        c = http_proxy_connect(c, "127.0.0.1", echo_port, "alice", "s3cret", &status);
        check("正确凭据 → 200 并建立隧道", status == 200 && c.fd != INVALID_SOCKET);
        c.close_all();
    }
    {
        // 绝对形式 GET（明文 HTTP 站点路径）
        Conn c = tcp_connect(proxy_port);
        const std::string req =
            "GET http://127.0.0.1:" + std::to_string(http_port) + "/index.html HTTP/1.1\r\n"
            "Host: 127.0.0.1:" + std::to_string(http_port) + "\r\n"
            "Proxy-Connection: keep-alive\r\n"
            "Proxy-Authorization: Basic xxxx\r\n\r\n";
        bool ok = c.send_all(req.data(), req.size());
        std::string head;
        ok = ok && c.recv_until_headers(head);
        check("绝对形式 GET 被转发（收到 200 响应头）",
              ok && head.find("200 OK") != std::string::npos);
        // 读 body
        std::string body;
        if (ok) {
            char buf[256];
            const int r = recv(c.fd, buf, sizeof(buf), 0);
            if (r > 0)
                body.assign(buf, static_cast<size_t>(r));
        }
        check("响应体来自目标 HTTP 服务", body.find("hello-from-http") != std::string::npos);
        c.close_all();
    }
    {
        // 非法请求（origin-form 且非 CONNECT）→ 501
        Conn c = tcp_connect(proxy_port);
        const std::string req = "GET /index.html HTTP/1.1\r\nHost: x\r\n\r\n";
        c.send_all(req.data(), req.size());
        std::string head;
        const bool got = c.recv_until_headers(head);
        check("非绝对形式请求 → 501", got && head.find("501") != std::string::npos);
        c.close_all();
    }
}

// ---------------------------------------------------------------------------
// 用例：目标地址 ACL（默认拒绝服务端内网/回环目标）
// ---------------------------------------------------------------------------
void test_target_acl(uint16_t socks_port, uint16_t http_port, uint16_t echo_port)
{
    printf("目标 ACL 用例（默认拒绝内网/回环）\n");

    // SOCKS5：127.0.0.1 目标应被拒绝，且应答码为 0x02（not allowed by ruleset）
    {
        uint8_t rep = 0xFF;
        Conn c = socks5_connect(socks_port, "127.0.0.1", echo_port, "", "", &rep);
        check("SOCKS5 回环目标被拒绝（REP=0x02）", c.fd == INVALID_SOCKET && rep == 0x02);
        c.close_all();
    }
    // SOCKS5：域名解析到回环（localhost）同样被拒绝
    {
        uint8_t rep = 0xFF;
        Conn c = socks5_connect(socks_port, "localhost", echo_port, "", "", &rep);
        check("SOCKS5 解析到回环的域名被拒绝", c.fd == INVALID_SOCKET && rep == 0x02);
        c.close_all();
    }
    // HTTP 代理：回环目标回 403
    {
        Conn c = tcp_connect(http_port);
        int status = 0;
        c = http_proxy_connect(c, "127.0.0.1", echo_port, "", "", &status);
        check("HTTP 代理回环目标被拒绝（403）", status == 403 && c.fd == INVALID_SOCKET);
        c.close_all();
    }
    // 私网网段（10.8.0.x = TUN 客户端虚拟 IP 段）同样被拒绝
    {
        uint8_t rep = 0xFF;
        Conn c = socks5_connect(socks_port, "10.8.0.2", 22, "", "", &rep);
        check("SOCKS5 TUN 网段目标被拒绝", c.fd == INVALID_SOCKET && rep == 0x02);
        c.close_all();
    }
    // 公网目标不受 ACL 影响（本机无外网时连接失败但不应是"被拒绝"码）
    {
        uint8_t rep = 0xFF;
        Conn c = socks5_connect(socks_port, "93.184.216.34", 80, "", "", &rep);
        check("公网目标不被 ACL 拒绝（非 0x02）", rep != 0x02);
        c.close_all();
    }
}

#ifdef PROXY_TEST_TLS
// ---------------------------------------------------------------------------
// 生成自签证书（仅测试用）：返回 true 并输出 PEM 路径
// ---------------------------------------------------------------------------
bool make_self_signed_cert(const std::string& cert_path, const std::string& key_path)
{
    EVP_PKEY* pkey = EVP_PKEY_Q_keygen(nullptr, nullptr, "RSA", 2048);
    if (pkey == nullptr)
        return false;
    X509* x = X509_new();
    if (x == nullptr) {
        EVP_PKEY_free(pkey);
        return false;
    }
    bool ok = true;
    X509_set_version(x, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
    X509_gmtime_adj(X509_getm_notBefore(x), 0);
    X509_gmtime_adj(X509_getm_notAfter(x), 24 * 3600);
    X509_set_pubkey(x, pkey);
    X509_NAME* name = X509_get_subject_name(x);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("localhost"), -1, -1, 0);
    X509_set_issuer_name(x, name);
    // 作为信任锚需要 CA:TRUE（测试里直接信任该证书）
    X509V3_CTX ctx{};
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, x, x, nullptr, nullptr, 0);
    if (X509_EXTENSION* ext =
            X509V3_EXT_conf_nid(nullptr, &ctx, NID_basic_constraints, "critical,CA:TRUE")) {
        X509_add_ext(x, ext, -1);
        X509_EXTENSION_free(ext);
    }
    if (X509_sign(x, pkey, EVP_sha256()) == 0)
        ok = false;
    // 用 BIO 写盘（MSVC 下 OpenSSL 的 FILE* 接口需要 OPENSSL_Applink，
    // BIO_new_file 走自己的 IO，无需额外适配）
    if (ok) {
        BIO* b = BIO_new_file(cert_path.c_str(), "w");
        ok = (b != nullptr) && PEM_write_bio_X509(b, x) == 1;
        if (b != nullptr)
            BIO_free(b);
    }
    if (ok) {
        BIO* b = BIO_new_file(key_path.c_str(), "w");
        ok = (b != nullptr) &&
             PEM_write_bio_PrivateKey(b, pkey, nullptr, nullptr, 0, nullptr, nullptr) == 1;
        if (b != nullptr)
            BIO_free(b);
    }
    X509_free(x);
    EVP_PKEY_free(pkey);
    return ok;
}

// 用例：HTTPS 代理（TLS）
void test_https_proxy(uint16_t tls_port, uint16_t echo_port, const std::string& cert_path)
{
    printf("HTTPS 代理（TLS 加密）用例\n");

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == nullptr || SSL_CTX_load_verify_locations(ctx, cert_path.c_str(), nullptr) != 1) {
        check("测试客户端 SSL_CTX 初始化", false);
        if (ctx != nullptr)
            SSL_CTX_free(ctx);
        return;
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);

    // 1) TLS 握手 + CONNECT + 中继
    {
        Conn c = tcp_connect(tls_port);
        if (c.fd == INVALID_SOCKET) {
            check("连接 TLS 端口", false);
        } else {
            c.ssl = SSL_new(ctx);
            SSL_set_fd(c.ssl, static_cast<int>(c.fd));
            const int hs = SSL_connect(c.ssl);
            check("TLS 握手成功（证书链校验通过）", hs == 1);
            if (hs == 1) {
                int status = 0;
                c = http_proxy_connect(c, "127.0.0.1", echo_port, "", "", &status);
                check("TLS 隧道内 CONNECT 200", status == 200 && c.fd != INVALID_SOCKET);
                if (c.fd != INVALID_SOCKET) {
                    const std::string msg = "tls-encrypted-relay";
                    bool ok = c.send_all(msg.data(), msg.size());
                    std::vector<char> got(msg.size());
                    ok = ok && c.recv_all(got.data(), got.size()) &&
                         memcmp(got.data(), msg.data(), msg.size()) == 0;
                    check("TLS 隧道内双向中继一致（密文承载）", ok);
                }
            }
            c.close_all();
        }
    }

    // 2) 明文打到 TLS 端口必须不成立（证明真的在加密）
    {
        Conn c = tcp_connect(tls_port);
        bool plain_ok = false;
        if (c.fd != INVALID_SOCKET) {
            const std::string req =
                "CONNECT 127.0.0.1:" + std::to_string(echo_port) + " HTTP/1.1\r\n\r\n";
            c.send_all(req.data(), req.size());
            std::string head;
            // 明文不会被当成 HTTP 请求处理：要么无响应，要么不是 200
            plain_ok = c.recv_until_headers(head) && head.find("200") != std::string::npos;
        }
        check("明文 CONNECT 打到 TLS 端口不生效", !plain_ok);
        c.close_all();
    }

    // 3) 无 TLS 时（http 模式）同样端口能明文工作——由 HTTP 用例覆盖，此处只验证 TLS 模式拒绝明文
    SSL_CTX_free(ctx);
}
#endif   // PROXY_TEST_TLS

} // namespace

int main()
{
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        fprintf(stderr, "WSAStartup failed\n");
        return 2;
    }

    EchoServer echo;
    MiniHttpServer web;
    if (!echo.start() || !web.start()) {
        fprintf(stderr, "本地测试服务启动失败\n");
        return 2;
    }

    // ---- SOCKS5：无认证 + 认证两个实例 ----
    Socks5Proxy socks_open;
    Socks5Proxy socks_auth;
    // 功能用例的目标是 127.0.0.1 上的本地回显/HTTP 服务，需放行内网目标；
    // ACL 默认拒绝行为由后面的专门用例验证（11086/11087）
    socks_open.set_allow_private(true);
    socks_auth.set_allow_private(true);
    if (!socks_open.start("127.0.0.1", 11080, "", "", 16) ||
        !socks_auth.start("127.0.0.1", 11081, "alice", "s3cret", 16)) {
        fprintf(stderr, "SOCKS5 代理启动失败\n");
        return 2;
    }
    test_socks5(11080, 11081, echo.port());
    socks_open.stop();
    socks_auth.stop();
    check("SOCKS5 stop() 回收完成", !socks_open.is_running() && !socks_auth.is_running());

    // ---- HTTP CONNECT：无认证 + 认证两个实例 ----
    HttpConnectProxy http_open;
    HttpConnectProxy http_auth;
    {
        HttpConnectProxy::Config c1;
        c1.bind_ip = "127.0.0.1";
        c1.port = 11082;
        c1.use_tls = false;
        c1.allow_private = true;         // 目标为本地回显/HTTP 服务
        HttpConnectProxy::Config c2;
        c2.bind_ip = "127.0.0.1";
        c2.port = 11083;
        c2.use_tls = false;
        c2.user = "alice";
        c2.pass = "s3cret";
        c2.allow_private = true;
        if (!http_open.start(c1) || !http_auth.start(c2)) {
            fprintf(stderr, "HTTP 代理启动失败\n");
            return 2;
        }
    }
    test_http_proxy(11082, 11083, echo.port(), web.port());
    http_open.stop();
    http_auth.stop();
    check("HTTP 代理 stop() 回收完成", !http_open.is_running() && !http_auth.is_running());

#ifdef PROXY_TEST_TLS
    // ---- HTTPS CONNECT（TLS）：自签证书 + 真实握手 ----
    {
        const std::string cert_path = "proxy_test_cert.pem";
        const std::string key_path = "proxy_test_key.pem";
        if (!make_self_signed_cert(cert_path, key_path)) {
            check("生成测试用自签证书", false, "(OpenSSL 不可用?)");
        } else {
            check("生成测试用自签证书", true);
            HttpConnectProxy tls_proxy;
            HttpConnectProxy::Config cfg;
            cfg.bind_ip = "127.0.0.1";
            cfg.port = 11084;
            cfg.use_tls = true;
            cfg.cert_path = cert_path;
            cfg.key_path = key_path;
            cfg.allow_private = true;    // 目标为本地回显服务
            if (!tls_proxy.start(cfg)) {
                check("HTTPS 代理启动（加载证书）", false);
            } else {
                check("HTTPS 代理启动（加载证书）", true);
                test_https_proxy(11084, echo.port(), cert_path);
                tls_proxy.stop();
                check("HTTPS 代理 stop() 回收完成", !tls_proxy.is_running());
            }
            remove(cert_path.c_str());
            remove(key_path.c_str());
        }
    }
    // 证书缺失时启动必须失败（use_tls 且未提供证书）
    {
        HttpConnectProxy bad;
        HttpConnectProxy::Config cfg;
        cfg.bind_ip = "127.0.0.1";
        cfg.port = 11085;
        cfg.use_tls = true;   // 无 cert/key
        check("TLS 模式缺证书 → 拒绝启动", !bad.start(cfg) && !bad.is_running());
    }
#else
    printf("（未定义 PROXY_TEST_TLS：跳过 TLS 用例）\n");
#endif

    // ---- 目标 ACL：默认配置（未调用 set_allow_private / allow_private=false）----
    {
        Socks5Proxy acl_socks;
        HttpConnectProxy acl_http;
        HttpConnectProxy::Config ac;
        ac.bind_ip = "127.0.0.1";
        ac.port = 11087;
        ac.use_tls = false;
        if (!acl_socks.start("127.0.0.1", 11086, "", "", 8) || !acl_http.start(ac)) {
            fprintf(stderr, "ACL 测试代理启动失败\n");
            return 2;
        }
        test_target_acl(11086, 11087, echo.port());
        acl_socks.stop();
        acl_http.stop();
    }

    // ---- 未启用（端口 0）----
    {
        Socks5Proxy off;
        HttpConnectProxy off2;
        HttpConnectProxy::Config c;
        c.port = 0;
        check("port=0 未启用不报错", off.start("127.0.0.1", 0, "", "", 8) &&
                                         off2.start(c) && !off.is_running() && !off2.is_running());
    }

    if (g_fail == 0)
        printf("\n全部用例通过\n");
    else
        printf("\n%d 项失败\n", g_fail);
    WSACleanup();
    return g_fail == 0 ? 0 : 1;
}
