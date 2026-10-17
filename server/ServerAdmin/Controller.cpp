// ============================================================================
// Controller.cpp —— vpn_controller（中转）实现（类声明见 Controller.h）
// 只做「VPN 服务器 ↔ 中转服务器」的业务接口：agent 通道 + 命令转发。
// ============================================================================
#include "Controller.h"
#include "AdminWire.h"
#include "../Crypt/crypt.h"

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <openssl/crypto.h>   // CRYPTO_memcmp
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>         // umask
#include <unistd.h>

namespace {

constexpr size_t kMaxHttpReq   = 8192;     // 管理请求上限（与 AdminServer 一致）
constexpr int    kForwardMs    = 10000;    // 转发等待 agent 回传的上限
constexpr int    kHeartbeatGap = 45000;    // 45s 没动静（3×15s 心跳）判 agent 失联
constexpr int    kPollSliceMs  = 500;

long long now_ms()
{
    return static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

std::string to_hex(const uint8_t* d, size_t n)
{
    static const char* h = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s += h[d[i] >> 4]; s += h[d[i] & 0xF]; }
    return s;
}

bool from_hex(const std::string& s, std::vector<uint8_t>& out)
{
    if (s.size() % 2 != 0) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    out.clear();
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        const int hi = nib(s[i]), lo = nib(s[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back(uint8_t((hi << 4) | lo));
    }
    return true;
}

int listen_tcp(const std::string& bind, uint16_t port, int backlog)
{
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int one = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (bind.empty() || bind == "0.0.0.0") {
        sa.sin_addr.s_addr = INADDR_ANY;
    } else if (::inet_pton(AF_INET, bind.c_str(), &sa.sin_addr) <= 0) {
        ::close(fd);
        return -1;
    }
    if (::bind(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) < 0) { ::close(fd); return -1; }
    if (::listen(fd, backlog) < 0) { ::close(fd); return -1; }
    return fd;
}

bool send_all(int fd, const std::string& data)
{
    size_t off = 0;
    while (off < data.size()) {
        const ssize_t n = ::send(fd, data.data() + off, data.size() - off, MSG_NOSIGNAL);
        if (n > 0) { off += size_t(n); continue; }
        if (n < 0 && errno == EINTR) continue;
        return false;
    }
    return true;
}

// 收一帧见 AdminWire.h 的 wire::Conn::recv_frame（循环读到凑齐或超时）

const char* reason_phrase(int status)
{
    switch (status) {
        case 200: return "OK";
        case 400: return "Bad Request";
        case 401: return "Unauthorized";
        case 404: return "Not Found";
        case 405: return "Method Not Allowed";
        case 413: return "Payload Too Large";
        case 503: return "Service Unavailable";
        case 504: return "Gateway Timeout";
        default:  return "Unknown";
    }
}

std::string make_http_response(int status, const std::string& body)
{
    std::string r;
    r.reserve(body.size() + 160);
    r += "HTTP/1.1 " + std::to_string(status) + " " + reason_phrase(status) + "\r\n";
    r += "Content-Type: application/json\r\n";
    r += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    r += "Connection: close\r\n\r\n";
    r += body;
    return r;
}

// 从已收齐的请求头块（raw[0..he) 为头，he = "\r\n\r\n" 的位置）里取 Content-Length。
// 缺省/非法按 0 处理。存在的意义：body 可能落在后续 TCP 段里，必须知道还要读多少。
size_t header_content_length(const std::string& raw, size_t he)
{
    long long cl = 0;
    size_t pos = raw.find("\r\n");
    if (pos == std::string::npos) return 0;
    pos += 2;
    while (pos < he) {
        const size_t eol = raw.find("\r\n", pos);
        if (eol == std::string::npos || eol > he) break;
        const std::string h = raw.substr(pos, eol - pos);
        const size_t c = h.find(':');
        if (c != std::string::npos) {
            std::string k = h.substr(0, c);
            for (char& ch : k) if (ch >= 'A' && ch <= 'Z') ch = char(ch + 32);
            if (k == "content-length") cl = std::atoll(h.c_str() + c + 1);
        }
        pos = eol + 2;
    }
    return cl > 0 ? static_cast<size_t>(cl) : 0;
}

Controller* g_ctl = nullptr;         // 供信号处理
void on_signal(int) { if (g_ctl != nullptr) g_ctl->stop(); }

void usage(const char* prog)
{
    fprintf(stderr,
        "用法: %s [选项]\n"
        "  --agent-bind <ip>     agent 通道监听地址（默认 0.0.0.0）\n"
        "  --agent-port <n>      agent 通道端口（默认 19090）\n"
        "  --http-bind <ip>      最小 HTTP 入口地址（默认 127.0.0.1）\n"
        "  --http-port <n>       HTTP 入口端口（默认 18081）\n"
        "  --admin-token <str>   HTTP 入口 Bearer（默认取 ADMIN_TOKEN 环境变量；空=不鉴权）\n"
        "  --agents <file>       agent 公钥指纹白名单文件（默认 agents.txt，每行一个 hex）\n"
        "  --tls-cert <file>     agent 通道 TLS 证书链，如 fullchain.pem（与 --tls-key 成对）\n"
        "  --tls-key <file>      agent 通道 TLS 私钥，如 privkey.pem（0600）\n"
        "  --add-agent <hex>     把某指纹追加进白名单后退出\n",
        prog);
}

}  // namespace

Controller::Controller(Options opt) : opt_(std::move(opt)) {}

Controller::~Controller()
{
    stop();
    if (agent_thread_.joinable()) agent_thread_.join();
    if (agent_fd_ >= 0) { ::close(agent_fd_); agent_fd_ = -1; }
    if (http_fd_ >= 0) { ::close(http_fd_); http_fd_ = -1; }
    if (tls_ctx_ != nullptr) { SSL_CTX_free(tls_ctx_); tls_ctx_ = nullptr; }
}

bool Controller::start()
{
    // 读白名单（不存在 = 空表：任何 agent 都会被拒，直到 --add-agent 登记）
    std::ifstream fin(opt_.agents_file);
    std::string line;
    while (std::getline(fin, line)) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
        if (!line.empty()) whitelist_.push_back(line);
    }

    // TLS 是 agent 通道的传输层保护；证书/私钥必须成对出现。
    if (!opt_.tls_cert.empty() || !opt_.tls_key.empty()) {
        if (opt_.tls_cert.empty() || opt_.tls_key.empty()) {
            fprintf(stderr, "[controller] TLS_CERT 与 TLS_KEY 必须同时设置\n");
            return false;
        }
        std::string err;
        tls_ctx_ = wire::make_server_ctx(opt_.tls_cert, opt_.tls_key, err);
        if (tls_ctx_ == nullptr) {
            fprintf(stderr, "[controller] TLS 初始化失败: %s\n", err.c_str());
            return false;
        }
    } else if (opt_.agent_bind != "127.0.0.1" && opt_.agent_bind != "::1") {
        fprintf(stderr,
                "[controller] 警告: agent 通道是明文 TCP。生产环境请配置 "
                "--tls-cert/--tls-key（或 TLS_CERT/TLS_KEY）\n");
    }

    agent_fd_ = listen_tcp(opt_.agent_bind, opt_.agent_port, 16);
    if (agent_fd_ < 0) {
        fprintf(stderr, "[controller] agent 通道监听 %s:%u 失败: %s\n",
                opt_.agent_bind.c_str(), unsigned(opt_.agent_port), strerror(errno));
        return false;
    }
    http_fd_ = listen_tcp(opt_.http_bind, opt_.http_port, 16);
    if (http_fd_ < 0) {
        fprintf(stderr, "[controller] HTTP 入口监听 %s:%u 失败: %s\n",
                opt_.http_bind.c_str(), unsigned(opt_.http_port), strerror(errno));
        return false;
    }

    running_.store(true);
    agent_thread_ = std::thread([this] { agent_loop(); });
    fprintf(stderr, "[controller] agent 通道 %s:%u（%s），HTTP 入口 %s:%u，白名单 %zu 条\n",
            opt_.agent_bind.c_str(), unsigned(opt_.agent_port),
            tls_ctx_ != nullptr ? "TLS" : "明文 TCP",
            opt_.http_bind.c_str(), unsigned(opt_.http_port), whitelist_.size());
    return true;
}

void Controller::stop()
{
    running_.store(false);
}

void Controller::run()
{
    http_loop();   // 阻塞：HTTP 入口跑在调用线程
}

bool Controller::in_whitelist(const std::string& pubkey_hex) const
{
    return std::find(whitelist_.begin(), whitelist_.end(), pubkey_hex) != whitelist_.end();
}

std::shared_ptr<Controller::Agent> Controller::find_agent(const std::string& id) const
{
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = agents_.find(id);
    return it == agents_.end() ? nullptr : it->second;
}

// ============================ agent 通道 ============================
void Controller::agent_loop()
{
    while (running_.load()) {
        // 先 poll 监听 fd（500ms 节拍，便于检查 running_）
        pollfd lp{}; lp.fd = agent_fd_; lp.events = POLLIN;
        if (::poll(&lp, 1, kPollSliceMs) <= 0) continue;
        if (!(lp.revents & POLLIN)) continue;

        sockaddr_in clt{};
        socklen_t cl = sizeof(clt);
        const int cfd = ::accept(agent_fd_, reinterpret_cast<sockaddr*>(&clt), &cl);
        if (cfd < 0) continue;
        char ipbuf[INET_ADDRSTRLEN]{};
        ::inet_ntop(AF_INET, &clt.sin_addr, ipbuf, sizeof(ipbuf));
        const std::string ip = ipbuf;

        wire::Conn conn;
        conn.adopt_fd(cfd);
        if (tls_ctx_ != nullptr) {
            std::string terr;
            if (!conn.enable_tls_server(tls_ctx_, wire::kTimeoutMs, terr)) {
                fprintf(stderr, "[controller] agent %s TLS 握手失败: %s\n",
                        ip.c_str(), terr.c_str());
                continue;   // conn 析构时关闭 fd
            }
        }

        // ---- 握手（管理连接很少，短暂占用本线程可接受）----
        const std::vector<uint8_t> nonce = generate_nonce(16);
        const std::string nonce_hex = to_hex(nonce.data(), nonce.size());
        if (!conn.send_frame(wire::Json().str("type", "challenge")
                                        .str("nonce", nonce_hex).done())) {
            continue;
        }
        wire::Framer fr;
        std::string frame, type, pub_hex, sig_hex, name;
        if (conn.recv_frame(fr, frame, wire::kTimeoutMs) != 1 ||
            !wire::get_string(frame, "type", type) || type != "hello" ||
            !wire::get_string(frame, "pubkey_hex", pub_hex) ||
            !wire::get_string(frame, "sig", sig_hex)) {
            continue;
        }
        wire::get_string(frame, "name", name);

        std::vector<uint8_t> pub, sig;
        bool ok = from_hex(pub_hex, pub) && pub.size() == 32 &&
                  from_hex(sig_hex, sig) && sig.size() == 64;
        if (ok) {
            EVP_PKEY* pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
                                                       pub.data(), pub.size());
            ok = false;
            if (pk != nullptr) {
                try { ok = ed25519_verify(pk, nonce.data(), nonce.size(), sig.data(), sig.size()); }
                catch (...) { ok = false; }
                EVP_PKEY_free(pk);
            }
        }
        if (!ok) {
            conn.send_frame(wire::Json().str("type", "reject")
                                     .str("reason", "signature verify failed").done());
            fprintf(stderr, "[controller] agent %s 签名校验失败，拒绝\n", ip.c_str());
            continue;
        }
        if (!in_whitelist(pub_hex)) {
            conn.send_frame(wire::Json().str("type", "reject")
                                     .str("reason", "pubkey not in whitelist").done());
            fprintf(stderr, "[controller] agent %s 指纹未登记，拒绝: %s\n", ip.c_str(), pub_hex.c_str());
            continue;
        }

        auto ag = std::make_shared<Agent>();
        ag->pubkey_hex = pub_hex;
        ag->id = name.empty() ? pub_hex.substr(0, 8) : name;
        ag->ip = ip;
        ag->connected_at = now_ms();
        ag->last_seen = ag->connected_at;
        if (!conn.send_frame(wire::Json().str("type", "welcome").str("id", ag->id).done())) {
            continue;
        }
        ag->conn = std::move(conn);
        ag->fr = std::move(fr);
        {
            std::lock_guard<std::mutex> lk(mtx_);
            agents_[ag->id] = ag;   // 同 id 重连：覆盖旧连接（旧的会在下面因断开被摘除）
        }
        fprintf(stderr, "[controller] agent 接入: id=%s ip=%s 指纹=%s\n",
                ag->id.c_str(), ip.c_str(), pub_hex.substr(0, 16).c_str());

        // ---- 长连接：收心跳 / 命令回执，直到断开或心跳超时 ----
        while (running_.load()) {
            const int r = ag->conn.recv_frame(ag->fr, frame, kPollSliceMs);
            if (r < 0) break;
            if (r == 0) {
                if (now_ms() - ag->last_seen > kHeartbeatGap) {
                    fprintf(stderr, "[controller] agent %s 心跳超时，断开\n", ag->id.c_str());
                    break;
                }
                continue;
            }
            ag->last_seen = now_ms();
            std::string t;
            wire::get_string(frame, "type", t);
            if (t == "reply") {
                long long id = 0, st = 0;
                std::string body;
                wire::get_int(frame, "id", id);
                wire::get_int(frame, "status", st);
                wire::get_string(frame, "body", body);
                std::lock_guard<std::mutex> lk(ag->pmtx);
                if (id == ag->pending_id) {
                    ag->pending_status = static_cast<int>(st);
                    ag->pending_body = body;
                    ag->pending_done = true;
                    ag->pcv.notify_all();
                }
            }
            // heartbeat：只刷新 last_seen，无需处理
        }
        {
            std::lock_guard<std::mutex> lk(mtx_);
            auto it = agents_.find(ag->id);
            if (it != agents_.end() && it->second == ag) agents_.erase(it);
        }
        fprintf(stderr, "[controller] agent 断开: id=%s ip=%s\n", ag->id.c_str(), ip.c_str());
    }
}

// ============================ 业务转发 ============================
bool Controller::forward(const std::string& server_id, const std::string& method,
                         const std::string& path, const std::string& body,
                         int& status, std::string& resp_body, std::string& err)
{
    const std::shared_ptr<Agent> ag = find_agent(server_id);
    if (!ag) { err = "agent offline"; return false; }

    static std::atomic<long long> seq{ 0 };
    const long long rid = ++seq;
    {
        std::lock_guard<std::mutex> lk(ag->pmtx);
        ag->pending_id = rid;
        ag->pending_done = false;
    }
    const std::string cmd = wire::Json().str("type", "command").num("id", rid)
                                     .str("method", method).str("path", path)
                                     .str("body", body).done();
    {
        std::lock_guard<std::mutex> lk(ag->wmtx);   // 命令帧不能交错
        if (!ag->conn.send_frame(cmd)) { err = "agent send failed"; return false; }
    }

    std::unique_lock<std::mutex> lk(ag->pmtx);
    if (!ag->pcv.wait_for(lk, std::chrono::milliseconds(kForwardMs),
                          [&] { return ag->pending_done && ag->pending_id == rid; })) {
        err = "agent timeout";
        return false;
    }
    status = ag->pending_status;
    resp_body = ag->pending_body;
    return true;
}

// ============================ 最小 HTTP 入口 ============================
bool Controller::check_auth(const HttpReq& req) const
{
    if (opt_.admin_token.empty()) return true;   // 未设令牌 = 不鉴权（仅限环本机调试）
    auto it = req.headers.find("authorization");
    if (it == req.headers.end()) return false;
    if (it->second.rfind("Bearer ", 0) != 0) return false;
    const std::string given = it->second.substr(7);
    if (given.size() != opt_.admin_token.size()) return false;
    return CRYPTO_memcmp(given.data(), opt_.admin_token.data(), opt_.admin_token.size()) == 0;
}

void Controller::http_loop()
{
    while (running_.load()) {
        pollfd p{}; p.fd = http_fd_; p.events = POLLIN;
        if (::poll(&p, 1, kPollSliceMs) <= 0) continue;
        if (!(p.revents & POLLIN)) continue;

        sockaddr_in clt{};
        socklen_t cl = sizeof(clt);
        const int cfd = ::accept(http_fd_, reinterpret_cast<sockaddr*>(&clt), &cl);
        if (cfd < 0) continue;

        // 读全一条请求：先读到头部结束（\r\n\r\n），再按 Content-Length 把 body 读满。
        // 不能一见到 \r\n\r\n 就收手——body 完全可能落在后续 TCP 段里
        // （POST /api/servers/{id}/tokens 的 {"count":N} 正是靠它）。
        std::string raw;
        char buf[4096];
        size_t he = std::string::npos;
        size_t need = 0;                 // 头 + body 的完整长度（算出前为 0）
        bool too_large = false;
        for (;;) {
            if (he == std::string::npos) {
                he = raw.find("\r\n\r\n");
                if (he != std::string::npos) {
                    need = he + 4 + header_content_length(raw, he);
                    if (need > kMaxHttpReq) { too_large = true; break; }
                }
            }
            if (he != std::string::npos && raw.size() >= need) break;   // 整条收齐
            if (raw.size() >= kMaxHttpReq) break;                       // 头都没读完就超限
            const ssize_t n = ::recv(cfd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            raw.append(buf, size_t(n));
        }
        if (too_large) {
            send_all(cfd, make_http_response(413, "{\"error\":\"request too large\"}"));
            ::close(cfd);
            continue;
        }
        if (he == std::string::npos) {
            send_all(cfd, make_http_response(400, "{\"error\":\"bad request\"}"));
            ::close(cfd);
            continue;
        }
        handle_http(cfd, raw, "");
        ::close(cfd);
    }
}

void Controller::handle_http(int fd, const std::string& raw, const std::string& /*ip*/)
{
    HttpReq req;
    const size_t he = raw.find("\r\n\r\n");
    const size_t le = raw.find("\r\n");
    if (he == std::string::npos || le == std::string::npos) {
        send_all(fd, make_http_response(400, "{\"error\":\"bad request\"}"));
        return;
    }
    const std::string line1 = raw.substr(0, le);
    const size_t sp1 = line1.find(' ');
    const size_t sp2 = (sp1 == std::string::npos) ? std::string::npos : line1.find(' ', sp1 + 1);
    if (sp1 == std::string::npos || sp2 == std::string::npos) {
        send_all(fd, make_http_response(400, "{\"error\":\"bad request\"}"));
        return;
    }
    req.method = line1.substr(0, sp1);
    req.path = line1.substr(sp1 + 1, sp2 - sp1 - 1);

    size_t pos = le + 2;
    while (pos < he) {
        const size_t eol = raw.find("\r\n", pos);
        if (eol == std::string::npos) break;
        const std::string h = raw.substr(pos, eol - pos);
        const size_t c = h.find(':');
        if (c != std::string::npos && c > 0) {
            std::string k = h.substr(0, c);
            for (char& ch : k) if (ch >= 'A' && ch <= 'Z') ch = char(ch + 32);
            size_t v = c + 1;
            while (v < h.size() && h[v] == ' ') ++v;
            req.headers[k] = h.substr(v);
        }
        pos = eol + 2;
    }
    long long cl = 0;
    if (auto it = req.headers.find("content-length"); it != req.headers.end())
        cl = std::atoll(it->second.c_str());
    if (cl < 0 || static_cast<size_t>(cl) > kMaxHttpReq) {
        send_all(fd, make_http_response(413, "{\"error\":\"request too large\"}"));
        return;
    }
    if (raw.size() >= he + 4) req.body = raw.substr(he + 4, static_cast<size_t>(cl));

    if (!check_auth(req)) {
        send_all(fd, make_http_response(401, "{\"error\":\"unauthorized\"}"));
        return;
    }

    // GET /api/servers —— 已接入 agent 列表
    if (req.method == "GET" && req.path == "/api/servers") {
        std::string body = "{\"servers\":[";
        {
            std::lock_guard<std::mutex> lk(mtx_);
            bool first = true;
            for (const auto& kv : agents_) {
                if (!first) body += ",";
                first = false;
                body += wire::Json().str("id", kv.second->id)
                                    .str("pubkey_hex", kv.second->pubkey_hex)
                                    .str("ip", kv.second->ip)
                                    .num("last_seen", kv.second->last_seen).done();
            }
        }
        send_all(fd, make_http_response(200, body + "]}"));
        return;
    }

    // /api/servers/{id}/info|tokens[/{token}] —— 转发到指定 agent
    static const std::string kPre = "/api/servers/";
    if (req.path.rfind(kPre, 0) == 0) {
        const std::string rest = req.path.substr(kPre.size());
        const size_t slash = rest.find('/');
        if (slash == std::string::npos) {
            send_all(fd, make_http_response(404, "{\"error\":\"not found\"}"));
            return;
        }
        const std::string id = rest.substr(0, slash);
        const std::string sub = rest.substr(slash);

        std::string fwd;
        if (sub == "/info")        fwd = "/api/info";
        else if (sub == "/tokens") fwd = "/api/tokens";
        else if (sub.rfind("/tokens/", 0) == 0) fwd = "/api/tokens/" + sub.substr(8);
        else {
            send_all(fd, make_http_response(404, "{\"error\":\"not found\"}"));
            return;
        }

        int status = 0;
        std::string body, err;
        if (!forward(id, req.method, fwd, req.body, status, body, err)) {
            const int code = (err.find("offline") != std::string::npos) ? 503 : 504;
            send_all(fd, make_http_response(code, "{\"error\":\"" + wire::escape(err) + "\"}"));
            return;
        }
        send_all(fd, make_http_response(status, body));
        return;
    }

    send_all(fd, make_http_response(404, "{\"error\":\"not found\"}"));
}

// ============================ 入口 ============================
int main(int argc, char* argv[])
{
    ::umask(077);
    Controller::Options opt;
    if (const char* e = std::getenv("AGENT_BIND"))   opt.agent_bind = e;
    if (const char* e = std::getenv("AGENT_PORT"))   opt.agent_port = uint16_t(std::atoi(e));
    if (const char* e = std::getenv("HTTP_BIND"))    opt.http_bind = e;
    if (const char* e = std::getenv("HTTP_PORT"))    opt.http_port = uint16_t(std::atoi(e));
    if (const char* e = std::getenv("ADMIN_TOKEN"))  opt.admin_token = e;
    if (const char* e = std::getenv("AGENTS_FILE"))  opt.agents_file = e;
    if (const char* e = std::getenv("TLS_CERT"))     opt.tls_cert = e;
    if (const char* e = std::getenv("TLS_KEY"))      opt.tls_key = e;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&](const char* what) -> const char* {
            if (i + 1 >= argc) { fprintf(stderr, "缺少参数: %s %s\n", a.c_str(), what); return nullptr; }
            return argv[++i];
        };
        if (a == "--agent-bind") { const char* v = next("ip"); if (!v) return 1; opt.agent_bind = v; }
        else if (a == "--agent-port") { const char* v = next("n"); if (!v) return 1; opt.agent_port = uint16_t(std::atoi(v)); }
        else if (a == "--http-bind") { const char* v = next("ip"); if (!v) return 1; opt.http_bind = v; }
        else if (a == "--http-port") { const char* v = next("n"); if (!v) return 1; opt.http_port = uint16_t(std::atoi(v)); }
        else if (a == "--admin-token") { const char* v = next("str"); if (!v) return 1; opt.admin_token = v; }
        else if (a == "--agents") { const char* v = next("file"); if (!v) return 1; opt.agents_file = v; }
        else if (a == "--tls-cert") { const char* v = next("file"); if (!v) return 1; opt.tls_cert = v; }
        else if (a == "--tls-key") { const char* v = next("file"); if (!v) return 1; opt.tls_key = v; }
        else if (a == "--add-agent") {
            const char* v = next("hex");
            if (v == nullptr) return 1;
            std::ofstream out(opt.agents_file, std::ios::app);
            if (!out) { fprintf(stderr, "无法写入 %s\n", opt.agents_file.c_str()); return 1; }
            out << v << "\n";
            printf("已登记 agent 指纹到 %s: %s\n", opt.agents_file.c_str(), v);
            return 0;
        } else if (a == "-h" || a == "--help") {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "未知参数: %s\n", a.c_str());
            usage(argv[0]);
            return 1;
        }
    }

    Controller ctl(std::move(opt));
    if (!ctl.start()) return 1;
    g_ctl = &ctl;
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    ctl.run();
    g_ctl = nullptr;
    printf("[controller] 已退出\n");
    return 0;
}
