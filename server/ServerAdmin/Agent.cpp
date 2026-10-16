// ============================================================================
// Agent.cpp —— admin_agent 实现（类声明见 Agent.h）
// ============================================================================
#include "Agent.h"
#include "AdminWire.h"
#include "../Crypt/crypt.h"

#include <algorithm>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>   // std::exception（catch 签名要求显式可见）
#include <string>
#include <thread>
#include <utility>     // std::move
#include <vector>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace {

constexpr int    kHeartbeatSec = 15;          // 心跳周期（计划书 3.5）
constexpr int    kBackoffMinMs = 1000;        // 退避起点
constexpr int    kBackoffMaxMs = 60000;       // 退避封顶
constexpr int    kPollSliceMs  = 500;         // 单次等待上限：便于发心跳/查 running
constexpr size_t kMaxHttpResp  = 1024 * 1024; // 本机 AdminServer 响应上限

std::string to_hex(const uint8_t* d, size_t n)
{
    static const char* h = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s += h[d[i] >> 4]; s += h[d[i] & 0xF]; }
    return s;
}

// hex → bytes；非法返回 false
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

// 非阻塞 connect + poll 等可写，成功返回已恢复阻塞的 fd
int tcp_connect(const std::string& host, uint16_t port, int timeout_ms)
{
    const int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &sa.sin_addr) <= 0) { ::close(fd); return -1; }

    const int flags = ::fcntl(fd, F_GETFL, 0);
    ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    const int rc = ::connect(fd, reinterpret_cast<sockaddr*>(&sa), sizeof(sa));
    if (rc < 0 && errno != EINPROGRESS) { ::close(fd); return -1; }
    if (rc < 0) {
        pollfd p{}; p.fd = fd; p.events = POLLOUT;
        if (::poll(&p, 1, timeout_ms) <= 0) { ::close(fd); return -1; }
        int err = 0; socklen_t el = sizeof(err);
        ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &el);
        if (err != 0) { ::close(fd); return -1; }
    }
    ::fcntl(fd, F_SETFL, flags);   // 恢复阻塞；后续节奏由 poll 控制
    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
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

// 收一帧见 AdminWire.h 的 wire::recv_frame（循环读到凑齐或超时）

// 解析 HTTP 响应（Connection: close 语义：头 + 之后全是 body）
bool parse_http(const std::string& raw, int& status, std::string& body)
{
    const size_t he = raw.find("\r\n\r\n");
    if (he == std::string::npos) return false;
    const size_t le = raw.find("\r\n");
    if (le == std::string::npos || raw.rfind("HTTP/", 0) != 0) return false;
    const size_t sp1 = raw.find(' ', 0);
    if (sp1 == std::string::npos) return false;
    status = std::atoi(raw.c_str() + sp1 + 1);
    body = raw.substr(he + 4);
    return status > 0;
}

// 极简 HTTP 客户端：连本机 AdminServer 发一条短连接请求，读到对端关闭
bool http_call(const std::string& host, uint16_t port, const std::string& token,
               const std::string& method, const std::string& path,
               const std::string& req_body, int& status, std::string& resp_body)
{
    const int fd = tcp_connect(host, port, wire::kTimeoutMs);
    if (fd < 0) return false;
    std::string req;
    req += method + " " + path + " HTTP/1.1\r\n";
    req += "Host: " + host + ":" + std::to_string(port) + "\r\n";
    if (!req_body.empty()) req += "Content-Type: application/json\r\n";
    req += "Content-Length: " + std::to_string(req_body.size()) + "\r\n";
    if (!token.empty()) req += "Authorization: Bearer " + token + "\r\n";
    req += "Connection: close\r\n\r\n";
    req += req_body;
    if (!send_all(fd, req)) { ::close(fd); return false; }

    std::string raw;
    char buf[4096];
    for (;;) {
        const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n > 0) {
            raw.append(buf, size_t(n));
            if (raw.size() > kMaxHttpResp) break;
            continue;
        }
        if (n == 0) break;
        if (errno == EINTR) continue;
        break;
    }
    ::close(fd);
    return parse_http(raw, status, resp_body);
}

// "host:port" → (host, port)
bool parse_hostport(const std::string& s, std::string& host, uint16_t& port)
{
    const size_t c = s.rfind(':');
    if (c == std::string::npos || c == 0 || c + 1 >= s.size()) return false;
    host = s.substr(0, c);
    const long p = std::strtol(s.c_str() + c + 1, nullptr, 10);
    if (p <= 0 || p > 65535) return false;
    port = static_cast<uint16_t>(p);
    return true;
}

Agent* g_agent = nullptr;   // 供信号处理优雅停止
void on_signal(int) { if (g_agent != nullptr) g_agent->stop(); }

void usage(const char* prog)
{
    fprintf(stderr,
        "用法: %s --controller <host:port> [选项]\n"
        "  --controller <host:port>  中转服务器地址（必填，默认 127.0.0.1:19090）\n"
        "  --admin <host:port>       本机 AdminServer 地址（默认 127.0.0.1:18080）\n"
        "  --key <path>              本机 Ed25519 身份私钥（默认 keys/server_sig.key）\n"
        "  --token <str>             访问本机 AdminServer 的 Bearer（默认取 ADMIN_TOKEN 环境变量）\n"
        "  --name <str>              展示名（可选）\n"
        "环境变量: CONTROLLER_HOST/CONTROLLER_PORT/ADMIN_HOST/ADMIN_PORT/KEY_PATH/ADMIN_TOKEN/AGENT_NAME\n",
        prog);
}

}  // namespace

Agent::Agent(Options opt) : opt_(std::move(opt)) {}

Agent::~Agent()
{
    stop();
    if (priv_ != nullptr) {
        EVP_PKEY_free(priv_);
        priv_ = nullptr;
    }
}

std::string Agent::sign_challenge(const std::string& nonce_hex)
{
    std::vector<uint8_t> nonce;
    if (!from_hex(nonce_hex, nonce)) return {};
    try {
        const std::vector<uint8_t> sig = ed25519_sign(priv_, nonce.data(), nonce.size());
        if (sig.size() != 64) return {};
        return to_hex(sig.data(), sig.size());
    } catch (const std::exception& e) {
        fprintf(stderr, "[agent] 签名失败: %s\n", e.what());
        return {};
    }
}

void Agent::run()
{
    running_.store(true);

    // 载入本机身份私钥（= 服务端 server_sig.key，controller 白名单登记的就是它的公钥指纹）
    try {
        priv_ = load_ed25519_private_key(opt_.key_path.c_str());
    } catch (const std::exception& e) {
        fprintf(stderr, "[agent] 载入身份私钥失败 (%s): %s\n", opt_.key_path.c_str(), e.what());
        return;
    }
    unsigned char raw[64];
    size_t raw_len = sizeof(raw);
    if (EVP_PKEY_get_raw_public_key(priv_, raw, &raw_len) != 1) {
        fprintf(stderr, "[agent] 取公钥失败\n");
        return;
    }
    pub_hex_ = to_hex(raw, raw_len);
    fprintf(stderr, "[agent] 本机身份指纹: %s\n", pub_hex_.c_str());

    int backoff = kBackoffMinMs;
    while (running_.load()) {
        if (connect_and_serve()) break;   // 收到 stop()：正常退出
        if (!running_.load()) break;
        const int wait_ms = backoff + (std::rand() % 500);   // 退避 + 抖动
        fprintf(stderr, "[agent] 与 controller 断开，%d ms 后重连\n", wait_ms);
        for (int slept = 0; slept < wait_ms && running_.load(); slept += 200)
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        backoff = (std::min)(backoff * 2, kBackoffMaxMs);
    }
}

bool Agent::connect_and_serve()
{
    const int fd = tcp_connect(opt_.controller_host, opt_.controller_port, wire::kTimeoutMs);
    if (fd < 0) {
        fprintf(stderr, "[agent] 连接 controller %s:%u 失败\n",
                opt_.controller_host.c_str(), unsigned(opt_.controller_port));
        return false;
    }

    wire::Framer fr;
    std::string frame, type;

    // 1) 等 controller 下发的挑战
    if (wire::recv_frame(fd, fr, frame, wire::kTimeoutMs) != 1 ||
        !wire::get_string(frame, "type", type) || type != "challenge") {
        fprintf(stderr, "[agent] 未收到 challenge\n");
        ::close(fd);
        return false;
    }
    std::string nonce;
    if (!wire::get_string(frame, "nonce", nonce)) { ::close(fd); return false; }

    // 2) 签名 + hello（上报公钥指纹，controller 据此比对白名单）
    const std::string sig = sign_challenge(nonce);
    if (sig.empty()) {
        fprintf(stderr, "[agent] 挑战签名失败\n");
        ::close(fd);
        return false;
    }
    if (!wire::send_frame(fd, wire::Json().str("type", "hello")
                                  .str("pubkey_hex", pub_hex_)
                                  .str("sig", sig)
                                  .str("name", opt_.name)
                                  .done())) {
        fprintf(stderr, "[agent] 发送 hello 失败\n");
        ::close(fd);
        return false;
    }

    // 3) 等准入结果
    const int wr = wire::recv_frame(fd, fr, frame, wire::kTimeoutMs);
    if (wr != 1) {
        fprintf(stderr, "[agent] 等待准入结果%s\n", wr == 0 ? "超时" : "时连接断开");
        ::close(fd);
        return false;
    }
    if (!wire::get_string(frame, "type", type)) {
        fprintf(stderr, "[agent] 准入结果帧格式不对\n");
        ::close(fd);
        return false;
    }
    if (type != "welcome") {
        std::string reason;
        wire::get_string(frame, "reason", reason);
        fprintf(stderr, "[agent] 准入被拒: %s\n", reason.c_str());
        ::close(fd);
        return false;   // 白名单可能还没登记：退避后重试
    }
    fprintf(stderr, "[agent] 已接入 controller\n");

    // 4) 心跳 + 命令循环
    auto last_hb = std::chrono::steady_clock::now();
    while (running_.load()) {
        const int r = wire::recv_frame(fd, fr, frame, kPollSliceMs);
        if (r < 0) { ::close(fd); return false; }
        if (r == 1) {
            std::string t;
            wire::get_string(frame, "type", t);
            if (t == "command") {
                std::string method, path, body;
                long long id = 0;
                wire::get_string(frame, "method", method);
                wire::get_string(frame, "path", path);
                wire::get_string(frame, "body", body);
                wire::get_int(frame, "id", id);

                // 转发给本机 AdminServer（业务执行层）——"HTTP 语义原样过隧道"
                int status = 0;
                std::string resp;
                if (!http_call(opt_.admin_host, opt_.admin_port, opt_.admin_token,
                               method, path, body, status, resp)) {
                    status = 502;
                    resp = "{\"error\":\"local admin server unreachable\"}";
                }
                if (!wire::send_frame(fd, wire::Json().str("type", "reply")
                                              .num("id", id)
                                              .num("status", status)
                                              .str("body", resp)
                                              .done())) {
                    ::close(fd);
                    return false;
                }
            }
            // 其他类型（heartbeat 等）忽略
        }
        const auto now = std::chrono::steady_clock::now();
        if (now - last_hb >= std::chrono::seconds(kHeartbeatSec)) {
            if (!wire::send_frame(fd, wire::Json().str("type", "heartbeat").done())) {
                ::close(fd);
                return false;
            }
            last_hb = now;
        }
    }
    ::close(fd);
    return true;   // stop() 打断
}

int main(int argc, char* argv[])
{
    Agent::Options opt;
    if (const char* e = std::getenv("CONTROLLER_HOST")) opt.controller_host = e;
    if (const char* e = std::getenv("CONTROLLER_PORT")) opt.controller_port = uint16_t(std::atoi(e));
    if (const char* e = std::getenv("ADMIN_HOST"))      opt.admin_host = e;
    if (const char* e = std::getenv("ADMIN_PORT"))      opt.admin_port = uint16_t(std::atoi(e));
    if (const char* e = std::getenv("KEY_PATH"))        opt.key_path = e;
    if (const char* e = std::getenv("ADMIN_TOKEN"))     opt.admin_token = e;
    if (const char* e = std::getenv("AGENT_NAME"))      opt.name = e;

    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&](const char* what) -> const char* {
            if (i + 1 >= argc) { fprintf(stderr, "缺少参数: %s %s\n", a.c_str(), what); return nullptr; }
            return argv[++i];
        };
        if (a == "--controller") {
            const char* v = next("host:port");
            if (v == nullptr || !parse_hostport(v, opt.controller_host, opt.controller_port)) {
                fprintf(stderr, "--controller 需要 host:port\n");
                return 1;
            }
        } else if (a == "--admin") {
            const char* v = next("host:port");
            if (v == nullptr || !parse_hostport(v, opt.admin_host, opt.admin_port)) {
                fprintf(stderr, "--admin 需要 host:port\n");
                return 1;
            }
        } else if (a == "--key") {
            const char* v = next("路径"); if (v == nullptr) return 1; opt.key_path = v;
        } else if (a == "--token") {
            const char* v = next("令牌"); if (v == nullptr) return 1; opt.admin_token = v;
        } else if (a == "--name") {
            const char* v = next("名称"); if (v == nullptr) return 1; opt.name = v;
        } else if (a == "-h" || a == "--help") {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "未知参数: %s\n", a.c_str());
            usage(argv[0]);
            return 1;
        }
    }

    fprintf(stderr, "[agent] controller=%s:%u admin=%s:%u key=%s\n",
            opt.controller_host.c_str(), unsigned(opt.controller_port),
            opt.admin_host.c_str(), unsigned(opt.admin_port), opt.key_path.c_str());

    Agent agent(std::move(opt));
    g_agent = &agent;
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    agent.run();
    g_agent = nullptr;
    return 0;
}
