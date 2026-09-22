#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

struct ssl_ctx_st;   // OpenSSL SSL_CTX 前置声明（头文件不引入 OpenSSL 类型）

// ============================================================================
// HTTP CONNECT 代理（浏览器插件专用出口；可选 TLS 承载）
//
// 为什么需要它：MV3 扩展只能通过 chrome.proxy 使用 http/https/socks4/socks5
// 四种代理。**只有 https 方案会做 TLS**——所以"浏览器插件加密"的正解是：
//   扩展 → HTTPS 代理（TLS + HTTP CONNECT）→ 服务端直连目标
// 实测 chrome.proxy 的固定代理/https 方案即浏览器↔代理全程 TLS，证书由
// 系统信任链校验（自签证书需把 CA 导入系统/浏览器信任存储）。
//
// 两种运行方式（同一份代码）：
//   - use_tls=true ：--https-proxy-port，TLS 承载（加密，推荐公网）
//   - use_tls=false：--http-proxy-port，明文 HTTP CONNECT（仅在内网、
//     或前置 stunnel/SSH 隧道时使用）
//
// 协议支持：
//   - CONNECT host:port          （HTTPS 站点隧道，主力路径）
//   - 绝对形式 GET/POST http://…  （明文 HTTP 站点：改写为 origin-form 转发）
//   - 可选 Basic 认证（Proxy-Authorization），失败回 407 + Proxy-Authenticate
//
// 实现：每连接一线程（上限 256），阻塞 socket + poll 中继，空闲 5 分钟回收。
// ============================================================================
class HttpConnectProxy
{
public:
    struct Config
    {
        std::string bind_ip = "0.0.0.0";
        uint16_t port = 0;              // 0 = 不启用
        bool use_tls = true;            // true = HTTPS 代理（TLS 承载）
        std::string cert_path;          // TLS 证书链（PEM）
        std::string key_path;           // TLS 私钥（PEM）
        std::string user;               // 非空则要求 Basic 认证
        std::string pass;
        size_t max_conns = 256;
        // 目标地址 ACL：false（默认）拒绝回环/私网/链路本地/组播等"服务端内网"
        // 目标（防止浏览器侧借代理访问服务端与其他客户端内网）；
        // true = 内网自用场景放行（--proxy-allow-private）
        bool allow_private = false;
    };

    HttpConnectProxy() = default;
    ~HttpConnectProxy();

    HttpConnectProxy(const HttpConnectProxy&) = delete;
    HttpConnectProxy& operator=(const HttpConnectProxy&) = delete;

    bool start(const Config& cfg);
    void stop();
    bool is_running() const { return m_running.load(); }
    uint16_t port() const { return m_cfg.port; }

private:
    struct Worker
    {
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> done;
    };

    void accept_work();
    void handle_conn(int fd, const std::string& peer);
    void join_finished();

    Config m_cfg;
    int m_listen_fd = -1;
    ssl_ctx_st* m_ssl_ctx = nullptr;
    std::string m_expected_auth;      // "Basic base64(user:pass)"（启动时算好）
    std::atomic<bool> m_running{ false };
    std::atomic<size_t> m_conns{ 0 };
    std::thread m_accept_thread;
    std::mutex m_workers_mutex;
    std::vector<Worker> m_workers;
};
