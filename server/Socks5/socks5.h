#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace proxy_common {
class AuthThrottle;   // 认证失败限速器
class ConnLimiter;    // 每来源连接限制（并发 + 新建速率）
class LogLimiter;     // 日志限速
struct TargetAcl;     // 目标 ACL（含本机地址）
}

// ============================================================================
// SOCKS5 代理（浏览器插件专用出口，可选启用）
//
// 定位：给"只在浏览器里用"的客户端（Chrome/Edge MV3 扩展经 chrome.proxy +
// chrome.webRequest.onAuthRequired）提供一个标准 SOCKS5 入口。浏览器把
// HTTP/HTTPS 流量交给本代理，由服务端主机直连目标——只影响该浏览器，
// 不安装系统级 VPN、不改系统路由。
//
// 与主隧道（UDP/TCP + 三阶段认证 + AES-GCM）是两个独立入口：
//   - 主隧道：整机/内核级流量，自有加密协议（安全边界见协议文档）
//   - 本代理：仅浏览器流量；SOCKS5 本身不加密，公网部署务必：
//       a) 启用 RFC1929 用户名/密码认证（本类 user/pass）
//       b) 用防火墙限制来源，或在前置 stunnel/nginx 里做 TLS 终结
//     默认关闭（--socks5-port 0），需要时显式开启。
//
// 实现：每连接一线程（连接数硬上限 256），阻塞 socket + poll 中继，
// 空闲 5 分钟回收；支持 CONNECT + IPv4/IPv6/域名目标。
// ============================================================================
class Socks5Proxy
{
public:
    Socks5Proxy();
    ~Socks5Proxy();

    Socks5Proxy(const Socks5Proxy&) = delete;
    Socks5Proxy& operator=(const Socks5Proxy&) = delete;

    // bind_ip 空/0.0.0.0 = 全部地址；port=0 表示不启用（start 返回 true 但不监听）。
    // user 非空则强制 RFC1929 用户名/密码认证
    bool start(const std::string& bind_ip, uint16_t port,
               const std::string& user, const std::string& pass,
               size_t max_conns = 256);
    void stop();
    bool is_running() const { return m_running.load(); }
    uint16_t port() const { return m_port; }

    // 目标地址 ACL 开关：false（默认）拒绝回环/私网/链路本地/组播等
    // "服务端内网"目标（防止浏览器侧借代理访问服务端与其他客户端内网）；
    // true = 内网自用场景放行（--proxy-allow-private）
    void set_allow_private(bool allow) { m_allow_private = allow; }

    // 显式允许"无认证"监听非回环地址（默认拒绝，防误开开放代理）。
    // 仅在内网/前置 TLS 终结（stunnel）等场景才应开启
    void set_allow_noauth(bool allow) { m_allow_noauth = allow; }

    // 每来源连接限制（并发/速率）：防单来源占满连接槽或高频新建放大 CPU
    void set_conn_limits(size_t max_per_source, size_t rate_per_sec)
    {
        m_max_per_source = (max_per_source > 0) ? max_per_source : 16;
        m_conn_rate_per_sec = (rate_per_sec > 0) ? rate_per_sec : 2;
    }

private:
    // 工作线程登记（启动时记录，accept 循环里顺手回收已结束的线程对象）
    struct Worker
    {
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> done;
    };

    void accept_work();
    void handle_conn(int fd, const std::string& peer_ip, const std::string& peer);
    void join_finished();

    int m_listen_fd = -1;
    uint16_t m_port = 0;
    std::string m_bind_ip = "0.0.0.0";
    std::atomic<bool> m_running{ false };
    std::atomic<size_t> m_conns{ 0 };
    size_t m_max_conns = 256;
    std::string m_user;
    std::string m_pass;
    bool m_allow_private = false;    // 目标 ACL：默认拒绝内网/回环
    bool m_allow_noauth = false;     // 默认拒绝无认证对外监听
    std::unique_ptr<proxy_common::AuthThrottle> m_auth_throttle;   // 认证失败限速
    std::unique_ptr<proxy_common::ConnLimiter> m_conn_limiter;     // 每来源连接限制
    std::unique_ptr<proxy_common::LogLimiter> m_log_limiter;       // 日志限速
    std::unique_ptr<proxy_common::TargetAcl> m_acl;                // 目标 ACL（含本机地址）
    size_t m_max_per_source = 16;
    size_t m_conn_rate_per_sec = 2;
    std::thread m_accept_thread;
    std::mutex m_workers_mutex;
    std::vector<Worker> m_workers;
};
