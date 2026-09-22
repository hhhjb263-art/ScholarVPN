#include "socks5.h"

#include "../Proxy/proxy_common.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <system_error>

namespace {

using proxy_common::constant_time_eq;
using proxy_common::read_full;
using proxy_common::sanitize_for_log;
using proxy_common::write_full;

// SOCKS5 常量（RFC 1928 / RFC 1929）
constexpr uint8_t kVer5 = 0x05;
constexpr uint8_t kAuthNone = 0x00;
constexpr uint8_t kAuthUserPass = 0x02;
constexpr uint8_t kAuthNoAcceptable = 0xFF;
constexpr uint8_t kCmdConnect = 0x01;
constexpr uint8_t kAtypIpv4 = 0x01;
constexpr uint8_t kAtypDomain = 0x03;
constexpr uint8_t kAtypIpv6 = 0x04;

// 应答码
constexpr uint8_t kRepSuccess = 0x00;
constexpr uint8_t kRepGeneralFail = 0x01;
constexpr uint8_t kRepNotAllowed = 0x02;
constexpr uint8_t kRepHostUnreach = 0x04;
constexpr uint8_t kRepConnRefused = 0x05;
constexpr uint8_t kRepCmdNotSupported = 0x07;
constexpr uint8_t kRepAtypNotSupported = 0x08;

constexpr int kHandshakeTimeoutMs = 15'000;   // 握手阶段单步超时
constexpr int kConnectTimeoutMs = 10'000;     // 连接目标超时
constexpr int kIdleTimeoutMs = 300'000;       // 转发空闲上限（5 分钟无数据即回收）
constexpr int kSendTimeoutSec = 30;           // 阻塞写上限（对端不收即断）

uint8_t rep_from_errno(int e)
{
    switch (e) {
    case ECONNREFUSED:  return kRepConnRefused;
    case ENETUNREACH:
    case EHOSTUNREACH:  return kRepHostUnreach;
    case EACCES:
    case EPERM:         return kRepNotAllowed;
    case ETIMEDOUT:     return kRepHostUnreach;
    default:            return kRepGeneralFail;
    }
}

} // namespace

Socks5Proxy::Socks5Proxy()
    : m_auth_throttle(new proxy_common::AuthThrottle()),
      m_log_limiter(new proxy_common::LogLimiter())
{
}

Socks5Proxy::~Socks5Proxy()
{
    stop();
}

bool Socks5Proxy::start(const std::string& bind_ip, uint16_t port,
                        const std::string& user, const std::string& pass,
                        size_t max_conns)
{
    if (m_running.load())
        return false;
    if (port == 0) {
        fprintf(stderr, "[SOCKS5] 未启用（--socks5-port 0）\n");
        return true;                    // 未启用视为成功
    }
    m_bind_ip = bind_ip.empty() ? "0.0.0.0" : bind_ip;
    m_port = port;
    m_user = user;
    m_pass = pass;
    m_max_conns = (max_conns > 0) ? max_conns : 256;

    // ---- 认证安全校验（防开放代理）----
    // 1) 配置了用户名却没给密码：等价于"空密码"，等于没有认证 → 拒绝
    if (!m_user.empty() && m_pass.empty()) {
        fprintf(stderr, "[SOCKS5] 拒绝启动：设置了 --proxy-user 但密码为空"
                        "（空密码等于无认证，请设置 --proxy-pass 或用 --proxy-pass-file）\n");
        return false;
    }
    // 2) 无认证 + 非回环监听：默认拒绝，避免把开放代理挂到公网
    const bool loopback = (m_bind_ip == "127.0.0.1" || m_bind_ip == "::1" ||
                           m_bind_ip == "localhost");
    if (m_user.empty() && !loopback && !m_allow_noauth) {
        fprintf(stderr, "[SOCKS5] 拒绝启动：监听 %s 但未配置认证。\n"
                        "         请加 --proxy-user/--proxy-pass；确需无认证（仅内网/前置 TLS）"
                        "再加 --proxy-allow-noauth\n", m_bind_ip.c_str());
        return false;
    }
    if (m_user.empty() && !loopback) {
        fprintf(stderr, "[SOCKS5] 警告：无认证代理监听 %s（已由 --proxy-allow-noauth 显式放行）\n",
                m_bind_ip.c_str());
    }
    if (!m_user.empty() && m_pass.size() < 8) {
        fprintf(stderr, "[SOCKS5] 警告：代理密码长度仅 %zu，公网暴露建议 ≥8 位随机密码\n",
                m_pass.size());
    }

    m_listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (m_listen_fd < 0) {
        fprintf(stderr, "[SOCKS5] socket() failed: %s\n", strerror(errno));
        return false;
    }
    int reuse = 1;
    setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(m_port);
    if (m_bind_ip == "0.0.0.0") {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else if (inet_pton(AF_INET, m_bind_ip.c_str(), &addr.sin_addr) != 1) {
        fprintf(stderr, "[SOCKS5] 非法绑定地址 %s\n", m_bind_ip.c_str());
        ::close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }
    if (bind(m_listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        fprintf(stderr, "[SOCKS5] bind(%s:%u) failed: %s\n",
                m_bind_ip.c_str(), static_cast<unsigned>(m_port), strerror(errno));
        ::close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }
    if (listen(m_listen_fd, 64) < 0) {
        fprintf(stderr, "[SOCKS5] listen() failed: %s\n", strerror(errno));
        ::close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }

    // 目标 ACL：内网/回环判定 + 本机接口地址（防经公网 IP 回连本机服务）
    m_acl.reset(new proxy_common::TargetAcl());
    m_acl->allow_internal = m_allow_private;
    proxy_common::collect_local_addresses(*m_acl);
    // 每来源连接限制
    {
        proxy_common::ConnLimits lim;
        lim.max_concurrent = m_max_per_source;
        lim.rate_per_sec = m_conn_rate_per_sec;
        lim.rate_burst = m_conn_rate_per_sec * 30;
        m_conn_limiter.reset(new proxy_common::ConnLimiter(lim));
    }

    m_running.store(true);
    try {
        m_accept_thread = std::thread(&Socks5Proxy::accept_work, this);
    } catch (const std::system_error& e) {
        fprintf(stderr, "[SOCKS5] 启动 accept 线程失败: %s\n", e.what());
        m_running.store(false);
        ::close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }
    fprintf(stderr, "[SOCKS5] 浏览器代理监听 %s:%u（%s，上限 %zu 连接）\n",
            m_bind_ip.c_str(), static_cast<unsigned>(m_port),
            m_user.empty() ? "无认证——公网部署请加 --socks5-user/--socks5-pass"
                           : "RFC1929 用户名/密码认证",
            m_max_conns);
    return true;
}

void Socks5Proxy::stop()
{
    if (!m_running.exchange(false)) {
        // 未运行：仍尝试回收残留线程
        std::lock_guard<std::mutex> lock(m_workers_mutex);
        for (auto& w : m_workers) {
            if (w.thread.joinable())
                w.thread.join();
        }
        m_workers.clear();
        return;
    }
    if (m_listen_fd >= 0) {
        ::shutdown(m_listen_fd, SHUT_RDWR);
        ::close(m_listen_fd);
        m_listen_fd = -1;
    }
    if (m_accept_thread.joinable())
        m_accept_thread.join();
    // 工作线程在 poll 超时/空闲检查中发现 m_running=false 后自行退出（≤500ms）
    std::lock_guard<std::mutex> lock(m_workers_mutex);
    for (auto& w : m_workers) {
        if (w.thread.joinable())
            w.thread.join();
    }
    m_workers.clear();
    fprintf(stderr, "[SOCKS5] 代理已停止\n");
}

void Socks5Proxy::join_finished()
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

void Socks5Proxy::accept_work()
{
    while (m_running.load()) {
        struct pollfd pfd{};
        pfd.fd = m_listen_fd;
        pfd.events = POLLIN;
        int pr;
        do {
            pr = poll(&pfd, 1, 500);    // 500ms 醒一次检查停止标志
        } while (pr < 0 && errno == EINTR);
        if (!m_running.load())
            break;
        if (pr <= 0)
            continue;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
            continue;

        join_finished();                // 顺手回收已结束的连接线程

        sockaddr_in peer{};
        socklen_t plen = sizeof(peer);
        const int fd = accept4(m_listen_fd, reinterpret_cast<sockaddr*>(&peer), &plen,
                               SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
                continue;
            if (errno == EMFILE || errno == ENFILE) {
                fprintf(stderr, "[SOCKS5] fd 耗尽，暂停接收新连接\n");
                continue;
            }
            fprintf(stderr, "[SOCKS5] accept() failed: %s\n", strerror(errno));
            continue;
        }
        // 连接数硬上限：超出直接拒绝（关闭连接），防止 fd/线程无界增长
        if (m_conns.load() >= m_max_conns) {
            fprintf(stderr, "[SOCKS5] 连接数达上限 %zu，拒绝新连接\n", m_max_conns);
            ::close(fd);
            continue;
        }
        // 收发超时上限：对端不收/半死连接在 30s 内失败并回收
        proxy_common::set_io_timeout(fd, kSendTimeoutSec);

        char ipbuf[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &peer.sin_addr, ipbuf, sizeof(ipbuf));
        const std::string peer_ip = ipbuf;

        // 每来源连接限制：并发超限或新建过快直接拒绝（防单来源占满连接槽）
        if (!m_conn_limiter->try_acquire(peer_ip, proxy_common::now_ms())) {
            size_t suppressed = 0;
            if (m_log_limiter->allow(proxy_common::now_ms(), &suppressed)) {
                fprintf(stderr, "[SOCKS5] %s 连接数/速率超限，拒绝（已抑制 %zu 条同类日志）\n",
                        sanitize_for_log(peer_ip).c_str(), suppressed);
            }
            ::close(fd);
            continue;
        }
        const std::string peer_str =
            peer_ip + ":" + std::to_string(ntohs(peer.sin_port));

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
            fprintf(stderr, "[SOCKS5] 创建处理线程失败: %s\n", e.what());
            ::close(fd);
            m_conns.fetch_sub(1);
        }
    }
    // 停止后回收全部工作线程
    join_finished();
}

void Socks5Proxy::handle_conn(int fd, const std::string& peer_ip, const std::string& peer)
{
    // ---- 阶段1：方法协商 ----
    uint8_t hdr[2] = {0};
    if (!read_full(fd, hdr, 2, kHandshakeTimeoutMs) || hdr[0] != kVer5) {
        ::close(fd);
        m_conns.fetch_sub(1);
        return;
    }
    const uint8_t nmethods = hdr[1];
    std::vector<uint8_t> methods(nmethods);
    if (nmethods == 0 || !read_full(fd, methods.data(), nmethods, kHandshakeTimeoutMs)) {
        ::close(fd);
        m_conns.fetch_sub(1);
        return;
    }
    const bool need_auth = !m_user.empty();
    uint8_t chosen = kAuthNoAcceptable;
    for (uint8_t m : methods) {
        if (need_auth && m == kAuthUserPass) {
            chosen = kAuthUserPass;
            break;
        }
        if (!need_auth && m == kAuthNone) {
            chosen = kAuthNone;
            break;
        }
    }
    const uint8_t method_reply[2] = { kVer5, chosen };
    if (chosen == kAuthNoAcceptable || !write_full(fd, method_reply, 2)) {
        fprintf(stderr, "[SOCKS5] %s 无可用认证方式，拒绝\n", sanitize_for_log(peer).c_str());
        ::close(fd);
        m_conns.fetch_sub(1);
        return;
    }

    // ---- 阶段2：RFC1929 用户名/密码（如配置） ----
    if (chosen == kAuthUserPass) {
        // 防暴力破解：失败过多的来源在锁定期内直接拒绝（对端表现与认证失败一致）
        if (!m_auth_throttle->allow(peer_ip, proxy_common::now_ms())) {
            const uint8_t denied[2] = { kVer5, kAuthNoAcceptable };
            write_full(fd, denied, 2);
            fprintf(stderr, "[SOCKS5] %s 认证失败次数过多，暂时拒绝\n",
                    sanitize_for_log(peer_ip).c_str());
            ::close(fd);
            m_conns.fetch_sub(1);
            return;
        }
        uint8_t ah[2] = {0};
        if (!read_full(fd, ah, 2, kHandshakeTimeoutMs) || ah[0] != 0x01) {
            ::close(fd);
            m_conns.fetch_sub(1);
            return;
        }
        const uint8_t ulen = ah[1];
        std::vector<char> user(ulen);
        if (ulen == 0 || !read_full(fd, reinterpret_cast<uint8_t*>(user.data()), ulen, kHandshakeTimeoutMs)) {
            ::close(fd);
            m_conns.fetch_sub(1);
            return;
        }
        uint8_t plen_b = 0;
        if (!read_full(fd, &plen_b, 1, kHandshakeTimeoutMs)) {
            ::close(fd);
            m_conns.fetch_sub(1);
            return;
        }
        std::vector<char> pass(plen_b);
        if (plen_b > 0 && !read_full(fd, reinterpret_cast<uint8_t*>(pass.data()), plen_b, kHandshakeTimeoutMs)) {
            ::close(fd);
            m_conns.fetch_sub(1);
            return;
        }
        const std::string u(user.data(), user.size());
        const std::string p(pass.data(), pass.size());
        const bool ok = constant_time_eq(u, m_user) && constant_time_eq(p, m_pass);
        const uint8_t auth_reply[2] = { 0x01, static_cast<uint8_t>(ok ? 0x00 : 0x01) };
        if (!write_full(fd, auth_reply, 2) || !ok) {
            const uint64_t lock_ms = ok ? 0
                : m_auth_throttle->on_failure(peer_ip, proxy_common::now_ms());
            if (lock_ms > 0) {
                fprintf(stderr, "[SOCKS5] %s 认证失败，已锁定 %llu 秒（防暴力破解）\n",
                        sanitize_for_log(peer_ip).c_str(),
                        static_cast<unsigned long long>(lock_ms / 1000));
            } else {
                fprintf(stderr, "[SOCKS5] %s 认证失败\n", sanitize_for_log(peer).c_str());
            }
            ::close(fd);
            m_conns.fetch_sub(1);
            return;
        }
        m_auth_throttle->on_success(peer_ip);
    }

    // ---- 阶段3：请求（仅 CONNECT） ----
    uint8_t req[4] = {0};
    if (!read_full(fd, req, 4, kHandshakeTimeoutMs) || req[0] != kVer5) {
        ::close(fd);
        m_conns.fetch_sub(1);
        return;
    }
    if (req[1] != kCmdConnect) {
        const uint8_t rep[10] = { kVer5, kRepCmdNotSupported, 0x00, kAtypIpv4, 0,0,0,0, 0,0 };
        write_full(fd, rep, sizeof(rep));
        fprintf(stderr, "[SOCKS5] %s 不支持的命令 0x%02X（仅 CONNECT）\n", sanitize_for_log(peer).c_str(), req[1]);
        ::close(fd);
        m_conns.fetch_sub(1);
        return;
    }

    char host[256] = {0};
    uint16_t dport = 0;
    sockaddr_in target4{};
    sockaddr_in6 target6{};

    if (req[3] == kAtypIpv4) {
        if (!read_full(fd, reinterpret_cast<uint8_t*>(&target4.sin_addr), 4, kHandshakeTimeoutMs) ||
            !read_full(fd, reinterpret_cast<uint8_t*>(&dport), 2, kHandshakeTimeoutMs)) {
            ::close(fd);
            m_conns.fetch_sub(1);
            return;
        }
        target4.sin_family = AF_INET;
        target4.sin_port = dport;
        inet_ntop(AF_INET, &target4.sin_addr, host, sizeof(host));
    } else if (req[3] == kAtypDomain) {
        uint8_t dlen = 0;
        if (!read_full(fd, &dlen, 1, kHandshakeTimeoutMs) || dlen == 0 ||
            !read_full(fd, reinterpret_cast<uint8_t*>(host), dlen, kHandshakeTimeoutMs) ||
            !read_full(fd, reinterpret_cast<uint8_t*>(&dport), 2, kHandshakeTimeoutMs)) {
            ::close(fd);
            m_conns.fetch_sub(1);
            return;
        }
        host[dlen] = '\0';
    } else if (req[3] == kAtypIpv6) {
        if (!read_full(fd, reinterpret_cast<uint8_t*>(&target6.sin6_addr), 16, kHandshakeTimeoutMs) ||
            !read_full(fd, reinterpret_cast<uint8_t*>(&dport), 2, kHandshakeTimeoutMs)) {
            ::close(fd);
            m_conns.fetch_sub(1);
            return;
        }
        target6.sin6_family = AF_INET6;
        target6.sin6_port = dport;
        inet_ntop(AF_INET6, &target6.sin6_addr, host, sizeof(host));
    } else {
        const uint8_t rep[10] = { kVer5, kRepAtypNotSupported, 0x00, kAtypIpv4, 0,0,0,0, 0,0 };
        write_full(fd, rep, sizeof(rep));
        ::close(fd);
        m_conns.fetch_sub(1);
        return;
    }
    const uint16_t port_host = ntohs(dport);

    // ---- 阶段4：连接目标（统一走 ACL：默认拒绝服务端内网/回环目标） ----
    const proxy_common::ConnectResult cr =
        proxy_common::connect_target_checked(host, port_host, *m_acl);
    const int out_fd = cr.fd;
    if (out_fd < 0) {
        // ACL 拒绝回 0x02（connection not allowed by ruleset），与 RFC1928 语义一致
        const uint8_t rep_code = cr.blocked ? kRepNotAllowed : rep_from_errno(cr.last_errno);
        const uint8_t rep[10] = { kVer5, rep_code, 0x00, kAtypIpv4, 0,0,0,0, 0,0 };
        write_full(fd, rep, sizeof(rep));
        if (cr.blocked) {
            // ACL 拒绝日志可被高频触发 → 限速（附抑制计数），避免刷屏打满磁盘
            size_t suppressed = 0;
            if (m_log_limiter->allow(proxy_common::now_ms(), &suppressed)) {
                fprintf(stderr, "[SOCKS5] %s → %s:%u 被目标 ACL 拒绝（服务端内网/回环/本机；"
                                "内网自用可加 --proxy-allow-private）（已抑制 %zu 条同类日志）\n",
                        sanitize_for_log(peer).c_str(), sanitize_for_log(host).c_str(), port_host,
                        suppressed);
            }
        } else {
            fprintf(stderr, "[SOCKS5] %s → %s:%u 连接失败: %s\n",
                    sanitize_for_log(peer).c_str(), sanitize_for_log(host).c_str(), port_host, strerror(cr.last_errno));
        }
        ::close(fd);
        m_conns.fetch_sub(1);
        return;
    }

    // 目标 socket 同样设置收发超时
    proxy_common::set_io_timeout(out_fd, kSendTimeoutSec);

    // ---- 阶段5：成功应答（BND.ADDR/PORT 取本端出口地址） ----
    {
        uint8_t rep[10] = { kVer5, kRepSuccess, 0x00, kAtypIpv4, 0,0,0,0, 0,0 };
        sockaddr_in local{};
        socklen_t llen = sizeof(local);
        if (getsockname(out_fd, reinterpret_cast<sockaddr*>(&local), &llen) == 0 &&
            local.sin_family == AF_INET) {
            memcpy(rep + 4, &local.sin_addr, 4);
            memcpy(rep + 8, &local.sin_port, 2);
        }
        if (!write_full(fd, rep, sizeof(rep))) {
            ::close(fd);
            ::close(out_fd);
            m_conns.fetch_sub(1);
            return;
        }
    }
    fprintf(stderr, "[SOCKS5] %s → %s:%u 已建立\n", sanitize_for_log(peer).c_str(), sanitize_for_log(host).c_str(), port_host);

    // ---- 阶段6：双向中继（公共件：poll + 半关闭 + 空闲回收） ----
    proxy_common::Stream browser_stream{ fd, nullptr };
    proxy_common::Stream target_stream{ out_fd, nullptr };
    const auto relay_begin = std::chrono::steady_clock::now();
    proxy_common::relay_two_way(browser_stream, target_stream, kIdleTimeoutMs, m_running);
    const auto relay_secs = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now() - relay_begin).count();
    if (relay_secs >= kIdleTimeoutMs / 1000) {
        fprintf(stderr, "[SOCKS5] %s 空闲超时，回收\n", sanitize_for_log(peer).c_str());
    }

    ::close(out_fd);
    ::close(fd);
    m_conns.fetch_sub(1);
}
