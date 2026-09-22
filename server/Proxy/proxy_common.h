#pragma once
// ============================================================================
// 浏览器代理入口公共件（server/Socks5 与 server/HttpsProxy 共用）
//
// 提供：
//   - POSIX socket 层小工具（限时读满/写满/非阻塞 connect）
//   - 目标地址 ACL（默认拒绝服务端内网/回环/链路本地/组播等目标）
//   - connect_target_checked：带 ACL 的目标连接（域名逐个候选过滤）
//   - Stream：明文 fd 或 TLS（SSL*）承载的统一读写接口
//   - relay_two_way：双向中继（poll + 半关闭 + 空闲回收）
//   - ssl_handshake_timed：非阻塞 + poll 驱动的限时 TLS 握手
//
// TLS 相关分支只在 Stream.ssl 非空时执行；SOCKS5 入口传 ssl=nullptr。
// ============================================================================

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#if !defined(_WIN32)
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#endif

#include <array>

#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace proxy_common {

// 单调时钟毫秒（限速/超时统一用它，避免系统时间跳变影响）
inline uint64_t now_ms()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

// 常量时间比较（代理凭据校验，避免计时侧信道；长度不同直接失败）
inline bool constant_time_eq(const std::string& a, const std::string& b)
{
    if (a.size() != b.size())
        return false;
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

// @return 1=可读 0=超时 -1=错误/对端关闭
inline int wait_readable(int fd, int timeout_ms)
{
    struct pollfd pfd{};
    pfd.fd = fd;
    pfd.events = POLLIN;
    for (;;) {
        const int pr = poll(&pfd, 1, timeout_ms);
        if (pr > 0)
            return (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) ? -1 : 1;
        if (pr == 0)
            return 0;
        if (errno != EINTR)
            return -1;
    }
}

// 阻塞读满 n 字节（带读就绪超时）；false = 对端关闭/超时/出错
inline bool read_full(int fd, uint8_t* buf, size_t n, int timeout_ms)
{
    size_t off = 0;
    while (off < n) {
        if (wait_readable(fd, timeout_ms) != 1)
            return false;
        const ssize_t r = recv(fd, buf + off, n - off, 0);
        if (r == 0)
            return false;
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK)
                continue;   // 竞态：继续等
            return false;
        }
        off += static_cast<size_t>(r);
    }
    return true;
}

inline bool write_full(int fd, const uint8_t* buf, size_t n)
{
    size_t off = 0;
    while (off < n) {
        const ssize_t w = send(fd, buf + off, n - off, MSG_NOSIGNAL);
        if (w > 0) {
            off += static_cast<size_t>(w);
            continue;
        }
        if (w < 0 && errno == EINTR)
            continue;
        return false;   // 含 EAGAIN（SO_SNDTIMEO 已给足缓冲；失败即断开）
    }
    return true;
}

// 非阻塞 connect + poll 限时；返回 0 成功，-1 失败（errno 反映原因）
inline int timed_connect(int fd, const struct sockaddr* sa, socklen_t sa_len)
{
    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
        return -1;
    int ret = ::connect(fd, sa, sa_len);
    if (ret < 0 && errno != EINPROGRESS)
        return -1;
    if (ret < 0) {
        struct pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLOUT;
        int pr;
        do {
            pr = poll(&pfd, 1, 10000);
        } while (pr < 0 && errno == EINTR);
        if (pr <= 0) {
            errno = (pr == 0) ? ETIMEDOUT : errno;
            return -1;
        }
        int err = 0;
        socklen_t elen = sizeof(err);
        if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen) < 0)
            return -1;
        if (err != 0) {
            errno = err;
            return -1;
        }
    }
    if (fcntl(fd, F_SETFL, flags) == -1)   // 恢复阻塞（中继阶段用阻塞 + 超时）
        return -1;
    return 0;
}

// 给 socket 设置收发超时（Linux 语义：struct timeval）。
// 目的：TLS 阻塞读写/中继阻塞读不会无限期挂住工作线程。
// 注意：Windows 的 SO_SNDTIMEO 取毫秒而非 timeval（测试垫片下该超时不生效）
inline void set_io_timeout(int fd, int seconds)
{
    struct timeval tv{};
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

// ---------------------------------------------------------------------------
// 日志安全：目标主机名/来源地址都来自对端（可被构造），直接拼进日志会被
// 注入换行/ANSI 转义伪造日志行。统一转义为可打印字符并限长
// ---------------------------------------------------------------------------
inline std::string sanitize_for_log(const std::string& in, size_t max_len = 128)
{
    std::string out;
    // 不用 std::min：MSVC 的 min 宏会与之冲突（Windows 测试构建踩过）
    out.reserve(in.size() < max_len ? in.size() : max_len);
    for (unsigned char c : in) {
        if (out.size() >= max_len) {
            out += "...";
            break;
        }
        out.push_back((c >= 0x20 && c <= 0x7E) ? static_cast<char>(c) : '?');
    }
    return out;
}

// ---------------------------------------------------------------------------
// 每来源连接限制（并发 + 新建速率）
//
// 远程攻击面：不做限制时，单个来源可以占满 256 个连接槽/线程（DoSing 所有
// 其他用户），也能靠"连上就断"的高频新建放大 CPU（每次 TLS 握手都要签名）。
// 令牌桶限速 + 并发上限：突发允许 rate_burst，之后按 rate_per_sec 补充；
// 并发超过 max_concurrent 直接拒绝。条目内存有界，空闲条目会被清理。
// ---------------------------------------------------------------------------
// （顶层结构：嵌套类型的默认成员初始化器不能用作同类的默认实参）
struct ConnLimits
{
    size_t max_concurrent = 16;    // 每来源并发连接上限
    size_t rate_burst = 60;        // 新建连接的突发额度
    size_t rate_per_sec = 2;       // 每秒补充额度（≈120/分钟）
};

class ConnLimiter
{
public:
    explicit ConnLimiter(ConnLimits limits = ConnLimits()) : m_limits(limits) {}

    // 尝试占用一个连接槽；false = 超限（调用方应拒绝该连接）
    bool try_acquire(const std::string& ip, uint64_t now_ms)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        purge_locked(now_ms);
        Entry& e = m_entries[ip];
        if (e.last_ms == 0) {
            e.last_ms = now_ms;
            e.tokens = static_cast<double>(m_limits.rate_burst);
        }
        // 令牌补充
        const uint64_t elapsed = (now_ms > e.last_ms) ? (now_ms - e.last_ms) : 0;
        e.tokens += static_cast<double>(elapsed) / 1000.0 * m_limits.rate_per_sec;
        if (e.tokens > static_cast<double>(m_limits.rate_burst))
            e.tokens = static_cast<double>(m_limits.rate_burst);
        e.last_ms = now_ms;
        if (e.concurrent >= m_limits.max_concurrent)
            return false;
        if (e.tokens < 1.0)
            return false;
        e.tokens -= 1.0;
        ++e.concurrent;
        return true;
    }

    void release(const std::string& ip)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        auto it = m_entries.find(ip);
        if (it == m_entries.end())
            return;
        if (it->second.concurrent > 0)
            --it->second.concurrent;
    }

    size_t tracked() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_entries.size();
    }

private:
    struct Entry
    {
        size_t concurrent = 0;
        double tokens = 0.0;
        uint64_t last_ms = 0;
    };
    static constexpr size_t kMaxEntries = 4096;
    static constexpr uint64_t kIdlePurgeMs = 10 * 60'000;   // 空闲 10 分钟清理

    void purge_locked(uint64_t now_ms)
    {
        if (m_entries.size() < kMaxEntries)
            return;
        for (auto it = m_entries.begin(); it != m_entries.end(); ) {
            const bool idle = it->second.concurrent == 0 &&
                              (now_ms - it->second.last_ms) > kIdlePurgeMs;
            it = idle ? m_entries.erase(it) : std::next(it);
        }
    }

    mutable std::mutex m_mutex;
    std::unordered_map<std::string, Entry> m_entries;
    ConnLimits m_limits;
};

// ---------------------------------------------------------------------------
// 日志限速：拒绝路径的日志会被攻击者高频触发（连接洪泛/认证爆破），
// 不限速会把磁盘打满并淹没真实告警。每类日志默认 5 条/秒，超出的丢弃并
// 在下次放行时附上"已抑制 N 条"
// ---------------------------------------------------------------------------
class LogLimiter
{
public:
    explicit LogLimiter(size_t per_sec = 5) : m_per_sec(per_sec) {}

    bool allow(uint64_t now_ms, size_t* suppressed_out = nullptr)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_window_start == 0 || now_ms - m_window_start >= 1000) {
            m_window_start = now_ms;
            m_emitted = 0;
        }
        if (m_emitted < m_per_sec) {
            ++m_emitted;
            if (suppressed_out != nullptr) {
                *suppressed_out = m_suppressed;
                m_suppressed = 0;
            }
            return true;
        }
        ++m_suppressed;
        return false;
    }

private:
    mutable std::mutex m_mutex;
    size_t m_per_sec;
    size_t m_emitted = 0;
    size_t m_suppressed = 0;
    uint64_t m_window_start = 0;
};

// ---------------------------------------------------------------------------
// 认证失败限速（防在线暴力破解）
//
// 按来源 IP 统计失败次数：60 秒窗口内失败 ≥5 次即锁定，锁定时长随失败次数
// 指数增长（30s → 15min 封顶）；成功一次立即清零。锁定期内直接拒绝（对端
// 看到的表现与"认证失败"一致，不泄露是否被锁定）。内存有界：条目上限
// 4096，超限时清理已过期条目。
// ---------------------------------------------------------------------------
class AuthThrottle
{
public:
    // 当前是否允许该来源尝试认证
    bool allow(const std::string& ip, uint64_t now_ms) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        const Entry* e = find(ip);
        return e == nullptr || now_ms >= e->lock_until;
    }

    // 记录一次失败；返回锁定剩余毫秒（0 = 未锁定）
    uint64_t on_failure(const std::string& ip, uint64_t now_ms)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        purge_locked(now_ms);
        Entry& e = m_entries[ip];
        if (e.window_start == 0 || now_ms - e.window_start > kWindowMs) {
            e.fails = 0;
            e.window_start = now_ms;
        }
        ++e.fails;
        if (e.fails >= kFailsToLock) {
            const uint32_t step = (e.fails - kFailsToLock) / kFailsToLock;   // 每多 5 次翻倍
            uint64_t lock_ms = kBaseLockMs << (step > 5 ? 5 : step);
            if (lock_ms > kMaxLockMs)
                lock_ms = kMaxLockMs;
            e.lock_until = now_ms + lock_ms;
            return lock_ms;
        }
        return 0;
    }

    void on_success(const std::string& ip)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_entries.erase(ip);
    }

    size_t size() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_entries.size();
    }

private:
    struct Entry
    {
        uint32_t fails = 0;
        uint64_t window_start = 0;
        uint64_t lock_until = 0;
    };

    static constexpr uint64_t kWindowMs = 60'000;      // 统计窗口
    static constexpr uint32_t kFailsToLock = 5;        // 窗口内失败达 5 次锁定
    static constexpr uint64_t kBaseLockMs = 30'000;    // 首次锁定 30s
    static constexpr uint64_t kMaxLockMs = 15 * 60'000; // 封顶 15 分钟
    static constexpr size_t kMaxEntries = 4096;

    Entry* find(const std::string& ip)
    {
        auto it = m_entries.find(ip);
        return it == m_entries.end() ? nullptr : &it->second;
    }
    const Entry* find(const std::string& ip) const
    {
        auto it = m_entries.find(ip);
        return it == m_entries.end() ? nullptr : &it->second;
    }
    void purge_locked(uint64_t now_ms)
    {
        if (m_entries.size() < kMaxEntries)
            return;
        for (auto it = m_entries.begin(); it != m_entries.end(); ) {
            const bool expired = (now_ms >= it->second.lock_until) &&
                                 (now_ms - it->second.window_start > kWindowMs);
            it = expired ? m_entries.erase(it) : std::next(it);
        }
    }

    mutable std::mutex m_mutex;
    std::unordered_map<std::string, Entry> m_entries;
};

// ---------------------------------------------------------------------------
// 目标地址 ACL：默认拒绝"服务端内网"目标
//
// 为什么需要：代理在服务端本机发起连接，若不限制，任何通过认证的浏览器
// 用户都能借它访问服务端回环（127.0.0.1 上的管理服务）、内网网段，以及
// TUN 虚拟网段（10.8.0.x = 其他 VPN 客户端的虚拟 IP）——等于把服务端与
// 其他客户端的内网暴露给浏览器侧。默认一律拒绝，仅当管理员显式
// --proxy-allow-private 时才放行（内网自用场景）。
// ---------------------------------------------------------------------------

// IPv4 主机序判断：回环/私网/链路本地/CGNAT/组播/保留段
inline bool ipv4_is_internal(uint32_t n)
{
    const uint32_t a = n >> 24;
    if (a == 0 || a == 127)                 return true;   // 0/8、127/8
    if ((n & 0xFF000000u) == 0x0A000000u)   return true;   // 10/8
    if ((n & 0xFFF00000u) == 0xAC100000u)   return true;   // 172.16/12
    if ((n & 0xFFFF0000u) == 0xC0A80000u)   return true;   // 192.168/16
    if ((n & 0xFFFF0000u) == 0xA9FE0000u)   return true;   // 169.254/16 链路本地
    if ((n & 0xFFC00000u) == 0x64400000u)   return true;   // 100.64/10 CGNAT
    if ((n & 0xFFFFFF00u) == 0xC0000000u)   return true;   // 192.0.0/24
    if ((n & 0xFFFFFF00u) == 0xC0000200u)   return true;   // 192.0.2/24 文档
    if ((n & 0xFFFE0000u) == 0xC6120000u)   return true;   // 198.18/15 基准测试
    if ((n & 0xFFFFFF00u) == 0xC6336400u)   return true;   // 198.51.100/24 文档
    if ((n & 0xFFFFFF00u) == 0xCB007100u)   return true;   // 203.0.113/24 文档
    if (a >= 224)                           return true;   // 224/4 组播 + 240/4 保留
    return false;
}

// IPv6 判断：未指定/回环/ULA/链路本地/组播/文档段；IPv4-mapped 按 IPv4 规则
inline bool ipv6_is_internal(const uint8_t* b)
{
    bool all_zero = true;
    for (int i = 0; i < 16; ++i) {
        if (b[i] != 0) {
            all_zero = false;
            break;
        }
    }
    if (all_zero)
        return true;                                      // ::
    static const uint8_t kLoopback[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    if (memcmp(b, kLoopback, 16) == 0)
        return true;                                      // ::1
    if ((b[0] & 0xFE) == 0xFC)
        return true;                                      // fc00::/7 ULA
    if (b[0] == 0xFE && (b[1] & 0xC0) == 0x80)
        return true;                                      // fe80::/10 链路本地
    if (b[0] == 0xFF)
        return true;                                      // ff00::/8 组播
    // ::ffff:0:0/96 IPv4-mapped：按 IPv4 规则判断
    static const uint8_t kMappedPrefix[12] = {0,0,0,0,0,0,0,0,0,0,0xFF,0xFF};
    if (memcmp(b, kMappedPrefix, 12) == 0) {
        const uint32_t v4 = (static_cast<uint32_t>(b[12]) << 24) |
                            (static_cast<uint32_t>(b[13]) << 16) |
                            (static_cast<uint32_t>(b[14]) << 8) |
                            static_cast<uint32_t>(b[15]);
        return ipv4_is_internal(v4);
    }
    // 2001:db8::/32 文档段
    if (b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8)
        return true;
    return false;
}

// sockaddr → 是否内网/特殊地址
inline bool addr_is_internal(const struct sockaddr* sa)
{
    if (sa == nullptr)
        return true;
    if (sa->sa_family == AF_INET) {
        const auto* a4 = reinterpret_cast<const sockaddr_in*>(sa);
        return ipv4_is_internal(ntohl(a4->sin_addr.s_addr));
    }
    if (sa->sa_family == AF_INET6) {
        const auto* a6 = reinterpret_cast<const sockaddr_in6*>(sa);
        return ipv6_is_internal(a6->sin6_addr.s6_addr);
    }
    return true;   // 未知地址族：保守拒绝
}

// ---------------------------------------------------------------------------
// 目标 ACL 上下文
//
// 除"内网/回环/链路本地"外，还要拒绝"本机任一接口地址"——否则认证用户可用
// 代理连回服务器的公网 IP，从而以"服务器自身"为源去访问本机服务（SSH 爆破、
// 绕过 fail2ban 白名单等）。本机地址在启动时枚举一次（getifaddrs）。
// ---------------------------------------------------------------------------
struct TargetAcl
{
    bool allow_internal = false;                  // --proxy-allow-private 时放行全部
    std::vector<uint32_t> local_v4_net;           // 本机 IPv4（网络序）
    std::vector<std::array<uint8_t, 16>> local_v6;

    bool is_local(const struct sockaddr* sa) const
    {
        if (sa == nullptr)
            return true;
        if (sa->sa_family == AF_INET) {
            const auto* a4 = reinterpret_cast<const sockaddr_in*>(sa);
            for (uint32_t v : local_v4_net) {
                if (v == a4->sin_addr.s_addr)
                    return true;
            }
            return false;
        }
        if (sa->sa_family == AF_INET6) {
            const auto* a6 = reinterpret_cast<const sockaddr_in6*>(sa);
            for (const auto& v : local_v6) {
                if (memcmp(v.data(), a6->sin6_addr.s6_addr, 16) == 0)
                    return true;
            }
            return false;
        }
        return true;
    }

    // true = 该目标被拒绝
    bool blocked(const struct sockaddr* sa) const
    {
        if (allow_internal)
            return false;
        return addr_is_internal(sa) || is_local(sa);
    }
};

// 枚举本机接口地址（Windows 测试构建下为空：正式部署在 Linux）
inline void collect_local_addresses(TargetAcl& acl)
{
#if !defined(_WIN32)
    struct ifaddrs* ifs = nullptr;
    if (getifaddrs(&ifs) != 0 || ifs == nullptr)
        return;
    for (struct ifaddrs* it = ifs; it != nullptr; it = it->ifa_next) {
        if (it->ifa_addr == nullptr)
            continue;
        if (it->ifa_addr->sa_family == AF_INET) {
            const auto* a4 = reinterpret_cast<const sockaddr_in*>(it->ifa_addr);
            acl.local_v4_net.push_back(a4->sin_addr.s_addr);
        } else if (it->ifa_addr->sa_family == AF_INET6) {
            const auto* a6 = reinterpret_cast<const sockaddr_in6*>(it->ifa_addr);
            std::array<uint8_t, 16> v{};
            memcpy(v.data(), a6->sin6_addr.s6_addr, 16);
            acl.local_v6.push_back(v);
        }
    }
    freeifaddrs(ifs);
#endif
}

// 目标连接结果
struct ConnectResult
{
    int fd = -1;              // >=0 = 已连接
    int last_errno = 0;       // 连接失败原因（errno 语义）
    bool blocked = false;     // true = 被 ACL 拒绝（内网/回环目标）
};

// 带 ACL 的连接：字面量地址直接判定；域名逐候选过滤（只连允许的地址）。
// allow_internal=true 时不做限制（--proxy-allow-private）
inline ConnectResult connect_target_checked(const std::string& host, uint16_t port,
                                           const TargetAcl& acl)
{
    ConnectResult r;
    sockaddr_in t4{};
    sockaddr_in6 t6{};
    const bool literal4 = inet_pton(AF_INET, host.c_str(), &t4.sin_addr) == 1;
    const bool literal6 = !literal4 &&
                          inet_pton(AF_INET6, host.c_str(), &t6.sin6_addr) == 1;
    if (literal4 || literal6) {
        const std::string port_str = std::to_string(port);
        addrinfo hints{};
        hints.ai_family = literal4 ? AF_INET : AF_INET6;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0 || res == nullptr) {
            r.last_errno = EHOSTUNREACH;
            return r;
        }
        for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
            if (acl.blocked(ai->ai_addr)) {
                r.blocked = true;
                continue;
            }
            const int fd = socket(ai->ai_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
            if (fd < 0) {
                r.last_errno = errno;
                continue;
            }
            if (timed_connect(fd, ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen)) == 0) {
                r.fd = fd;
                freeaddrinfo(res);
                return r;
            }
            r.last_errno = errno;
            close(fd);
        }
        freeaddrinfo(res);
        if (r.fd < 0 && r.last_errno == 0)
            r.last_errno = r.blocked ? EACCES : EHOSTUNREACH;
        return r;
    }

    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    const std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0 || res == nullptr) {
        r.last_errno = EHOSTUNREACH;
        return r;
    }
    for (addrinfo* ai = res; ai != nullptr; ai = ai->ai_next) {
        if (acl.blocked(ai->ai_addr)) {
            r.blocked = true;   // 域名解析到内网：跳过该候选
            continue;
        }
        const int fd = socket(ai->ai_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
        if (fd < 0) {
            r.last_errno = errno;
            continue;
        }
        if (timed_connect(fd, ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen)) == 0) {
            r.fd = fd;
            freeaddrinfo(res);
            return r;
        }
        r.last_errno = errno;
        close(fd);
    }
    freeaddrinfo(res);
    if (r.fd < 0 && r.last_errno == 0) {
        r.last_errno = r.blocked ? EACCES : EHOSTUNREACH;
        r.blocked = true;   // 全部候选都被 ACL 拒绝
    }
    return r;
}

// ---------------------------------------------------------------------------
// Stream：明文 fd 或 TLS 承载
// ---------------------------------------------------------------------------
struct Stream
{
    int fd = -1;
    SSL* ssl = nullptr;   // 非空 = TLS 承载（TLS 版本由其对应的 SSL_CTX 决定）
};

inline ssize_t stream_read(Stream& s, uint8_t* buf, size_t n)
{
    if (s.ssl != nullptr) {
        const int r = SSL_read(s.ssl, buf, static_cast<int>(n));
        if (r > 0)
            return r;
        const int e = SSL_get_error(s.ssl, r);
        if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
            return -2;   // 需重试（调用方下一轮 poll 再读）
        return -1;
    }
    return recv(s.fd, buf, n, 0);
}

inline bool stream_write(Stream& s, const uint8_t* buf, size_t n)
{
    if (s.ssl != nullptr) {
        size_t off = 0;
        while (off < n) {
            const int w = SSL_write(s.ssl, buf + off, static_cast<int>(n - off));
            if (w > 0) {
                off += static_cast<size_t>(w);
                continue;
            }
            const int e = SSL_get_error(s.ssl, w);
            if (e == SSL_ERROR_WANT_READ || e == SSL_ERROR_WANT_WRITE)
                continue;
            return false;
        }
        return true;
    }
    return write_full(s.fd, buf, n);
}

inline void stream_shutdown_write(const Stream& s)
{
    if (s.ssl != nullptr) {
        // 尽力而为：TLS 无半关闭，直接放行（对端收到 close_notify/EOF）
        return;
    }
    ::shutdown(s.fd, SHUT_WR);
}

// 可读等待（TLS 需先看 SSL 内部是否已有解密好的记录）
inline int stream_wait_readable(const Stream& s, int timeout_ms)
{
    if (s.ssl != nullptr && SSL_pending(s.ssl) > 0)
        return 1;
    return wait_readable(s.fd, timeout_ms);
}

// ---------------------------------------------------------------------------
// 双向中继：poll 驱动 + 半关闭 + 空闲回收；两侧读尽或出错/停止即返回
// ---------------------------------------------------------------------------
inline void relay_two_way(Stream& a, Stream& b,
                          int idle_timeout_ms, const std::atomic<bool>& running,
                          uint64_t max_lifetime_ms = 12ull * 3600 * 1000)
{
    uint8_t buf[16 * 1024];
    Stream* sides[2] = { &a, &b };
    bool closed[2] = { false, false };
    auto last_active = std::chrono::steady_clock::now();
    const auto relay_start = last_active;

    while (running.load() && !(closed[0] && closed[1])) {
        // 绝对寿命上限：即使一直有少量流量（涓流）也不允许长期占用连接槽
        if (max_lifetime_ms != 0 &&
            std::chrono::steady_clock::now() - relay_start >
                std::chrono::milliseconds(max_lifetime_ms)) {
            break;
        }
        // TLS 侧可能已有解密好但未读的数据（SSL_pending）：此时不必等 socket 可读
        bool pending[2] = { false, false };
        for (int i = 0; i < 2; ++i) {
            pending[i] = !closed[i] && sides[i]->ssl != nullptr &&
                         SSL_pending(sides[i]->ssl) > 0;
        }
        const bool any_pending = pending[0] || pending[1];

        // 组装 poll 集合（side → pfds 槽位映射）
        struct pollfd pfds[2]{};
        int slot_of_side[2] = { -1, -1 };
        int n = 0;
        for (int i = 0; i < 2; ++i) {
            if (closed[i])
                continue;
            pfds[n].fd = sides[i]->fd;
            pfds[n].events = POLLIN;
            slot_of_side[i] = n;
            ++n;
        }
        if (!any_pending && n > 0) {
            int pr;
            do {
                pr = poll(pfds, static_cast<nfds_t>(n), 300);
            } while (pr < 0 && errno == EINTR);
            if (pr < 0)
                break;
            if (pr == 0) {
                if (std::chrono::steady_clock::now() - last_active >
                    std::chrono::milliseconds(idle_timeout_ms)) {
                    break;   // 空闲超时回收
                }
                continue;
            }
        }

        for (int i = 0; i < 2; ++i) {
            if (closed[i])
                continue;
            if (!any_pending) {
                const int slot = slot_of_side[i];
                if (slot < 0 ||
                    !(pfds[slot].revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL))) {
                    continue;
                }
            }
            const int dst_idx = 1 - i;
            const ssize_t r = stream_read(*sides[i], buf, sizeof(buf));
            if (r == -2)
                continue;   // TLS 需重试（下一轮 poll/SSL_pending 会再进来）
            if (r <= 0) {
                stream_shutdown_write(*sides[dst_idx]);
                closed[i] = true;   // 本侧读尽：对端收到 EOF，继续等对侧读尽
                last_active = std::chrono::steady_clock::now();
                continue;
            }
            if (!stream_write(*sides[dst_idx], buf, static_cast<size_t>(r))) {
                closed[0] = closed[1] = true;
                break;
            }
            last_active = std::chrono::steady_clock::now();
            if (sides[i]->ssl != nullptr && SSL_pending(sides[i]->ssl) > 0) {
                --i;   // 仍有挂起数据：立即再读同一侧
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 限时 TLS 握手（非阻塞 + poll 驱动；返回 true = 成功）
// ---------------------------------------------------------------------------
inline bool ssl_handshake_timed(SSL* ssl, int fd, int timeout_ms)
{
    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
        return false;

    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);
    bool ok = false;
    for (;;) {
        const int r = SSL_do_handshake(ssl);
        if (r == 1) {
            ok = true;
            break;
        }
        const int e = SSL_get_error(ssl, r);
        if (e != SSL_ERROR_WANT_READ && e != SSL_ERROR_WANT_WRITE)
            break;   // 真正失败（证书/协议错误等）
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now()).count();
        if (left <= 0)
            break;   // 超时
        struct pollfd pfd{};
        pfd.fd = fd;
        pfd.events = (e == SSL_ERROR_WANT_READ) ? POLLIN : POLLOUT;
        int pr;
        do {
            pr = poll(&pfd, 1, static_cast<int>(left));
        } while (pr < 0 && errno == EINTR);
        if (pr <= 0)
            break;
    }
    // 恢复阻塞（中继阶段）
    fcntl(fd, F_SETFL, flags);
    return ok;
}

// 读取 HTTP 头块（读到 \r\n\r\n 为止，含上限与超时）；false = 失败/超限
inline bool stream_read_headers(Stream& s, std::string& out,
                                size_t max_len, int timeout_ms)
{
    out.clear();
    uint8_t ch = 0;
    while (out.size() < max_len) {
        if (stream_wait_readable(s, timeout_ms) != 1)
            return false;
        const ssize_t r = stream_read(s, &ch, 1);
        if (r == -2)
            continue;
        if (r <= 0)
            return false;
        out.push_back(static_cast<char>(ch));
        if (out.size() >= 4 &&
            out.compare(out.size() - 4, 4, "\r\n\r\n") == 0) {
            return true;
        }
        // 兼容裸 LF 分隔（少见但存在）
        if (out.size() >= 2 && out.compare(out.size() - 2, 2, "\n\n") == 0)
            return true;
    }
    return false;
}

} // namespace proxy_common
