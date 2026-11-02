// ============================================================================
// src/DnsProxy.cpp —— 本地 DNS 代理实现（UDP/53，双上游按域名分流）
// ============================================================================
#include "DnsProxy.h"

#include "logger.h"
#include "util/utf.h"
#include "tun_macro.h"   // LOG_INFO/LOG_WARN 分级日志宏

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstring>
#include <unordered_map>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <ws2ipdef.h>
#pragma comment(lib, "ws2_32.lib")
using SocketT = SOCKET;
constexpr SocketT kInvalidSock = INVALID_SOCKET;
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
using SocketT = int;
constexpr SocketT kInvalidSock = -1;
#endif

namespace {

// ---- DNS 报文解析：取 question 段的 QNAME（只需要域名，不做完整解析） ----
// 报文：[txid(2)][flags(2)][qd(2)][an(2)][ns(2)][ar(2)] 后跟 question
bool dns_query_info(const unsigned char* buf, size_t len, uint16_t& txid,
                    std::string& qname)
{
    if (len < 12)
        return false;
    txid = static_cast<uint16_t>((buf[0] << 8) | buf[1]);
    const uint16_t qd = static_cast<uint16_t>((buf[4] << 8) | buf[5]);
    if (qd < 1)
        return false;
    size_t p = 12;
    std::string name;
    for (int guard = 0; guard < 16; ++guard) {   // 标签数上限
        if (p >= len)
            return false;
        const uint8_t l = buf[p];
        p += 1;
        if (l == 0)
            break;
        if (p + l > len)
            return false;
        if (!name.empty())
            name += '.';
        for (uint8_t k = 0; k < l; ++k)
            name += static_cast<char>(std::tolower(buf[p + k]));
        p += l;
    }
    if (name.empty() || name.size() > 253)
        return false;
    qname = name;
    return true;
}

// 是否国内域名：等于表内条目，或以 "." + 条目 结尾（子域匹配）
bool domestic_match(const std::string& qname, const std::unordered_set<std::string>& set)
{
    if (set.count(qname) != 0)
        return true;
    const size_t dot = qname.find('.');
    if (dot == std::string::npos)
        return false;
    for (size_t i = 1; i < qname.size(); ++i) {
        if (qname[i - 1] == '.' && set.count(qname.substr(i)) != 0)
            return true;
    }
    return false;
}

} // namespace

// ---------------------------------------------------------------------------
// 生命周期
// ---------------------------------------------------------------------------

bool DnsProxy::start(const cfgstr& listFile, const std::string& upstreamDomestic,
                     const std::string& upstreamForeign)
{
    if (m_running.load())
        return true;
    if (upstreamDomestic.empty() || upstreamForeign.empty())
        return false;

    // 加载国内域名表（坏行跳过；~11 万行加载 <100ms）
    m_domestic.clear();
    // 预留桶数：表约 11 万条，不预留会反复 rehash（Debug 堆校验下 rehash 也不便宜）
    if (m_domestic.bucket_count() < 131072)
        m_domestic.reserve(131072);
    {
        std::FILE* f = nullptr;
#if defined(_WIN32)
        f = ::_wfopen(listFile.c_str(), L"rb");
#else
        f = std::fopen(listFile.c_str(), "rb");
#endif
        if (f == nullptr) {
            LOG_WARN("[DnsProxy] 域名表缺失，代理不启动: %s", cfg_to_utf8(listFile).c_str());
            return false;
        }
        char line[512];
        while (std::fgets(line, sizeof(line), f) != nullptr) {
            std::string d(line);
            while (!d.empty() && (d.back() == '\n' || d.back() == '\r'))
                d.pop_back();
            while (!d.empty() && (d.front() == ' '))
                d.erase(d.begin());
            if (d.empty() || d[0] == '#')
                continue;
            std::transform(d.begin(), d.end(), d.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            m_domestic.insert(d);
        }
        std::fclose(f);
    }
    if (m_domestic.empty()) {
        LOG_WARN("[DnsProxy] 域名表为空，代理不启动");
        return false;
    }
    m_upDomestic = upstreamDomestic;
    m_upForeign = upstreamForeign;

    // 三个 UDP socket：127.0.0.1:53 监听 + 两个上游出口
    SocketT listenSock = ::socket(AF_INET, SOCK_DGRAM, 0);
    SocketT domSock = ::socket(AF_INET, SOCK_DGRAM, 0);
    SocketT forSock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (listenSock == kInvalidSock || domSock == kInvalidSock || forSock == kInvalidSock) {
        LOG_ERR("[DnsProxy] socket 创建失败");
        return false;
    }
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = ::htons(53);
    addr.sin_addr.s_addr = ::htonl(INADDR_LOOPBACK);
    if (::bind(listenSock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        LOG_ERR("[DnsProxy] 绑定 127.0.0.1:53 失败（53 端口需管理员权限/无占用）");
#if defined(_WIN32)
        ::closesocket(listenSock);
        ::closesocket(domSock);
        ::closesocket(forSock);
#else
        ::close(listenSock);
        ::close(domSock);
        ::close(forSock);
#endif
        return false;
    }
    m_listenSock = new SocketT(listenSock);
    m_domSock = new SocketT(domSock);
    m_forSock = new SocketT(forSock);

    m_running.store(true);
    m_thread = std::thread(&DnsProxy::run_loop, this);
    LOG_INFO("[DnsProxy] 已启动：127.0.0.1:53（国内 %s / 国外 %s，域名表 %zu 条）",
             m_upDomestic.c_str(), m_upForeign.c_str(), m_domestic.size());
    return true;
}

void DnsProxy::stop()
{
    if (!m_running.exchange(false))
        return;
#if defined(_WIN32)
    // 关监听 socket 让 poll 立即返回并退出线程
    if (m_listenSock != nullptr) {
        ::closesocket(*static_cast<SocketT*>(m_listenSock));
    }
#endif
    if (m_thread.joinable())
        m_thread.join();
#if defined(_WIN32)
    if (m_listenSock != nullptr) { delete static_cast<SocketT*>(m_listenSock); m_listenSock = nullptr; }
    if (m_domSock != nullptr) { ::closesocket(*static_cast<SocketT*>(m_domSock)); delete static_cast<SocketT*>(m_domSock); m_domSock = nullptr; }
    if (m_forSock != nullptr) { ::closesocket(*static_cast<SocketT*>(m_forSock)); delete static_cast<SocketT*>(m_forSock); m_forSock = nullptr; }
#else
    if (m_listenSock != nullptr) { ::close(*static_cast<SocketT*>(m_listenSock)); delete static_cast<SocketT*>(m_listenSock); m_listenSock = nullptr; }
    if (m_domSock != nullptr) { ::close(*static_cast<SocketT*>(m_domSock)); delete static_cast<SocketT*>(m_domSock); m_domSock = nullptr; }
    if (m_forSock != nullptr) { ::close(*static_cast<SocketT*>(m_forSock)); delete static_cast<SocketT*>(m_forSock); m_forSock = nullptr; }
#endif
    LOG_INFO("[DnsProxy] 已停止");
}

// ---------------------------------------------------------------------------
// 主循环：poll 三 socket，收查询→选上游转发；收应答→按事务回送
// ---------------------------------------------------------------------------

void DnsProxy::run_loop()
{
    struct Pending {
        sockaddr_in client{};
        int clientLen = sizeof(sockaddr_in);
        uint64_t atMs = 0;
        bool viaDomestic = false;
    };
    // 事务表：txid(16bit) → 未决查询。同 txid 并发极少；命中即回送并删除。
    std::unordered_map<uint16_t, Pending> pending;

    const SocketT listenSock = *static_cast<SocketT*>(m_listenSock);
    const SocketT domSock = *static_cast<SocketT*>(m_domSock);
    const SocketT forSock = *static_cast<SocketT*>(m_forSock);

    unsigned char buf[4096];
    auto nowMs = [] {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count());
    };

    while (m_running.load()) {
        // 超时清理（每轮顺带做一次；表里条目通常个位数）
        const uint64_t now = nowMs();
        for (auto it = pending.begin(); it != pending.end();) {
            if (now - it->second.atMs > 10000)
                it = pending.erase(it);
            else
                ++it;
        }

        pollfd fds[3];
        fds[0] = { listenSock, POLLIN, 0 };
        fds[1] = { domSock, POLLIN, 0 };
        fds[2] = { forSock, POLLIN, 0 };
#if defined(_WIN32)
        const int rc = ::WSAPoll(fds, 3, 500);
#else
        const int rc = ::poll(fds, 3, 500);
#endif
        if (rc <= 0)
            continue;

        // ---- 上游应答 → 回送客户端 ----
        for (int u = 1; u <= 2; ++u) {
            if ((fds[u].revents & POLLIN) == 0)
                continue;
            sockaddr_in from{};
            int fromLen = sizeof(from);
            const int n = ::recvfrom(u == 1 ? domSock : forSock,
                                     reinterpret_cast<char*>(buf), sizeof(buf), 0,
                                     reinterpret_cast<sockaddr*>(&from), &fromLen);
            if (n < 12)
                continue;
            const uint16_t txid = static_cast<uint16_t>((buf[0] << 8) | buf[1]);
            auto it = pending.find(txid);
            if (it == pending.end())
                continue;   // 不是我们发出的（伪造/迟到）→ 丢弃
            ::sendto(listenSock, reinterpret_cast<const char*>(buf), n, 0,
                     reinterpret_cast<const sockaddr*>(&it->second.client),
                     it->second.clientLen);
            pending.erase(it);
        }

        // ---- 客户端查询 → 选上游转发 ----
        if (fds[0].revents & POLLIN) {
            sockaddr_in client{};
            int clientLen = sizeof(client);
            const int n = ::recvfrom(listenSock, reinterpret_cast<char*>(buf), sizeof(buf), 0,
                                     reinterpret_cast<sockaddr*>(&client), &clientLen);
            if (n < 12 || n > 2048)   // 合法 DNS 查询很小；超常直接丢弃
                continue;
            uint16_t txid = 0;
            std::string qname;
            if (!dns_query_info(buf, static_cast<size_t>(n), txid, qname))
                continue;
            if (pending.find(txid) != pending.end())
                continue;   // 同 txid 的未决事务还在——极小概率，宁弃不串
            const bool domestic = domestic_match(qname, m_domestic);
            const SocketT up = domestic ? domSock : forSock;
            sockaddr_in dst{};
            dst.sin_family = AF_INET;
            dst.sin_port = ::htons(53);
            const std::string upAddr = domestic ? m_upDomestic : m_upForeign;
            ::inet_pton(AF_INET, upAddr.c_str(), &dst.sin_addr.s_addr);
            if (::sendto(up, reinterpret_cast<const char*>(buf), n, 0,
                         reinterpret_cast<const sockaddr*>(&dst), sizeof(dst)) <= 0)
                continue;
            Pending p;
            p.client = client;
            p.clientLen = clientLen;
            p.atMs = nowMs();
            p.viaDomestic = domestic;
            pending[txid] = p;
        }
    }
}
