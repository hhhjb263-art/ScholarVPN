#pragma once

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>
#include <netinet/in.h>
#include <random>
#include <set>
#include <string>
#include <vector>

#include "../Buffer/QueueBuffer.h"
#include "../Crypt/crypt.h"

constexpr uint32_t kSeqRekeyLimit = 0x80000000u;

class ReplayWindow
{
public:
    bool accept(uint32_t seq)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return accept_locked(seq);
    }

    bool too_old(uint32_t seq) const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_highest == kNone)
            return false;
        const uint64_t s = seq;
        if (s > m_highest)
            return false;
        return (m_highest - s) >= kWindow;
    }

private:
    static constexpr uint64_t kWindow = 64;
    static constexpr uint64_t kNone = ~0ull;
    mutable std::mutex m_mutex;
    uint64_t m_highest = kNone;
    uint64_t m_window = 0;

    bool accept_locked(uint32_t seq)
    {
        const uint64_t s = seq;
        if (m_highest == kNone) {
            m_highest = s;
            m_window = 1;
            return true;
        }
        if (s > m_highest) {
            const uint64_t shift = s - m_highest;
            m_window = (shift >= kWindow) ? 1 : ((m_window << shift) | 1);
            m_highest = s;
            return true;
        }
        const uint64_t age = m_highest - s;
        if (age >= kWindow)
            return false;
        const uint64_t bit = 1ull << age;
        if (m_window & bit)
            return false;
        m_window |= bit;
        return true;
    }
};

enum HandshakeStage : int
{
    HS_STAGE_NONE = 0,
    HS_STAGE_HELLO = 1,
    HS_STAGE_KEYS = 2,
    HS_STAGE_AUTHED = 3,
};

constexpr size_t kMaxTcpTxBufBytes = 2 * 1024 * 1024;

struct Session
{
    explicit Session(const sockaddr_in& addr, bool tcp, size_t queueMax = 512)
        : is_tcp(tcp), peer_addr(addr), send_queue(queueMax)
    {
        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
        peer_ip = ip;
        peer_key = peer_ip + ":" + std::to_string(ntohs(addr.sin_port)) +
                   (tcp ? "/tcp" : "/udp");
        const int64_t t = static_cast<int64_t>(now_ms());
        last_rx_ms.store(t);
        created_at_ms.store(t);
    }

    ~Session()
    {
        if (dh_srv_priv != nullptr)
        {
            EVP_PKEY_free(dh_srv_priv);
            dh_srv_priv = nullptr;
        }
        secure_wipe(key_c2s);
        secure_wipe(key_s2c);
    }

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    static std::string peer_addr_to_key(const sockaddr_in& addr, bool tcp)
    {
        char ip[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
        return std::string(ip) + ":" + std::to_string(ntohs(addr.sin_port)) +
               (tcp ? "/tcp" : "/udp");
    }

    static uint64_t now_ms()
    {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    sockaddr_in peer_addr{};
    std::string peer_key;
    std::string peer_ip;
    const bool is_tcp;
    std::atomic<int> tcp_fd{ -1 };
    std::atomic<bool> tcp_drop{ false };

    std::string client_id;
    std::string cli_pub_hex;
    uint32_t virtual_ip = 0;
    bool ip_assigned = false;

    std::atomic<int> hs_stage{ HS_STAGE_NONE };
    std::vector<uint8_t> nonce_c;
    std::vector<uint8_t> nonce_s;
    std::vector<uint8_t> dh_cli_pub;
    std::vector<uint8_t> dh_srv_pub;
    EVP_PKEY* dh_srv_priv = nullptr;
    std::vector<uint8_t> key_c2s;
    std::vector<uint8_t> key_s2c;
    std::atomic<bool> enc_ready{ false };
    std::atomic<bool> authenticated{ false };
    std::atomic<bool> handshaked{ false };
    std::atomic<bool> released{ false };
    std::vector<uint8_t> server_hello_payload;

    PacketQueue send_queue;
    std::mutex send_mutex;
    std::mutex tcp_tx_mutex;
    std::deque<std::vector<uint8_t>> tcp_tx;
    size_t tcp_tx_bytes = 0;
    std::atomic<uint32_t> seq{ 0 };
    ReplayWindow replay;
    std::atomic<uint32_t> src_reject_logged{ 0 };
    std::atomic<uint32_t> auth_fail_logged{ 0 };
    std::atomic<uint32_t> txq_full_logged{ 0 };

    std::atomic<int64_t> last_rx_ms{ 0 };
    std::atomic<int64_t> created_at_ms{ 0 };

    bool svc_managed = false;
    long long svc_used_base = 0;
    long long svc_quota = 0;
    std::atomic<long long> svc_bytes{ 0 };
    std::atomic<bool> svc_over{ false };
    std::atomic<uint32_t> svc_blk_logged{ 0 };
};

class VirtualIpPool
{
public:
    explicit VirtualIpPool(uint32_t gateway_net, int prefix)
        : rng(std::random_device{}() ^
              static_cast<uint32_t>(std::chrono::steady_clock::now()
                                        .time_since_epoch().count()))
    {
        const uint32_t mask = (prefix <= 0) ? 0u
                            : (prefix >= 32) ? 0xFFFFFFFFu
                            : (~((1u << (32 - prefix)) - 1));
        const uint32_t gw = ntohl(gateway_net);
        const uint32_t net = gw & mask;
        first = net + 1;
        last = net | (~mask);
        if (last > 0)
            last -= 1;
        this->gw = gw;
        if (last < first)
        {
            first = 0;
            last = 0;
        }
    }

    uint32_t allocate()
    {
        if (first == 0 || last < first)
            return 0;
        std::lock_guard<std::mutex> lock(m_mutex);

        std::uniform_int_distribution<uint32_t> dist(first, last);
        for (int i = 0; i < 32; ++i)
        {
            const uint32_t ip = dist(rng);
            if (ip != gw && used.find(ip) == used.end())
            {
                used.insert(ip);
                return htonl(ip);
            }
        }

        uint32_t ip = first;
        while (ip <= last)
        {
            if (ip != gw && used.find(ip) == used.end())
            {
                used.insert(ip);
                return htonl(ip);
            }
            if (ip == 0xFFFFFFFFu)
                break;
            ++ip;
        }
        return 0;
    }

    uint32_t preferred_for(const std::string& key) const
    {
        if (first == 0 || last < first)
            return 0;
        uint64_t h = 14695981039346656037ull;
        for (unsigned char c : key)
        {
            h ^= c;
            h *= 1099511628211ull;
        }
        const uint64_t span = static_cast<uint64_t>(last - first) + 1ull;
        uint32_t ip = first + static_cast<uint32_t>(h % span);
        if (ip == gw)
            ip = (ip < last) ? ip + 1 : first;
        return ip;
    }

    void release(uint32_t ip_net)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        used.erase(ntohl(ip_net));
    }

    bool try_acquire(uint32_t ip_host)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (ip_host == 0 || ip_host == gw || ip_host < first || ip_host > last)
            return false;
        if (used.find(ip_host) != used.end())
            return false;
        used.insert(ip_host);
        return true;
    }

    size_t used_count() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return used.size();
    }

private:
    mutable std::mutex m_mutex;
    std::set<uint32_t> used;
    std::mt19937 rng;
    uint32_t first = 0;
    uint32_t last = 0;
    uint32_t gw = 0;
};
