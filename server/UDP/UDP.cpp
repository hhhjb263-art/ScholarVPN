#include "UDP.h"

#include "../ServiceDB.h"
#include "../Crypt/crypt.h"
#include "../core/log.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <optional>
#include <poll.h>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <unistd.h>
#include <random>
#include <chrono>
#include <thread>

#include <openssl/rand.h>

namespace {

static std::mutex g_keys_db_mutex;

static bool with_token_lock(const std::string& tokens_path,
                            const std::function<bool()>& op)
{
    const std::string lock_path = tokens_path + ".lock";
    const int lfd = ::open(lock_path.c_str(), O_CREAT | O_RDWR, 0600);
    if (lfd < 0) {
        fprintf(stderr, "[UDP] open(%s) failed: %s\n",
                lock_path.c_str(), strerror(errno));
        return false;
    }
    if (::flock(lfd, LOCK_EX) != 0) {
        fprintf(stderr, "[UDP] flock(%s) failed: %s\n",
                lock_path.c_str(), strerror(errno));
        ::close(lfd);
        return false;
    }
    const bool ok = op();
    ::flock(lfd, LOCK_UN);
    ::close(lfd);
    return ok;
}

constexpr auto kHeartbeatInterval = std::chrono::seconds(10);
constexpr auto kHeartbeatTimeout = std::chrono::seconds(30);
constexpr auto kHandshakeTimeout = std::chrono::seconds(30);
constexpr size_t kMaxPendingSessions = 32;
constexpr size_t kMaxSessionsPerIp = 8;

constexpr uint64_t kSessionMaxLifetimeMs = 24ull * 60ull * 60ull * 1000ull;

uint64_t now_ms()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

bool get_raw_pubkey(EVP_PKEY* pkey, std::vector<uint8_t>& out)
{
    if (pkey == nullptr)
        return false;
    size_t len = 0;
    if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &len) != 1)
        return false;
    out.resize(len);
    return EVP_PKEY_get_raw_public_key(pkey, out.data(), &len) == 1;
}

EVP_PKEY* make_x25519_public_key(const uint8_t* raw, size_t len)
{
    return EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, raw, len);
}

EVP_PKEY* make_ed25519_public_key(const uint8_t* raw, size_t len)
{
    return EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, raw, len);
}

bool generate_ephemeral_x25519(EVP_PKEY*& priv_out, std::vector<uint8_t>& pub_out)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "X25519", nullptr);
    if (ctx == nullptr)
        return false;
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen(ctx, &key) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    EVP_PKEY_CTX_free(ctx);
    if (!get_raw_pubkey(key, pub_out)) {
        EVP_PKEY_free(key);
        return false;
    }
    priv_out = key;
    return true;
}

}

UDP::~UDP()
{
    stop();
    close();
}

std::shared_ptr<Session> UDP::get_or_create_session(const sockaddr_in& addr, bool tcp)
{
    const std::string key = Session::peer_addr_to_key(addr, tcp);
    const std::string ip = key.substr(0, key.rfind(':'));
    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    auto it = m_sessions.find(key);
    if (it != m_sessions.end())
        return it->second;

    size_t pending = 0;
    for (auto& kv : m_sessions)
        if (!kv.second->handshaked.load())
            ++pending;
    if (pending >= kMaxPendingSessions) {
        fprintf(stderr, "[UDP] 未认证会话已达上限 %zu，丢弃新连接 %s\n",
                kMaxPendingSessions, key.c_str());
        return nullptr;
    }

    size_t perIp = 0;
    std::string oldestPendingKey;
    uint64_t oldestCreated = UINT64_MAX;
    for (auto& kv : m_sessions) {
        if (kv.second->peer_ip != ip)
            continue;
        ++perIp;
        if (!kv.second->handshaked.load()) {
            const uint64_t created = static_cast<uint64_t>(kv.second->created_at_ms.load());
            if (created < oldestCreated) {
                oldestCreated = created;
                oldestPendingKey = kv.first;
            }
        }
    }
    if (perIp >= kMaxSessionsPerIp) {
        if (oldestPendingKey.empty()) {
            fprintf(stderr, "[UDP] 来源 %s 会话数已达上限 %zu，拒绝新连接\n",
                    ip.c_str(), kMaxSessionsPerIp);
            return nullptr;
        }
        fprintf(stderr, "[UDP] 来源 %s 超过每源上限，淘汰最早未认证会话 %s\n",
                ip.c_str(), oldestPendingKey.c_str());
        auto victim = m_sessions[oldestPendingKey];
        if (victim) {
            if (victim->is_tcp)
                victim->tcp_drop.store(true);
            if (victim->ip_assigned && victim->virtual_ip != 0)
                release_virtual_ip(victim->virtual_ip);
            victim->released.store(true);
            victim->enc_ready.store(false);
            victim->authenticated.store(false);
            victim->handshaked.store(false);
            victim->hs_stage.store(HS_STAGE_NONE);
        }
        m_sessions.erase(oldestPendingKey);
    }

    if (m_sessions.size() >= m_max_clients) {
        fprintf(stderr, "[UDP] 会话数已达上限 %zu，丢弃新连接 %s\n", m_max_clients, key.c_str());
        return nullptr;
    }
    auto s = std::make_shared<Session>(addr, tcp);
    m_sessions.emplace(key, s);
    fprintf(stderr, "[UDP] 新会话 %s（当前在线 %zu）\n", key.c_str(), m_sessions.size());
    return s;
}

void UDP::release_session(const std::string& key)
{
    std::shared_ptr<Session> victim;
    {
        std::lock_guard<std::mutex> lock(m_sessions_mutex);
        auto it = m_sessions.find(key);
        if (it == m_sessions.end())
            return;
        victim = it->second;
        m_sessions.erase(it);
    }
    if (!victim)
        return;
    if (m_svc && victim->svc_managed && victim->svc_bytes.load() > 0) {
        const long long d = victim->svc_bytes.exchange(0);
        m_svc->add_used(victim->client_id, d);
        m_svc->flush();
    }
    if (victim->ip_assigned && victim->virtual_ip != 0) {
        release_virtual_ip(victim->virtual_ip);
    }
    victim->released.store(true);
    victim->enc_ready.store(false);
    victim->authenticated.store(false);
    victim->handshaked.store(false);
    victim->hs_stage.store(HS_STAGE_NONE);
    fprintf(stderr, "[UDP] 会话 %s 已下线（剩余 %d）\n", key.c_str(), client_count());
}

uint32_t UDP::allocate_virtual_ip(const std::string& client_id)
{
    if (!m_ip_pool)
        return 0;

    auto remember = [this](const std::string& key, uint32_t ip_host) {
        if (key.empty())
            return;
        std::unordered_map<std::string, uint32_t> snapshot;
        {
            std::lock_guard<std::mutex> lock(m_vip_mutex);
            if (m_last_vip.size() > 10000)
                m_last_vip.clear();
            m_last_vip[key] = ip_host;
            snapshot = m_last_vip;
        }
        save_vip_leases(snapshot);
    };

    if (!client_id.empty())
    {
        uint32_t preferred = 0;
        {
            std::lock_guard<std::mutex> lock(m_vip_mutex);
            auto it = m_last_vip.find(client_id);
            if (it != m_last_vip.end())
                preferred = it->second;
        }
        if (preferred != 0 && m_ip_pool->try_acquire(preferred))
            return htonl(preferred);
    }

    if (!client_id.empty())
    {
        const uint32_t hint = m_ip_pool->preferred_for(client_id);
        if (hint != 0)
        {
            bool leased_elsewhere = false;
            {
                std::lock_guard<std::mutex> lock(m_vip_mutex);
                for (const auto& kv : m_last_vip)
                {
                    if (kv.first != client_id && kv.second == hint)
                    {
                        leased_elsewhere = true;
                        break;
                    }
                }
            }
            if (!leased_elsewhere && m_ip_pool->try_acquire(hint))
            {
                remember(client_id, hint);
                fprintf(stderr, "[UDP][VIP] 按身份派生分配 %s -> 0x%08X（主机序）\n",
                        client_id.c_str(), hint);
                return htonl(hint);
            }
        }
    }

    const uint32_t ip_net = m_ip_pool->allocate();
    if (ip_net == 0)
        return 0;
    remember(client_id, ntohl(ip_net));
    return ip_net;
}

void UDP::release_virtual_ip(uint32_t ip)
{
    if (ip == 0)
        return;
    {
        std::lock_guard<std::mutex> lock(m_vip_mutex);
        m_vip_to_key.erase(ip);
    }
    if (m_ip_pool)
        m_ip_pool->release(ip);
}

void UDP::load_vip_leases()
{
    const std::string path = m_keys_dir + "/vip_leases.txt";
    std::ifstream in(path);
    if (!in)
        return;
    std::string cid;
    uint32_t ip = 0;
    while (in >> cid >> ip)
    {
        if (!cid.empty() && ip != 0)
            m_last_vip[cid] = ip;
    }
    if (!m_last_vip.empty())
        fprintf(stderr, "[UDP] 已加载虚拟 IP 租约 %zu 条（%s）\n",
                m_last_vip.size(), path.c_str());
}

void UDP::save_vip_leases(const std::unordered_map<std::string, uint32_t>& leases)
{
    const std::string path = m_keys_dir + "/vip_leases.txt";
    const std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out)
        {
            fprintf(stderr, "[UDP] 租约文件写入失败: %s\n", tmp.c_str());
            return;
        }
        for (const auto& kv : leases)
            out << kv.first << " " << kv.second << "\n";
    }
    std::rename(tmp.c_str(), path.c_str());
}

bool UDP::allow_handshake_recompute(uint32_t ip_net)
{
    constexpr double kRatePerSec = 20.0;
    constexpr double kBurst = 40.0;
    const int64_t now = static_cast<int64_t>(now_ms());

    std::lock_guard<std::mutex> lock(m_hs_rl_mutex);
    if (m_hs_rl.size() > 4096) {
        for (auto it = m_hs_rl.begin(); it != m_hs_rl.end(); ) {
            if (now - it->second.last_ms > 10000)
                it = m_hs_rl.erase(it);
            else
                ++it;
        }
        if (m_hs_rl.size() > 4096)
            m_hs_rl.clear();
    }
    auto& b = m_hs_rl[ip_net];
    if (b.last_ms == 0) {
        b.tokens = kBurst;
        b.last_ms = now;
    }
    const double elapsed = static_cast<double>(now - b.last_ms) / 1000.0;
    b.tokens += elapsed * kRatePerSec;
    if (b.tokens > kBurst)
        b.tokens = kBurst;
    b.last_ms = now;
    if (b.tokens < 1.0) {
        ++b.logged;
        if (b.logged <= 3) {
            char ipstr[INET_ADDRSTRLEN] = {0};
            struct in_addr a{};
            a.s_addr = ip_net;
            inet_ntop(AF_INET, &a, ipstr, sizeof(ipstr));
            fprintf(stderr, "[UDP][AUTH] 握手重算限速命中，丢弃来自 %s 的 auth_hello%s\n",
                    ipstr, (b.logged == 3) ? "（同类日志已抑制）" : "");
        }
        return false;
    }
    b.tokens -= 1.0;
    return true;
}

// 启动传输层：同一端口同时监听 UDP 与 TCP，TCP 用于穿透只放行 443 的网络
bool UDP::start(const std::string& local_ip, uint16_t local_port,
                const std::string& tun_ip, int tun_prefix,
                size_t max_clients, bool udp_enabled)
{
    if (is_running())
        return true;
    m_max_clients = (max_clients > 0) ? max_clients : 64;
    m_tun_prefix = static_cast<uint8_t>((tun_prefix > 0 && tun_prefix <= 32) ? tun_prefix : 24);

    uint32_t gw_net = inet_addr("10.8.0.1");
    if (!tun_ip.empty()) {
        in_addr a{};
        if (inet_pton(AF_INET, tun_ip.c_str(), &a) == 1)
            gw_net = a.s_addr;
    }
    m_ip_pool = std::make_shared<VirtualIpPool>(gw_net, m_tun_prefix);
    load_vip_leases();

    if (udp_enabled) {
        m_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (m_sock < 0) {
            fprintf(stderr, "[UDP] socket() failed: %s\n", strerror(errno));
            return false;
        }
        int reuse = 1;
        if (setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
            fprintf(stderr, "[UDP] setsockopt(SO_REUSEADDR) failed: %s\n", strerror(errno));
        }
        {
            const int bufsize = 8 * 1024 * 1024;
            if (setsockopt(m_sock, SOL_SOCKET, SO_RCVBUFFORCE, &bufsize, sizeof(bufsize)) < 0) {
                if (setsockopt(m_sock, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize)) < 0) {
                    fprintf(stderr, "[UDP] setsockopt(SO_RCVBUF) failed: %s\n", strerror(errno));
                } else {
                    fprintf(stderr, "[UDP] 提示: SO_RCVBUF 可能被 net.core.rmem_max 钳制，"
                            "建议 sysctl -w net.core.rmem_max=8388608\n");
                }
            }
            if (setsockopt(m_sock, SOL_SOCKET, SO_SNDBUFFORCE, &bufsize, sizeof(bufsize)) < 0) {
                if (setsockopt(m_sock, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize)) < 0) {
                    fprintf(stderr, "[UDP] setsockopt(SO_SNDBUF) failed: %s\n", strerror(errno));
                } else {
                    fprintf(stderr, "[UDP] 提示: SO_SNDBUF 可能被 net.core.wmem_max 钳制，"
                            "建议 sysctl -w net.core.wmem_max=8388608\n");
                }
            }
        }
        sockaddr_in server_addr{};
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(local_port);
        if (local_ip.empty() || local_ip == "0.0.0.0") {
            server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
        } else {
            int ret = inet_pton(AF_INET, local_ip.c_str(), &server_addr.sin_addr);
            if (ret != 1) {
                fprintf(stderr, "[UDP] inet_pton(%s) failed\n", local_ip.c_str());
                close();
                return false;
            }
        }
        if (bind(m_sock, reinterpret_cast<struct sockaddr*>(&server_addr), sizeof(server_addr)) < 0) {
            fprintf(stderr, "[UDP] bind(%s:%u) failed: %s\n", local_ip.c_str(), local_port, strerror(errno));
            close();
            return false;
        }
        int flags = fcntl(m_sock, F_GETFL, 0);
        if (flags != -1) {
            fcntl(m_sock, F_SETFL, flags | O_NONBLOCK);
        }
    } else {
        fprintf(stderr, "[UDP] --transport tcp：UDP 监听已禁用，仅服务 TCP 会话\n");
    }

    m_running.store(true);
    if (!start_threads()) {
        fprintf(stderr, "[UDP] start: start_threads failed\n");
        m_running.store(false);
        close();
        return false;
    }
    fprintf(stderr, "[UDP] 监听 %s:%u，虚拟 IP 池网关 %s/%d，上限 %zu 会话\n",
            local_ip.c_str(), local_port, tun_ip.c_str(), m_tun_prefix, m_max_clients);
    return true;
}

void UDP::stop()
{
    if (!m_running.exchange(false)) {
        stop_threads();
        close();
        return;
    }
    if (m_sock >= 0) {
        ::shutdown(m_sock, SHUT_RDWR);
    }
    stop_threads();
    close();
    {
        std::lock_guard<std::mutex> lock(m_sessions_mutex);
        for (auto& kv : m_sessions) {
            kv.second->authenticated.store(false);
            kv.second->handshaked.store(false);
        }
        m_sessions.clear();
    }
    {
        std::lock_guard<std::mutex> lock(m_vip_mutex);
        m_vip_to_key.clear();
    }
}

void UDP::close()
{
    if (m_sock < 0)
        return;
    ::shutdown(m_sock, SHUT_RDWR);
    ::close(m_sock);
    m_sock = -1;
}

int UDP::client_count() const
{
    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    return static_cast<int>(m_sessions.size());
}

void UDP::set_service_db(const std::string& db_path)
{
    auto svc = std::make_unique<service::ServiceDB>();
    if (svc->open(db_path)) {
        fprintf(stderr, "[SVC] 受管服务已启用: %s\n", db_path.c_str());
        m_svc = std::move(svc);
    } else {
        fprintf(stderr, "[SVC] 受管服务库打开失败，功能停用: %s\n", db_path.c_str());
    }
}

void UDP::set_identity(std::shared_ptr<EVP_PKEY> sig_priv, const std::string& keys_dir)
{
    m_sig_priv = std::move(sig_priv);
    m_keys_dir = keys_dir;
    if (m_keys_dir.empty())
        m_keys_dir = "keys";
}

// 下行分发：按虚拟 IP 找到会话并加密发出；新增会话类型从这里接入
bool UDP::forward_tun_packet(packet_buffer&& buf)
{
    if (!is_running() || buf.is_empty())
        return false;
    const uint8_t* d = buf.get_data();
    const size_t n = buf.data_size();
    if (n < 20)
        return false;
    if ((d[0] >> 4) != 4)
        return false;
    const uint8_t ihl = d[0] & 0x0F;
    if (ihl < 5 || static_cast<size_t>(ihl) * 4 > n)
        return false;
    uint32_t dst_net = 0;
    memcpy(&dst_net, d + 16, 4);

    std::string key;
    {
        std::lock_guard<std::mutex> lock(m_vip_mutex);
        auto it = m_vip_to_key.find(dst_net);
        if (it == m_vip_to_key.end())
            return false;
        key = it->second;
    }
    std::shared_ptr<Session> s;
    {
        std::lock_guard<std::mutex> lock(m_sessions_mutex);
        auto it = m_sessions.find(key);
        if (it != m_sessions.end())
            s = it->second;
    }
    if (!s || !s->authenticated.load())
        return false;
    if (!s->send_queue.push(std::move(buf))) {
        const uint32_t n = s->txq_full_logged.fetch_add(1);
        if (n < 3) {
            fprintf(stderr, "[UDP] 下行队列满，丢弃该包（会话保留）%s%s\n",
                    s->peer_key.c_str(), n == 2 ? "（同类日志将抑制）" : "");
        }
        return false;
    }
    wake_send_waiters();
    return true;
}

void UDP::wake_send_waiters()
{
    {
        std::lock_guard<std::mutex> lk(m_wake_mutex);
        m_send_wake = true;
    }
    m_send_cv.notify_one();
}

void UDP::wake_recv_waiters()
{
    {
        std::lock_guard<std::mutex> lk(m_wake_mutex);
        m_recv_wake = true;
    }
    m_recv_cv.notify_all();
}

void UDP::wait_recv_queue(int timeout_ms)
{
    std::unique_lock<std::mutex> lk(m_wake_mutex);
    m_recv_cv.wait_for(lk, std::chrono::milliseconds(timeout_ms),
                       [this] { return m_recv_wake || !is_running(); });
    m_recv_wake = false;
}

bool UDP::recv_ip_packet(packet_buffer& buf)
{
    if (!is_running())
        return false;
    return m_queue_recv.pop(buf);
}

bool UDP::send_packet(Session& s, uint8_t type, const uint8_t* data, size_t len,
                      std::vector<uint8_t>& tmp_buf)
{
    if (len > KMax_data_payload)
        return false;
    if (!is_running())
        return false;
    std::lock_guard<std::mutex> lock(s.send_mutex);

    size_t total_len = Ktunnel_header + len;
    tmp_buf.resize(total_len);
    tunnel_header hdr{};
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = Kmagic;
    hdr.version = s.is_tcp ? static_cast<uint8_t>(v_tcp)
                           : static_cast<uint8_t>(v_udp);
    hdr.type = type;
    hdr.payload_len = htons(static_cast<uint16_t>(len));
    uint32_t seq = s.seq.fetch_add(1);
    if (seq >= kSeqRekeyLimit) {
        fprintf(stderr, "[UDP] 发送序号达到安全上限，强制换会话 %s\n", s.peer_key.c_str());
        if (s.is_tcp)
            s.tcp_drop.store(true);
        else
            release_session(s.peer_key);
        return false;
    }
    hdr.sequence = htonl(seq);
    memcpy(tmp_buf.data(), &hdr, Ktunnel_header);

    if (type == static_cast<uint8_t>(m_data) ||
        type == static_cast<uint8_t>(m_heart) ||
        type == static_cast<uint8_t>(m_heart_response) ||
        type == static_cast<uint8_t>(m_identity) ||
        type == static_cast<uint8_t>(m_identity_ok) ||
        type == static_cast<uint8_t>(m_identity_deny)) {
        if (!s.enc_ready.load()) {
            fprintf(stderr, "[UDP] 密钥未就绪，无法加密发送 type=%d\n", type);
            return false;
        }
        hdr.payload_len = htons(static_cast<uint16_t>(len + 1 + AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN));
        memcpy(tmp_buf.data(), &hdr, Ktunnel_header);
        tmp_buf.resize(Ktunnel_header + len + 1 + AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN);
        const uint8_t inner_type = type;
        size_t sealed_len = 0;
        try {
            sealed_len = aes256_gcm_seal(
                s.key_s2c,
                &inner_type, 1,
                len ? data : nullptr, len,
                tmp_buf.data(), Ktunnel_header,
                tmp_buf.data() + Ktunnel_header,
                tmp_buf.size() - Ktunnel_header);
        } catch (const std::exception& e) {
            fprintf(stderr, "[UDP] 加密失败: %s\n", e.what());
            return false;
        }
        if (Ktunnel_header + sealed_len > KMax_packet_size) {
            return false;
        }
        tmp_buf.resize(Ktunnel_header + sealed_len);
        total_len = Ktunnel_header + sealed_len;
    } else {
        if (len)
            memcpy(tmp_buf.data() + Ktunnel_header, data, len);
    }

    if (s.is_tcp) {
        bool overflow = false;
        {
            std::lock_guard<std::mutex> tx_lock(s.tcp_tx_mutex);
            if (s.tcp_tx_bytes + total_len > kMaxTcpTxBufBytes) {
                overflow = true;
            } else {
                s.tcp_tx.emplace_back(tmp_buf.data(), tmp_buf.data() + total_len);
                s.tcp_tx_bytes += total_len;
            }
        }
        if (overflow) {
            fprintf(stderr, "[UDP] TCP 发送积压超限，断开会话 %s\n", s.peer_key.c_str());
            s.tcp_drop.store(true);
            return false;
        }
        tcp_tx_wake();
        return true;
    }
    int ret = sendto(m_sock, tmp_buf.data(), total_len, 0,
                     reinterpret_cast<struct sockaddr*>(&s.peer_addr), sizeof(s.peer_addr));
    if (ret == -1) {
        fprintf(stderr, "[UDP] sendto() failed (%s): %s\n", s.peer_key.c_str(), strerror(errno));
        return false;
    }
    if (static_cast<size_t>(ret) != total_len) {
        fprintf(stderr, "[UDP] sendto() partial send: %d / %zu bytes\n", ret, total_len);
        return false;
    }
    return true;
}

void UDP::set_tcp_tx_wake(std::function<void()> wake)
{
    std::lock_guard<std::mutex> lock(m_tcp_tx_wake_mutex);
    m_tcp_tx_wake = std::move(wake);
}

void UDP::tcp_tx_wake() const
{
    std::function<void()> wake;
    {
        std::lock_guard<std::mutex> lock(m_tcp_tx_wake_mutex);
        wake = m_tcp_tx_wake;
    }
    if (wake)
        wake();
}

static bool tunnel_packet_source_ok(const Session& s, const std::vector<uint8_t>& pkt)
{
    if (pkt.size() < 20 || (pkt[0] >> 4) != 4)
        return false;
    const uint8_t ihl = pkt[0] & 0x0F;
    if (ihl < 5 || static_cast<size_t>(ihl) * 4 > pkt.size())
        return false;
    const uint16_t total = static_cast<uint16_t>((pkt[2] << 8) | pkt[3]);
    if (total < static_cast<uint16_t>(ihl) * 4 || total > pkt.size())
        return false;
    uint32_t src = 0;
    memcpy(&src, pkt.data() + 12, 4);
    return s.ip_assigned && src == s.virtual_ip;
}

static std::string tunnel_packet_reject_reason(const Session& s, const std::vector<uint8_t>& pkt)
{
    auto ip4 = [](uint32_t net_order_ip) {
        const uint8_t* b = reinterpret_cast<const uint8_t*>(&net_order_ip);
        char out[16] = {0};
        std::snprintf(out, sizeof(out), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
        return std::string(out);
    };
    char buf[192] = {0};
    if (pkt.size() < 20) {
        std::snprintf(buf, sizeof(buf), "包过短（%zu 字节，不足 IPv4 最小头 20）", pkt.size());
    } else if ((pkt[0] >> 4) != 4) {
        std::snprintf(buf, sizeof(buf), "非 IPv4 包（version=%u，%zu 字节）",
                      static_cast<unsigned>(pkt[0] >> 4), pkt.size());
    } else if ((pkt[0] & 0x0F) < 5 || static_cast<size_t>(pkt[0] & 0x0F) * 4 > pkt.size()) {
        std::snprintf(buf, sizeof(buf), "IPv4 头长度非法（IHL=%u，实际 %zu 字节）",
                      static_cast<unsigned>(pkt[0] & 0x0F), pkt.size());
    } else {
        const uint16_t total = static_cast<uint16_t>((pkt[2] << 8) | pkt[3]);
        const uint16_t hdr_len = static_cast<uint16_t>((pkt[0] & 0x0F) * 4);
        if (total < hdr_len || total > pkt.size()) {
            std::snprintf(buf, sizeof(buf), "IPv4 总长字段与实际不符（total=%u，实际 %zu 字节）",
                          static_cast<unsigned>(total), pkt.size());
        } else {
            uint32_t src = 0;
            std::memcpy(&src, pkt.data() + 12, 4);
            if (!s.ip_assigned) {
                std::snprintf(buf, sizeof(buf), "本会话尚未分配虚拟 IP 却收到上行数据包");
            } else {
                std::snprintf(buf, sizeof(buf), "包内源地址=%s，本会话虚拟 IP=%s（源地址不匹配）",
                              ip4(src).c_str(), ip4(s.virtual_ip).c_str());
            }
        }
    }
    return std::string(buf);
}

void UDP::reply_heartbeat(Session& s)
{
    std::vector<uint8_t> sendbuf;
    send_packet(s, static_cast<uint8_t>(m_heart_response), nullptr, 0, sendbuf);
}

void UDP::send_work()
{
    std::vector<uint8_t> sendbuf;
    sendbuf.reserve(KMax_packet_size);
    packet_buffer buf;

    while (is_running()) {
        std::vector<std::shared_ptr<Session>> sessions;
        {
            std::lock_guard<std::mutex> lock(m_sessions_mutex);
            sessions.reserve(m_sessions.size());
            for (auto& kv : m_sessions)
                sessions.push_back(kv.second);
        }
        bool any = false;
        for (auto& s : sessions) {
            if (!s->handshaked.load() || !s->enc_ready.load())
                continue;
            for (int n = 0; n < 256 && s->send_queue.pop(buf); ++n) {
                if (buf.is_empty()) {
                    buf.clear();
                    continue;
                }
                const size_t pay_size = buf.data_size();
                if (pay_size > KMax_data_payload) {
                    buf.clear();
                    continue;
                }
                if (g_packet_log) {
                    fprintf(stderr, "[UDP][TX] 发送数据 len=%zu to %s\n", pay_size, s->peer_key.c_str());
                }
                if (!send_packet(*s, static_cast<uint8_t>(m_data), buf.get_data(), pay_size, sendbuf)) {
                    fprintf(stderr, "[UDP] 发送数据失败: %s\n", s->peer_key.c_str());
                }
                if (m_svc && s->svc_managed) {
                    s->svc_bytes.fetch_add(static_cast<long long>(pay_size));
                    if (!s->svc_over.load() && s->svc_quota > 0 &&
                        s->svc_used_base + s->svc_bytes.load() >= s->svc_quota) {
                        s->svc_over.store(true);
                        fprintf(stderr, "[SVC] 试用流量已达上限，切断会话 (id=%s)\n",
                                s->client_id.c_str());
                        m_svc->flush();
                        release_session(s->peer_key);
                        buf.clear();
                        continue;
                    }
                }
                buf.clear();
                any = true;
            }
        }
        if (!any) {
            std::unique_lock<std::mutex> lk(m_wake_mutex);
            m_send_cv.wait_for(lk, std::chrono::milliseconds(200),
                               [this] { return m_send_wake || !is_running(); });
            m_send_wake = false;
        }
    }
}

void UDP::recv_work()
{
    std::vector<uint8_t> recvbuf;
    std::vector<uint8_t> sendbuf;
    recvbuf.reserve(KMax_packet_size + 64);
    sendbuf.reserve(KMax_packet_size);
    sockaddr_in peer_addr{};

    while (is_running()) {
        if (m_sock < 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }
        struct pollfd pfd{};
        pfd.fd = m_sock;
        pfd.events = POLLIN;
        const int pr = poll(&pfd, 1, 200);
        if (pr <= 0)
            continue;
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
            continue;

        for (int budget = 0; budget < 256 && is_running(); ++budget) {
            recvbuf.resize(KMax_packet_size);
            socklen_t peer_addr_size = sizeof(peer_addr);

            int ret = recvfrom(m_sock, recvbuf.data(), recvbuf.size(), 0,
                               reinterpret_cast<struct sockaddr*>(&peer_addr), &peer_addr_size);
            if (ret == 0) {
                continue;
            }
            if (ret < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    break;
                }
                fprintf(stderr, "[UDP] recvfrom() failed: %s\n", strerror(errno));
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                break;
            }
            if (ret < static_cast<int>(Ktunnel_header))
                continue;

            tunnel_header hdr{};
            memcpy(&hdr, recvbuf.data(), Ktunnel_header);
            if (hdr.magic != Kmagic)
                continue;
            size_t pay_len = ntohs(hdr.payload_len);
            if (pay_len > Max_payload_len || pay_len + Ktunnel_header > static_cast<size_t>(ret))
                continue;

            std::shared_ptr<Session> s = get_or_create_session(peer_addr, false);
            if (!s)
                continue;
            handle_framed(*s, hdr, recvbuf.data() + Ktunnel_header, pay_len);
        }
    }
}

void UDP::handle_framed(Session& s, const tunnel_header& hdr,
                        const uint8_t* payload, size_t pay_len)
{
    if (g_packet_log) {
        char ipstr[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &s.peer_addr.sin_addr, ipstr, sizeof(ipstr));
        fprintf(stderr, "[UDP][RX] type=%d len=%zu from=%s (tcp=%d)\n",
                hdr.type, pay_len, s.peer_key.c_str(), s.is_tcp ? 1 : 0);
    }
    if (s.released.load()) {
        return;
    }

    const uint8_t expect_ver = s.is_tcp ? static_cast<uint8_t>(v_tcp)
                                        : static_cast<uint8_t>(v_udp);
    if (hdr.version != expect_ver) {
        fprintf(stderr, "[UDP] 协议版本不匹配: 收到 v%u 期望 v%u (%s)，丢弃\n",
                static_cast<unsigned>(hdr.version), static_cast<unsigned>(expect_ver),
                s.peer_key.c_str());
        return;
    }
    const uint8_t* aad = payload - Ktunnel_header;

    if (hdr.type == static_cast<uint8_t>(m_data) ||
        hdr.type == static_cast<uint8_t>(m_heart) ||
        hdr.type == static_cast<uint8_t>(m_heart_response) ||
        hdr.type == static_cast<uint8_t>(m_identity) ||
        hdr.type == static_cast<uint8_t>(m_identity_ok) ||
        hdr.type == static_cast<uint8_t>(m_identity_deny) ||
        hdr.type == static_cast<uint8_t>(disconnect)) {
        if (!s.enc_ready.load()) {
            return;
        }
        const uint32_t seq_host = ntohl(hdr.sequence);
        if (s.replay.too_old(seq_host)) {
            if (g_packet_log) {
                fprintf(stderr, "[UDP] 过旧帧丢弃 seq=%u (%s)\n", seq_host, s.peer_key.c_str());
            }
            return;
        }
        uint8_t plain[KMax_data_payload + 1];
        size_t plain_len = 0;
        try {
            plain_len = aes256_gcm_open(s.key_c2s, payload, pay_len,
                                        aad, Ktunnel_header,
                                        plain, sizeof(plain));
        } catch (const std::exception& e) {
            fprintf(stderr, "[UDP] 解密异常: %s\n", e.what());
            return;
        }
        if (plain_len == 0) {
            const uint32_t n = s.auth_fail_logged.fetch_add(1);
            if (n < 3) {
                fprintf(stderr, "[UDP] 密文帧认证失败（密钥不匹配/帧被篡改），丢弃 (%s)%s\n",
                        s.peer_key.c_str(), (n == 2) ? "（同类日志已抑制）" : "");
            }
            return;
        }
        if (!s.replay.accept(seq_host)) {
            if (g_packet_log) {
                fprintf(stderr, "[UDP] 重放帧被丢弃 seq=%u (%s)\n", seq_host, s.peer_key.c_str());
            }
            return;
        }
        s.last_rx_ms.store(static_cast<int64_t>(now_ms()));
        const uint8_t inner_type = plain[0];
        const uint8_t* inner_data = plain + 1;
        const size_t inner_len = plain_len - 1;
        switch (inner_type) {
        case m_data:
            if (inner_len == 0)
                break;
            if (!s.authenticated.load())
                break;
            {
                std::vector<uint8_t> pkt(inner_data, inner_data + inner_len);
                if (!tunnel_packet_source_ok(s, pkt)) {
                    const uint32_t n = s.src_reject_logged.fetch_add(1);
                    if (n < 3) {
                        const std::string why = tunnel_packet_reject_reason(s, pkt);
                        fprintf(stderr, "[UDP] 拒绝上行数据包 (%s): %s%s\n",
                                s.peer_key.c_str(), why.c_str(),
                                (n == 2) ? "（同类日志已抑制）" : "");
                    }
                    break;
                }
                if (m_svc && s.svc_managed) {
                    s.svc_bytes.fetch_add(static_cast<long long>(inner_len));
                    if (!s.svc_over.load() && s.svc_quota > 0 &&
                        s.svc_used_base + s.svc_bytes.load() >= s.svc_quota) {
                        s.svc_over.store(true);
                        fprintf(stderr, "[SVC] 试用流量已达上限，切断会话 (id=%s)\n",
                                s.client_id.c_str());
                        m_svc->flush();
                        release_session(s.peer_key);
                        break;
                    }
                }
                if (m_svc) {
                    if (inner_len >= 20) {
                        uint32_t dst = 0;
                        std::memcpy(&dst, pkt.data() + 16, 4);
                        if (m_svc->ip_blocked(ntohl(dst))) {
                            const uint32_t nb = s.svc_blk_logged.fetch_add(1);
                            if (nb < 3) {
                                fprintf(stderr, "[SVC] 目的 IP 黑名单命中丢弃 (%s)%s\n",
                                        s.client_id.c_str(),
                                        (nb == 2) ? "（同类日志已抑制）" : "");
                            }
                            break;
                        }
                    }
                    std::string domain;
                    if (service::extract_domain(pkt.data(), pkt.size(), domain)) {
                        if (m_svc->domain_blocked(domain)) {
                            const uint32_t nb = s.svc_blk_logged.fetch_add(1);
                            if (nb < 3) {
                                fprintf(stderr, "[SVC] 黑名单命中丢弃: %s (id=%s)%s\n",
                                        domain.c_str(), s.client_id.c_str(),
                                        (nb == 2) ? "（同类日志已抑制）" : "");
                            }
                            break;
                        }
                        m_svc->audit_hit(s.client_id, domain);
                    }
                }
                if (m_queue_recv.push(packet_buffer(std::move(pkt))))
                    wake_recv_waiters();
            }
            break;
        case m_heart:
            reply_heartbeat(s);
            break;
        case m_heart_response:
            break;
        case m_identity:
            handle_identity(s,
                            std::vector<uint8_t>(inner_data, inner_data + inner_len));
            break;
        case m_identity_ok:
        case m_identity_deny:
            break;
        case disconnect:
            fprintf(stderr, "[UDP] 客户端断开: %s\n", s.peer_key.c_str());
            if (s.is_tcp)
                s.tcp_drop.store(true);
            else
                release_session(s.peer_key);
            break;
        default:
            break;
        }
        return;
    }

    switch (hdr.type) {
    case m_auth_hello:
        handle_auth_hello(s, payload, pay_len);
        break;
    case m_auth_client_hello:
        handle_auth_client_hello(s, payload, pay_len);
        break;
    case m_data: {
        break;
    }
    case m_heart:
        reply_heartbeat(s);
        break;
    case m_heart_response:
        break;
    case disconnect:
        break;
    default:
        break;
    }
}

void UDP::handle_auth_hello(Session& s, const uint8_t* payload, size_t len)
{
    if (len != KAuthNonceLen) {
        fprintf(stderr, "[UDP][AUTH] auth_hello 长度错误: %zu != %zu\n", len, KAuthNonceLen);
        return;
    }
    if (!m_sig_priv) {
        fprintf(stderr, "[UDP][AUTH] 未配置服务器身份私钥 SIG_SRV_PRI\n");
        return;
    }

    auto send_server_hello = [&]() -> bool {
        if (s.server_hello_payload.size() != KAuthServerHelloLen) {
            std::vector<uint8_t> sig_payload;
            sig_payload.reserve(KAuthNonceLen * 2 + KAuthDhPubLen);
            sig_payload.insert(sig_payload.end(), s.nonce_c.begin(), s.nonce_c.end());
            sig_payload.insert(sig_payload.end(), s.nonce_s.begin(), s.nonce_s.end());
            sig_payload.insert(sig_payload.end(), s.dh_srv_pub.begin(), s.dh_srv_pub.end());
            std::vector<uint8_t> sig;
            try {
                sig = ed25519_sign(m_sig_priv.get(), sig_payload.data(), sig_payload.size());
            } catch (const std::exception& e) {
                fprintf(stderr, "[UDP][AUTH] 服务器签名失败: %s\n", e.what());
                return false;
            }
            if (sig.size() != KAuthSigLen)
                return false;
            s.server_hello_payload.clear();
            s.server_hello_payload.reserve(KAuthServerHelloLen);
            s.server_hello_payload.insert(s.server_hello_payload.end(), s.nonce_s.begin(), s.nonce_s.end());
            s.server_hello_payload.insert(s.server_hello_payload.end(), s.dh_srv_pub.begin(), s.dh_srv_pub.end());
            s.server_hello_payload.insert(s.server_hello_payload.end(), sig.begin(), sig.end());
        }
        std::vector<uint8_t> sendbuf;
        return send_packet(s, static_cast<uint8_t>(m_auth_server_hello),
                           s.server_hello_payload.data(), s.server_hello_payload.size(), sendbuf);
    };

    if (s.hs_stage.load() >= HS_STAGE_AUTHED || s.authenticated.load()) {
        fprintf(stderr, "[UDP][AUTH] 已认证会话拒绝明文 auth_hello (%s)\n", s.peer_key.c_str());
        return;
    }

    if (!s.nonce_c.empty() && s.nonce_c.size() == KAuthNonceLen &&
        std::memcmp(s.nonce_c.data(), payload, KAuthNonceLen) == 0 &&
        s.dh_srv_priv != nullptr && !s.nonce_s.empty() && !s.dh_srv_pub.empty()) {
        if (send_server_hello())
            fprintf(stderr, "[UDP][AUTH] auth_hello 重传：幂等重发 ServerHello\n");
        return;
    }

    if ((s.hs_stage.load() >= HS_STAGE_KEYS || s.authenticated.load() ||
         s.enc_ready.load() || s.handshaked.load()) &&
        !s.nonce_c.empty() && s.nonce_c.size() == KAuthNonceLen &&
        std::memcmp(s.nonce_c.data(), payload, KAuthNonceLen) != 0) {
        fprintf(stderr, "[UDP][AUTH] 已建立会话收到不同 nonce 的 auth_hello，拒绝重置 (%s)\n",
                s.peer_key.c_str());
        return;
    }

    if (!allow_handshake_recompute(s.peer_addr.sin_addr.s_addr))
        return;

    if (s.dh_srv_priv != nullptr) {
        EVP_PKEY_free(s.dh_srv_priv);
        s.dh_srv_priv = nullptr;
    }
    secure_wipe(s.key_c2s);
    secure_wipe(s.key_s2c);
    s.server_hello_payload.clear();
    s.enc_ready.store(false);
    s.authenticated.store(false);
    s.handshaked.store(false);
    s.hs_stage.store(HS_STAGE_HELLO);
    s.nonce_c.assign(payload, payload + KAuthNonceLen);
    s.nonce_s = generate_nonce(KAuthNonceLen);
    if (!generate_ephemeral_x25519(s.dh_srv_priv, s.dh_srv_pub)) {
        fprintf(stderr, "[UDP][AUTH] 生成临时 X25519 密钥对失败\n");
        return;
    }
    if (!send_server_hello())
        fprintf(stderr, "[UDP][AUTH] 发送 ServerHello 失败\n");
    else
        fprintf(stderr, "[UDP][AUTH] 已回复签名 ServerHello (%s)\n", s.peer_key.c_str());
}

void UDP::handle_auth_client_hello(Session& s, const uint8_t* payload, size_t len)
{
    if (len != KAuthDhPubLen) {
        fprintf(stderr, "[UDP][AUTH] auth_client_hello 长度错误: %zu != %zu\n", len, KAuthDhPubLen);
        return;
    }
    if (s.hs_stage.load() != HS_STAGE_HELLO) {
        fprintf(stderr, "[UDP][AUTH] 非法阶段的 auth_client_hello，拒绝 (%s, stage=%d)\n",
                s.peer_key.c_str(), s.hs_stage.load());
        return;
    }
    if (s.dh_srv_priv == nullptr || s.nonce_c.empty() || s.nonce_s.empty()) {
        fprintf(stderr, "[UDP][AUTH] 会话状态不完整（未先收到 auth_hello）\n");
        return;
    }
    s.dh_cli_pub.assign(payload, payload + KAuthDhPubLen);

    EVP_PKEY* cli_pub = make_x25519_public_key(s.dh_cli_pub.data(), s.dh_cli_pub.size());
    if (cli_pub == nullptr) {
        fprintf(stderr, "[UDP][AUTH] 构造客户端临时公钥失败\n");
        return;
    }
    std::vector<uint8_t> ss;
    try {
        ss = ecdh_derive_shared_secret(s.dh_srv_priv, cli_pub);
    } catch (const std::exception& e) {
        EVP_PKEY_free(cli_pub);
        fprintf(stderr, "[UDP][AUTH] ECDH 失败: %s\n", e.what());
        return;
    }
    EVP_PKEY_free(cli_pub);

    try {
        DirectionalSessionKeys keys = derive_directional_session_keys(ss, s.nonce_c, s.nonce_s);
        secure_wipe(ss);
        s.key_c2s = std::move(keys.key_tx);
        s.key_s2c = std::move(keys.key_rx);
    } catch (const std::exception& e) {
        secure_wipe(ss);
        fprintf(stderr, "[UDP][AUTH] 会话密钥派生失败: %s\n", e.what());
        return;
    }
    if (s.dh_srv_priv != nullptr) {
        EVP_PKEY_free(s.dh_srv_priv);
        s.dh_srv_priv = nullptr;
    }
    s.hs_stage.store(HS_STAGE_KEYS);
    s.enc_ready.store(true);
    fprintf(stderr, "[UDP][AUTH] 加密隧道已建立（阶段2完成，等待身份报文）%s\n", s.peer_key.c_str());
}

void UDP::handle_identity(Session& s, const std::vector<uint8_t>& inner)
{
    if (s.authenticated.load()) {
        uint8_t resend_payload[5] = {0};
        memcpy(resend_payload, &s.virtual_ip, 4);
        resend_payload[4] = static_cast<uint8_t>(m_tun_prefix);
        std::vector<uint8_t> resend_buf;
        if (!send_packet(s, static_cast<uint8_t>(m_identity_ok), resend_payload,
                         sizeof(resend_payload), resend_buf)) {
            fprintf(stderr, "[UDP][AUTH] 重传 identity_ok 失败 (%s)\n", s.peer_key.c_str());
        }
        return;
    }
    auto deny = [&](uint8_t reason) {
        std::vector<uint8_t> r{ reason };
        std::vector<uint8_t> sendbuf;
        send_packet(s, static_cast<uint8_t>(m_identity_deny), r.data(), r.size(), sendbuf);
        s.authenticated.store(false);
        s.handshaked.store(false);
    };
    if (inner.size() < 2 + KAuthIdentityFixed + KAuthSigLen) {
        fprintf(stderr, "[UDP][AUTH] 身份报文过短: %zu\n", inner.size());
        deny(0);
        return;
    }
    const uint8_t flags = inner[0];
    const size_t token_len = inner[1];
    if (inner.size() < 2 + token_len + KAuthIdentityFixed + KAuthSigLen) {
        fprintf(stderr, "[UDP][AUTH] 身份报文长度不匹配\n");
        deny(0);
        return;
    }
    size_t pos = 2;
    const std::string token(reinterpret_cast<const char*>(inner.data() + pos), token_len);
    pos += token_len;

    const std::vector<uint8_t> payload(inner.begin() + pos, inner.end() - KAuthSigLen);
    const uint8_t* sig = inner.data() + inner.size() - KAuthSigLen;
    if (payload.size() < KAuthIdentityFixed) {
        deny(0);
        return;
    }
    const uint8_t* p = payload.data();
    const std::vector<uint8_t> nc(p, p + KAuthNonceLen);             p += KAuthNonceLen;
    const std::vector<uint8_t> ns(p, p + KAuthNonceLen);             p += KAuthNonceLen;
    const std::vector<uint8_t> dc(p, p + KAuthDhPubLen);             p += KAuthDhPubLen;
    const std::vector<uint8_t> ds(p, p + KAuthDhPubLen);             p += KAuthDhPubLen;
    const std::vector<uint8_t> cli_pub(p, p + KAuthDhPubLen);        p += KAuthDhPubLen;
    const size_t id_len = *p;                                        ++p;
    if (payload.size() != KAuthIdentityFixed + id_len) {
        fprintf(stderr, "[UDP][AUTH] identity_payload 长度不匹配\n");
        deny(0);
        return;
    }
    const std::string client_id(reinterpret_cast<const char*>(p), id_len);

    if (nc != s.nonce_c || ns != s.nonce_s || dc != s.dh_cli_pub || ds != s.dh_srv_pub) {
        fprintf(stderr, "[UDP][AUTH] 身份报文会话上下文不匹配，拒绝\n");
        deny(0);
        return;
    }

    EVP_PKEY* cli_key = make_ed25519_public_key(cli_pub.data(), cli_pub.size());
    if (cli_key == nullptr) {
        fprintf(stderr, "[UDP][AUTH] 构造客户端身份公钥失败\n");
        deny(0);
        return;
    }
    bool sig_ok = false;
    try {
        sig_ok = ed25519_verify(cli_key, payload.data(), payload.size(), sig, KAuthSigLen);
    } catch (const std::exception&) {
        sig_ok = false;
    }
    EVP_PKEY_free(cli_key);
    if (!sig_ok) {
        fprintf(stderr, "[UDP][AUTH] 客户端身份签名校验失败，拒绝\n");
        deny(0);
        return;
    }

    const std::string cli_pub_hex = to_hex(cli_pub.data(), cli_pub.size());
    const std::string clients_path = m_keys_dir + "/registered_clients.txt";
    const std::string tokens_path  = m_keys_dir + "/register_tokens.txt";
    {
        std::lock_guard<std::mutex> db_lock(g_keys_db_mutex);
        // flags=1 注册：消耗一次性令牌并把客户端公钥写入登记表
        if (flags == 1) {
            if (token.empty()) {
                fprintf(stderr, "[UDP][AUTH] 注册模式缺少 register_token\n");
                deny(1);
                return;
            }
            if (!file_remove_line(tokens_path, token)) {
                fprintf(stderr, "[UDP][AUTH] 注册令牌无效或已使用\n");
                deny(1);
                return;
            }
            if (!file_append_line(clients_path, cli_pub_hex)) {
                fprintf(stderr, "[UDP][AUTH] 写入已注册客户端失败\n");
                deny(1);
                return;
            }
            fprintf(stderr, "[UDP][AUTH] 客户端注册成功 id=%s (%s)\n", client_id.c_str(), s.peer_key.c_str());
        } else {
            // flags=0 登录：只校验公钥是否已在登记表中
            if (!file_contains_line(clients_path, cli_pub_hex)) {
                fprintf(stderr, "[UDP][AUTH] 未注册的客户端身份，拒绝登录\n");
                deny(0);
                return;
            }
            fprintf(stderr, "[UDP][AUTH] 客户端登录成功 id=%s (%s)\n", client_id.c_str(), s.peer_key.c_str());
        }
    }

    if (m_svc && m_svc->machine_blocked(client_id)) {
        fprintf(stderr, "[SVC] 机器黑名单拒绝接入 %s\n", client_id.c_str());
        deny(2);
        return;
    }

    // 受管模式：按 trial 记录校验状态、有效期与配额
    if (m_svc) {
        const service::TrialInfo t = m_svc->get_trial(client_id);
        if (t.found) {
            std::string why;
            const long long now_s = static_cast<long long>(time(nullptr));
            if (t.status == "rejected")
                why = "该设备的服务申请已被拒绝";
            else if (t.expire_at != 0 && now_s >= t.expire_at)
                why = "已超出使用范围";
            else if (t.quota_bytes != 0 && t.used_bytes >= t.quota_bytes)
                why = "已超出使用范围";
            else if (t.status != "trial" && t.status != "approved")
                why = "服务状态异常";
            if (!why.empty()) {
                fprintf(stderr, "[SVC] 拒绝接入 %s: %s\n", client_id.c_str(), why.c_str());
                deny(2);
                return;
            }
            s.svc_managed = true;
            s.svc_used_base = t.used_bytes;
            s.svc_quota = t.quota_bytes;
            if (t.quota_bytes != 0) {
                fprintf(stderr, "[SVC] 受管用户 %s：已用 %lld / 配额 %lld 字节\n",
                        client_id.c_str(), t.used_bytes, t.quota_bytes);
            }
        }
    }
    s.client_id = client_id;
    s.cli_pub_hex = cli_pub_hex;

    {
        std::vector<std::shared_ptr<Session>> victims;
        {
            std::lock_guard<std::mutex> lock(m_sessions_mutex);
            for (auto& kv : m_sessions) {
                if (kv.second.get() != &s && kv.second->cli_pub_hex == s.cli_pub_hex)
                    victims.push_back(kv.second);
            }
        }
        for (auto& victim : victims) {
            if (victim->is_tcp)
                victim->tcp_drop.store(true);
            release_session(victim->peer_key);
        }
    }

    if (!s.ip_assigned) {
        s.virtual_ip = allocate_virtual_ip(client_id);
        if (s.virtual_ip == 0) {
            fprintf(stderr, "[UDP][AUTH] 虚拟 IP 池已满，拒绝 %s\n", client_id.c_str());
            deny(0);
            return;
        }
        s.ip_assigned = true;
        {
            std::lock_guard<std::mutex> lock(m_vip_mutex);
            m_vip_to_key[s.virtual_ip] = s.peer_key;
        }
    }

    s.authenticated.store(true);
    s.handshaked.store(true);
    s.hs_stage.store(HS_STAGE_AUTHED);
    s.last_rx_ms.store(static_cast<int64_t>(now_ms()));
    uint8_t ok_payload[5] = {0};
    memcpy(ok_payload, &s.virtual_ip, 4);
    ok_payload[4] = static_cast<uint8_t>(m_tun_prefix);
    std::vector<uint8_t> sendbuf;
    if (!send_packet(s, static_cast<uint8_t>(m_identity_ok), ok_payload, sizeof(ok_payload), sendbuf)) {
        fprintf(stderr, "[UDP][AUTH] 发送 identity_ok 失败\n");
        return;
    }
    {
        char ipstr[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &s.virtual_ip, ipstr, sizeof(ipstr));
        fprintf(stderr, "[UDP][AUTH] 身份认证通过，放行 TUN 流量：id=%s vip=%s/%d (%s)\n",
                client_id.c_str(), ipstr, m_tun_prefix, s.peer_key.c_str());
    }
}

void UDP::heartbeat_work()
{
    const uint64_t timeout_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(kHeartbeatTimeout).count());
    const uint64_t hs_timeout_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(kHandshakeTimeout).count());
    auto next_due = std::chrono::steady_clock::now() + kHeartbeatInterval;
    int svc_flush_beats = 0;
    while (is_running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (!is_running())
            break;
        if (std::chrono::steady_clock::now() < next_due)
            continue;
        if (m_svc) {
            std::vector<std::shared_ptr<Session>> blk;
            {
                std::lock_guard<std::mutex> lock(m_sessions_mutex);
                for (auto& kv : m_sessions) {
                    if (kv.second->svc_managed && kv.second->svc_bytes.load() > 0) {
                        const long long d = kv.second->svc_bytes.exchange(0);
                        m_svc->add_used(kv.second->client_id, d);
                    }
                    if (!kv.second->client_id.empty() &&
                        m_svc->machine_blocked(kv.second->client_id)) {
                        blk.push_back(kv.second);
                    }
                }
            }
            for (auto& v : blk) {
                fprintf(stderr, "[SVC] 机器黑名单命中，切断会话 (id=%s)\n",
                        v->client_id.c_str());
                release_session(v->peer_key);
            }
            m_svc->flush();
            ++svc_flush_beats;
        }
        next_due = std::chrono::steady_clock::now() + kHeartbeatInterval;
        const uint64_t now = now_ms();
        std::vector<std::shared_ptr<Session>> sessions;
        {
            std::lock_guard<std::mutex> lock(m_sessions_mutex);
            sessions.reserve(m_sessions.size());
            for (auto& kv : m_sessions)
                sessions.push_back(kv.second);
        }
        for (auto& s : sessions) {
            auto destroy = [&](const char* why) {
                fprintf(stderr, "[UDP] %s，销毁会话 %s\n", why, s->peer_key.c_str());
                if (s->is_tcp)
                    s->tcp_drop.store(true);
                else
                    release_session(s->peer_key);
            };
            if (!s->authenticated.load()) {
                if (now - static_cast<uint64_t>(s->created_at_ms.load()) > hs_timeout_ms)
                    destroy("握手超时");
                continue;
            }
            const int64_t last = s->last_rx_ms.load();
            if (last != 0 && (now - static_cast<uint64_t>(last)) > timeout_ms) {
                destroy("heartbeat timeout");
                continue;
            }
            {
                const uint64_t age_ms = now - static_cast<uint64_t>(s->created_at_ms.load());
                if (age_ms > kSessionMaxLifetimeMs) {
                    fprintf(stderr, "[UDP] 会话时长达到上限（%llu 小时），换新会话重协商密钥: %s\n",
                            static_cast<unsigned long long>(kSessionMaxLifetimeMs / 3600000ull),
                            s->peer_key.c_str());
                    std::vector<uint8_t> bye_buf;
                    send_packet(*s, static_cast<uint8_t>(disconnect), nullptr, 0, bye_buf);
                    destroy("会话时长上限");
                    continue;
                }
            }
            std::vector<uint8_t> sendbuf;
            if (!send_packet(*s, static_cast<uint8_t>(m_heart), nullptr, 0, sendbuf)) {
                fprintf(stderr, "[UDP] send heartbeat failed: %s\n", s->peer_key.c_str());
            }
        }
    }
}

std::string UDP::to_hex(const uint8_t* data, size_t len)
{
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(hex[data[i] >> 4]);
        out.push_back(hex[data[i] & 0x0F]);
    }
    return out;
}

bool UDP::file_contains_line(const std::string& path, const std::string& line)
{
    FILE* f = std::fopen(path.c_str(), "r");
    if (f == nullptr)
        return false;
    ::flock(fileno(f), LOCK_SH);
    char buf[512] = {0};
    bool found = false;
    while (std::fgets(buf, sizeof(buf), f) != nullptr) {
        std::string s(buf);
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
            s.pop_back();
        if (s == line) {
            found = true;
            break;
        }
    }
    ::flock(fileno(f), LOCK_UN);
    std::fclose(f);
    return found;
}

bool UDP::file_append_line(const std::string& path, const std::string& line)
{
    FILE* f = std::fopen(path.c_str(), "a");
    if (f == nullptr)
        return false;
    ::flock(fileno(f), LOCK_EX);
    const bool ok = std::fprintf(f, "%s\n", line.c_str()) > 0;
    std::fflush(f);
    ::flock(fileno(f), LOCK_UN);
    std::fclose(f);
    return ok;
}

bool UDP::file_remove_line(const std::string& path, const std::string& line)
{
    return with_token_lock(path, [&]() -> bool {
        FILE* src = std::fopen(path.c_str(), "r");
        if (src == nullptr)
            return false;
        std::vector<std::string> keep;
        char buf[512] = {0};
        bool removed = false;
        while (std::fgets(buf, sizeof(buf), src) != nullptr) {
            std::string s(buf);
            while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
                s.pop_back();
            if (!removed && s == line) {
                removed = true;
                continue;
            }
            keep.push_back(s);
        }
        std::fclose(src);
        if (!removed)
            return false;

        const std::string tmp = path + ".tmp." + std::to_string(::getpid());
        FILE* dst = std::fopen(tmp.c_str(), "w");
        if (dst == nullptr) {
            fprintf(stderr, "[UDP] 写临时令牌文件 %s 失败: %s\n",
                    tmp.c_str(), strerror(errno));
            return false;
        }
        bool ok = true;
        for (const auto& s : keep) {
            if (std::fprintf(dst, "%s\n", s.c_str()) < 0) {
                ok = false;
                break;
            }
        }
        if (std::fflush(dst) != 0)
            ok = false;
        if (ok && ::fsync(fileno(dst)) != 0) {
            fprintf(stderr, "[UDP] fsync(%s) 失败: %s\n", tmp.c_str(), strerror(errno));
            ok = false;
        }
        std::fclose(dst);
        if (!ok) {
            ::unlink(tmp.c_str());
            return false;
        }
        if (::rename(tmp.c_str(), path.c_str()) != 0) {
            fprintf(stderr, "[UDP] rename(%s) 失败: %s\n", path.c_str(), strerror(errno));
            ::unlink(tmp.c_str());
            return false;
        }
        return true;
    });
}

bool UDP::start_threads()
{
    try {
        send_thread = std::thread(&UDP::send_work, this);
        recv_thread = std::thread(&UDP::recv_work, this);
        heartbeat_thread = std::thread(&UDP::heartbeat_work, this);
    } catch (const std::system_error& e) {
        fprintf(stderr, "[UDP] start_threads failed: %s\n", e.what());
        stop_threads();
        return false;
    }
    return true;
}

void UDP::stop_threads()
{
    if (send_thread.joinable())
        send_thread.join();
    if (recv_thread.joinable())
        recv_thread.join();
    if (heartbeat_thread.joinable())
        heartbeat_thread.join();
}
