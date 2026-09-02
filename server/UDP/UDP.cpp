#include "UDP.h"
#include "../Crypt/crypt.h"
#include "../core/log.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <optional>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <random>
#include <chrono>
#include <thread>

#include <openssl/rand.h>

// 数据包级日志开关：1=打印每个收发数据包（诊断用），0=只打关键事件（见 core/log.h）

namespace {

// 心跳保活参数
constexpr auto kHeartbeatInterval = std::chrono::seconds(10);   // 每 10s 发一次心跳
constexpr auto kHeartbeatTimeout  = std::chrono::seconds(30);   // 30s 未收到对端任何报文判失联
// 未认证（pending）会话独立防护：客户端连接失败/重试风暴不能占满整张会话表
constexpr auto kHandshakeTimeout  = std::chrono::seconds(10);   // 未认证会话 10s 未完成握手即清理
constexpr size_t kMaxPendingSessions = 32;                      // 未认证会话独立配额（不挤占已认证容量）
constexpr size_t kMaxSessionsPerIp   = 3;                       // 每来源 IP 最多同时持有的会话数

// 当前 steady_clock 毫秒时间戳
uint64_t now_ms()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}

// 密钥交换辅助（X25519 + HKDF + AES-256-GCM）

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

// 生成一次性临时 X25519 密钥对（每次会话独立，前向安全）
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

} // namespace

UDP::~UDP()
{
    stop();
    close();
}

// 会话管理
std::shared_ptr<Session> UDP::get_or_create_session(const sockaddr_in& addr)
{
    const std::string key = Session::peer_addr_to_key(addr);
    const std::string ip = key.substr(0, key.rfind(':'));
    std::lock_guard<std::mutex> lock(m_sessions_mutex);
    auto it = m_sessions.find(key);
    if (it != m_sessions.end())
        return it->second;

    // 未认证会话独立配额：连接失败/重试风暴的 pending 会话不能挤占已认证容量
    size_t pending = 0;
    for (auto& kv : m_sessions)
        if (!kv.second->handshaked.load())
            ++pending;
    if (pending >= kMaxPendingSessions) {
        fprintf(stderr, "[UDP] 未认证会话已达上限 %zu，丢弃新连接 %s\n",
                kMaxPendingSessions, key.c_str());
        return nullptr;
    }

    // 每 IP 会话数上限：客户端重试/伪造源都无法用同一来源占满会话表。
    // 超限时淘汰该 IP 最早的未认证会话（最新连接优先）；该 IP 全是已认证会话才拒绝
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
        m_sessions.erase(oldestPendingKey);
    }

    if (m_sessions.size() >= m_max_clients) {
        fprintf(stderr, "[UDP] 会话数已达上限 %zu，丢弃新连接 %s\n", m_max_clients, key.c_str());
        return nullptr;
    }
    auto s = std::make_shared<Session>(addr);
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
    if (victim->ip_assigned && victim->virtual_ip != 0) {
        release_virtual_ip(victim->virtual_ip);
    }
    victim->authenticated.store(false);
    victim->handshaked.store(false);
    fprintf(stderr, "[UDP] 会话 %s 已下线（剩余 %d）\n", key.c_str(), client_count());
}

// 虚拟 IP
uint32_t UDP::allocate_virtual_ip()
{
    if (!m_ip_pool)
        return 0;
    return m_ip_pool->allocate();
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

// 生命周期
bool UDP::start(const std::string& local_ip, uint16_t local_port,
                const std::string& tun_ip, int tun_prefix,
                size_t max_clients)
{
    if (is_running())
        return true;   // 已在运行
    m_max_clients = (max_clients > 0) ? max_clients : 64;
    m_tun_prefix = static_cast<uint8_t>((tun_prefix > 0 && tun_prefix <= 32) ? tun_prefix : 24);

    // 虚拟 IP 池：以服务端 TUN 地址为网关，在网段内分配
    uint32_t gw_net = inet_addr("10.8.0.1");
    if (!tun_ip.empty()) {
        in_addr a{};
        if (inet_pton(AF_INET, tun_ip.c_str(), &a) == 1)
            gw_net = a.s_addr;
    }
    m_ip_pool = std::make_shared<VirtualIpPool>(gw_net, m_tun_prefix);

    m_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (m_sock < 0) {
        fprintf(stderr, "[UDP] socket() failed: %s\n", strerror(errno));
        return false;
    }
    int reuse = 1;
    if (setsockopt(m_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        fprintf(stderr, "[UDP] setsockopt(SO_REUSEADDR) failed: %s\n", strerror(errno));
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
    // 非阻塞：让 recv_work 的 EAGAIN 分支生效，stop() 可快速退出
    int flags = fcntl(m_sock, F_GETFL, 0);
    if (flags != -1) {
        fcntl(m_sock, F_SETFL, flags | O_NONBLOCK);
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
    // 先置位停止标志，再 shutdown 唤醒可能阻塞的系统调用
    if (m_sock >= 0) {
        ::shutdown(m_sock, SHUT_RDWR);
    }
    stop_threads();
    close();
    // 清理全部会话（线程已回收，无并发）
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

void UDP::set_identity(std::shared_ptr<EVP_PKEY> sig_priv, const std::string& keys_dir)
{
    m_sig_priv = std::move(sig_priv);
    m_keys_dir = keys_dir;
    if (m_keys_dir.empty())
        m_keys_dir = "keys";
}

// 数据面 —— 下行数据流（服务器 → 客户端）：
//   内核把发给 10.8.0.x 的 IP 包送进 TUN → VpnCore 读 TUN → 本函数
//   解析 IPv4 目的地址 → 查"虚拟IP→会话"表 → 推入目标会话的发送队列
//   → send_work 线程加密后发往该客户端的 UDP 地址。
// 目的 IP 不在表里（未分配/客户端不在线）→ 丢弃。
bool UDP::forward_tun_packet(packet_buffer&& buf)
{
    if (!is_running() || buf.is_empty())
        return false;
    const uint8_t* d = buf.get_data();
    const size_t n = buf.data_size();
    if (n < 20)
        return false;                       // 最短 IPv4 头 20 字节
    if ((d[0] >> 4) != 4)
        return false;                       // 仅支持 IPv4
    const uint8_t ihl = d[0] & 0x0F;
    if (ihl < 5 || static_cast<size_t>(ihl) * 4 > n)
        return false;
    uint32_t dst_net = 0;                   // 目的 IP（网络字节序）
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
    return s->send_queue.push(std::move(buf));
}

bool UDP::recv_ip_packet(packet_buffer& buf)
{
    if (!is_running())
        return false;
    return m_queue_recv.pop(buf);
}

// 发送
// 通用发送；密钥/序号/目标地址取自 Session（多用户隔离）。
bool UDP::send_packet(Session& s, uint8_t type, const uint8_t* data, size_t len,
                      std::vector<uint8_t>& tmp_buf)
{
    if (len > VPN_MTU)
        return false;
    if (!is_running())
        return false;
    std::lock_guard<std::mutex> lock(s.send_mutex);

    size_t total_len = Ktunnel_header + len;
    tmp_buf.resize(total_len);
    tunnel_header hdr{};
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = Kmagic;
    hdr.version = Kversion;
    hdr.type = type;
    hdr.payload_len = htons(static_cast<uint16_t>(len));
    uint32_t seq = s.seq.fetch_add(1);
    hdr.sequence = htonl(seq);
    memcpy(tmp_buf.data(), &hdr, Ktunnel_header);

    // 数据面加密：m_data / m_heart / m_heart_response / m_identity 等在密钥就绪后以密文发送
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
        std::vector<uint8_t> inner;
        inner.reserve(1 + len);
        inner.push_back(type);
        if (len)
            inner.insert(inner.end(), data, data + len);
        // AAD = 实际发出的头部：先按密文长度更新 payload_len 再加密
        hdr.payload_len = htons(static_cast<uint16_t>(len + 1 + AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN));
        memcpy(tmp_buf.data(), &hdr, Ktunnel_header);
        std::vector<uint8_t> enc;
        try {
            enc = aes256_gcm_encrypt(s.key_s2c, inner.data(), inner.size(),
                                     tmp_buf.data(), Ktunnel_header);
        } catch (const std::exception& e) {
            fprintf(stderr, "[UDP] 加密失败: %s\n", e.what());
            return false;
        }
        if (Ktunnel_header + enc.size() > KMax_packet_size)
            return false;
        tmp_buf.resize(Ktunnel_header + enc.size());
        memcpy(tmp_buf.data() + Ktunnel_header, enc.data(), enc.size());
        total_len = Ktunnel_header + enc.size();
    } else {
        if (len)
            memcpy(tmp_buf.data() + Ktunnel_header, data, len);
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

void UDP::reply_heartbeat(Session& s)
{
    std::vector<uint8_t> sendbuf;
    send_packet(s, static_cast<uint8_t>(m_heart_response), nullptr, 0, sendbuf);
}

// 发送线程：遍历各会话发送队列，把 TUN 下行的 IP 包加密发给对应客户端
void UDP::send_work()
{
    std::vector<uint8_t> sendbuf;
    sendbuf.reserve(KMax_packet_size);
    packet_buffer buf;

    while (is_running()) {
        // 拷贝会话列表（避免遍历时持锁；会话被销毁后 shared_ptr 仍安全）
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
            if (!s->send_queue.pop(buf))
                continue;
            if (buf.is_empty())
                continue;
            const size_t pay_size = buf.data_size();
            if (pay_size > VPN_MTU) {
                buf.clear();
                continue;
            }
            if (g_packet_log) {
                fprintf(stderr, "[UDP][TX] 发送数据 len=%zu to %s\n", pay_size, s->peer_key.c_str());
            }
            if (!send_packet(*s, static_cast<uint8_t>(m_data), buf.get_data(), pay_size, sendbuf)) {
                fprintf(stderr, "[UDP] 发送数据失败: %s\n", s->peer_key.c_str());
            }
            buf.clear();
            any = true;
        }
        if (!any)
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

// 接收 —— 上行数据流 + 全部控制面（认证/心跳/断开）的唯一入口：
//   1) recvfrom 收包，校验魔数/版本/长度；
//   2) 按 (源IP,端口) 取/建 Session（新来源先建 pending 会话，达到 --max-clients 上限则丢弃）；
//   3) 密文类型（data/heart/identity…）用该会话的 key_c2s 解密，按内层类型分发：
//        data → 校验 authenticated 后推入全局接收队列（VpnCore 写入 TUN）
//        heart → 回 heart_response
//        identity → handle_identity()（阶段3 认证）
//   4) 明文类型（阶段1 认证消息 / disconnect）直接分发。
// 任何合法报文都会刷新 s.last_rx_ms（心跳超时判活的依据）。
void UDP::recv_work()
{
    std::vector<uint8_t> recvbuf;
    std::vector<uint8_t> sendbuf;
    recvbuf.reserve(KMax_packet_size + 64);
    sendbuf.reserve(KMax_packet_size);
    sockaddr_in peer_addr{};

    while (is_running()) {
        recvbuf.resize(KMax_packet_size);
        socklen_t peer_addr_size = sizeof(peer_addr);

        int ret = recvfrom(m_sock, recvbuf.data(), recvbuf.size(), 0,
                           reinterpret_cast<struct sockaddr*>(&peer_addr), &peer_addr_size);
        if (ret == 0) {
            // 零长度 UDP 数据报是合法报文：攻击者发一个空包不应打死收包线程
            continue;
        }
        if (ret < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;   // 非阻塞下无数据，短暂休眠后重试
            }
            // 瞬时错误（ENETUNREACH/ENOBUFS 等）：记日志后继续。
            // 绝不能 break——recv 线程退出后认证/转发/心跳全部停摆且 watchdog 无法感知
            fprintf(stderr, "[UDP] recvfrom() failed: %s\n", strerror(errno));
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        if (ret < static_cast<int>(Ktunnel_header))
            continue;   // 包太短

        tunnel_header hdr{};
        memcpy(&hdr, recvbuf.data(), Ktunnel_header);
        if (hdr.magic != Kmagic || hdr.version != Kversion)
            continue;
        size_t pay_len = ntohs(hdr.payload_len);
        if (pay_len > Max_payload_len || pay_len + Ktunnel_header > static_cast<size_t>(ret))
            continue;

        // 按源地址取/建会话（新来源创建 pending 会话；达到上限则丢弃）
        std::shared_ptr<Session> s = get_or_create_session(peer_addr);
        if (!s)
            continue;
        s->last_rx_ms.store(static_cast<int64_t>(now_ms()));   // 任何合法报文都视为对端存活
        if (g_packet_log) {
            char ipstr[INET_ADDRSTRLEN] = {0};
            inet_ntop(AF_INET, &peer_addr.sin_addr, ipstr, sizeof(ipstr));
            fprintf(stderr, "[UDP][RX] type=%d len=%zu from=%s:%u\n",
                    hdr.type, pay_len, ipstr, ntohs(peer_addr.sin_port));
        }
        const uint8_t* payload = recvbuf.data() + Ktunnel_header;

        // 加密类型：密钥就绪后 data/heart/identity/disconnect 均为密文
        if (hdr.type == static_cast<uint8_t>(m_data) ||
            hdr.type == static_cast<uint8_t>(m_heart) ||
            hdr.type == static_cast<uint8_t>(m_heart_response) ||
            hdr.type == static_cast<uint8_t>(m_identity) ||
            hdr.type == static_cast<uint8_t>(m_identity_ok) ||
            hdr.type == static_cast<uint8_t>(m_identity_deny) ||
            hdr.type == static_cast<uint8_t>(disconnect)) {
            if (!s->enc_ready.load()) {
                continue;   // 密钥未就绪，丢弃
            }
            std::vector<uint8_t> enc(payload, payload + pay_len);
            std::optional<std::vector<uint8_t>> plain;
            try {
                plain = aes256_gcm_decrypt(s->key_c2s, enc, recvbuf.data(), Ktunnel_header);
            } catch (const std::exception& e) {
                fprintf(stderr, "[UDP] 解密异常: %s\n", e.what());
                continue;
            }
            if (!plain) {
                continue;   // 认证失败，静默丢弃
            }
            uint8_t inner_type = 0;
            std::vector<uint8_t> inner_payload;
            if (!parse_inner_packet(*plain, inner_type, inner_payload))
                continue;
            switch (inner_type) {
            case m_data:
                if (inner_payload.empty())
                    break;
                if (!s->authenticated.load())
                    break;   // 身份未验证通过前禁止把数据转发进 TUN
                m_queue_recv.push(packet_buffer(std::move(inner_payload)));
                break;
            case m_heart:
                reply_heartbeat(*s);
                break;
            case m_heart_response:
                break;
            case m_identity:
                // 阶段3：身份报文（验签 + 注册/登录）
                handle_identity(*s, inner_payload);
                break;
            case m_identity_ok:
            case m_identity_deny:
                // 服务端角色不应收到这些，忽略
                break;
            case disconnect:
                // 客户端显式断开（密文内层）：立即释放会话，每源配额即时归还。
                // 注意 release_session 会把 s 从表中移除，之后不要再使用 s
                fprintf(stderr, "[UDP] 客户端断开: %s\n", s->peer_key.c_str());
                release_session(s->peer_key);
                break;
            default:
                break;
            }
            continue;
        }

        // 明文类型：阶段1 认证 / 断开
        switch (hdr.type) {
        case m_auth_hello:
            handle_auth_hello(*s, payload, pay_len);
            break;
        case m_auth_client_hello:
            handle_auth_client_hello(*s, payload, pay_len);
            break;
        case m_data: {
            // 明文数据兼容路径已删除：握手后的明文 m_data 可被伪造源地址
            // 未认证注入 TUN（高危）。数据面只接受 AES-256-GCM 密文（下方密文分支）。
            break;
        }
        case m_heart:
            reply_heartbeat(*s);
            break;
        case m_heart_response:
            break;
        case disconnect:
            // 明文 disconnect 已不再受理：伪造源地址可一包踢人。
            // 会话生命周期由心跳超时统一管理，无需显式断开消息
            break;
        default:
            break;
        }
    }
}

// 三阶段身份认证（Ed25519 + 临时X25519 + HKDF + AES-256-GCM）
// 阶段1 明文交换 nonce/临时DH 公钥并验签防中间人；阶段2 ECDH+HKDF 派生 key_tx/key_rx；
// 阶段3 密文身份报文验签后按注册（令牌）/登录（公钥比对）放行 TUN 流量。

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

    // 组装并发送 ServerHello：nonce_s || DH_SRV_EPHEM_PUB || sig_srv
    auto send_server_hello = [&]() -> bool {
        // sig_payload = nonce_c || nonce_s || DH_SRV_EPHEM_PUB，用 SIG_SRV_PRI 签名
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
        std::vector<uint8_t> reply;
        reply.reserve(KAuthServerHelloLen);
        reply.insert(reply.end(), s.nonce_s.begin(), s.nonce_s.end());
        reply.insert(reply.end(), s.dh_srv_pub.begin(), s.dh_srv_pub.end());
        reply.insert(reply.end(), sig.begin(), sig.end());
        std::vector<uint8_t> sendbuf;
        return send_packet(s, static_cast<uint8_t>(m_auth_server_hello), reply.data(), reply.size(), sendbuf);
    };

    // 同一会话的 auth_hello 重传（nonce_c 相同且会话已建立）：不重置状态，幂等重发同一 ServerHello。
    if (!s.nonce_c.empty() && s.nonce_c.size() == KAuthNonceLen &&
        std::memcmp(s.nonce_c.data(), payload, KAuthNonceLen) == 0 &&
        s.dh_srv_priv != nullptr && !s.nonce_s.empty() && !s.dh_srv_pub.empty()) {
        if (send_server_hello())
            fprintf(stderr, "[UDP][AUTH] auth_hello 重传：幂等重发 ServerHello\n");
        return;
    }

    // 已建立（握手/加密就绪/已认证）的会话收到"不同 nonce_c"的 auth_hello：
    // 伪造源地址可借此清空密钥、把合法客户端钉死在离线状态——拒绝重置。
    // （同一 nonce 走上面的幂等分支无害；客户端真实重连会换端口形成全新会话）
    if ((s.authenticated.load() || s.enc_ready.load() || s.handshaked.load()) &&
        !s.nonce_c.empty() && s.nonce_c.size() == KAuthNonceLen &&
        std::memcmp(s.nonce_c.data(), payload, KAuthNonceLen) != 0) {
        fprintf(stderr, "[UDP][AUTH] 已建立会话收到不同 nonce 的 auth_hello，拒绝重置 (%s)\n",
                s.peer_key.c_str());
        return;
    }

    // 新会话：重置上一会话的认证/密钥状态（客户端重连时不复用旧密钥）
    if (s.dh_srv_priv != nullptr) {
        EVP_PKEY_free(s.dh_srv_priv);
        s.dh_srv_priv = nullptr;
    }
    secure_wipe(s.key_c2s);
    secure_wipe(s.key_s2c);
    s.enc_ready.store(false);
    s.authenticated.store(false);
    s.handshaked.store(false);
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
    if (s.dh_srv_priv == nullptr || s.nonce_c.empty() || s.nonce_s.empty()) {
        fprintf(stderr, "[UDP][AUTH] 会话状态不完整（未先收到 auth_hello）\n");
        return;
    }
    s.dh_cli_pub.assign(payload, payload + KAuthDhPubLen);

    // 阶段2：X25519 ECDH 计算共享秘密
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

    // HKDF：Extract(salt=nonce_c||nonce_s, IKM=ss) → prk → Expand 出 key_tx/key_rx
    try {
        DirectionalSessionKeys keys = derive_directional_session_keys(ss, s.nonce_c, s.nonce_s);
        secure_wipe(ss);
        s.key_c2s = std::move(keys.key_tx);   // 客户端→服务端（接收解密）
        s.key_s2c = std::move(keys.key_rx);   // 服务端→客户端（发送加密）
    } catch (const std::exception& e) {
        secure_wipe(ss);
        fprintf(stderr, "[UDP][AUTH] 会话密钥派生失败: %s\n", e.what());
        return;
    }
    s.enc_ready.store(true);
    fprintf(stderr, "[UDP][AUTH] 加密隧道已建立（阶段2完成，等待身份报文）%s\n", s.peer_key.c_str());
}

// 阶段3：身份报文（AES-GCM 密文内层，已解密）
// body = [flags(1: 0=登录 1=注册)] [token_len(1)] [token?] [identity_payload] [sig_cli(64)]
// identity_payload = nonce_c(16) || nonce_s(16) || dh_cli_pub(32) || dh_srv_pub(32)
//                    || sig_cli_pub(32) || id_len(1) || client_id
// 校验流程（顺序执行，任一失败即 deny 断开）：
//   1) 长度/字段完整性检查
//   2) 会话绑定检查：报文里的 nonce/DH 公钥必须与本会话一致（防跨会话重放）
//   3) 用报文携带的 cli_pub 验证 sig_cli 签名（证明持有对应私钥）
//   4) 注册分支：校验 register_token（一次性，用后从 register_tokens.txt 移除），
//      把客户端公钥写入 registered_clients.txt；
//      登录分支：在 registered_clients.txt 里比对公钥
//   5) 通过 → 分配虚拟 IP → 回 identity_ok（携带 [ip(4)][prefix(1)]）→ 放行
void UDP::handle_identity(Session& s, const std::vector<uint8_t>& inner)
{
    // 已认证会话再次收到身份报文 = 客户端在首次成功确认前发出的重传，直接忽略。
    if (s.authenticated.load()) {
        return;
    }
    // identity_deny 携带 1 字节原因码（密文内层）：
    //   0 = 身份未注册 / 签名失败等（登录类失败）
    //   1 = 注册令牌无效或已使用（注册类失败）
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

    // 重建 identity_payload（与客户端组装规则完全一致）
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

    // 会话绑定检查：全部会话上下文必须与本会话一致
    if (nc != s.nonce_c || ns != s.nonce_s || dc != s.dh_cli_pub || ds != s.dh_srv_pub) {
        fprintf(stderr, "[UDP][AUTH] 身份报文会话上下文不匹配，拒绝\n");
        deny(0);
        return;
    }

    // 校验 sig_cli
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

    // 注册 / 登录分支
    const std::string cli_pub_hex = to_hex(cli_pub.data(), cli_pub.size());
    const std::string clients_path = m_keys_dir + "/registered_clients.txt";
    const std::string tokens_path  = m_keys_dir + "/register_tokens.txt";
    if (flags == 1) {
        // 注册分支：校验一次性令牌，写入数据库，令牌作废
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
        // 登录分支：数据库比对 SIG_CLI_PUB
        if (!file_contains_line(clients_path, cli_pub_hex)) {
            fprintf(stderr, "[UDP][AUTH] 未注册的客户端身份，拒绝登录\n");
            deny(0);
            return;
        }
        fprintf(stderr, "[UDP][AUTH] 客户端登录成功 id=%s (%s)\n", client_id.c_str(), s.peer_key.c_str());
    }
    s.client_id = client_id;
    s.cli_pub_hex = cli_pub_hex;

    // 同身份重复登录：踢掉旧的在线会话（同一 client_id 只保留最新）
    {
        std::vector<std::string> to_kill;
        {
            std::lock_guard<std::mutex> lock(m_sessions_mutex);
            for (auto& kv : m_sessions) {
                if (kv.second.get() != &s && kv.second->client_id == s.client_id)
                    to_kill.push_back(kv.first);
            }
        }
        for (auto& k : to_kill)
            release_session(k);
    }

    // 分配虚拟 IP（多用户唯一地址；认证通过后才分配）
    if (!s.ip_assigned) {
        s.virtual_ip = allocate_virtual_ip();
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

    // 全部校验通过 → 放行 TUN 业务流量，并通告分配的虚拟 IP
    s.authenticated.store(true);
    s.handshaked.store(true);
    s.last_rx_ms.store(static_cast<int64_t>(now_ms()));
    // identity_ok payload: [virtual_ip(4, 网络序)] [prefix(1)]
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

// 心跳保活
void UDP::heartbeat_work()
{
    const uint64_t timeout_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(kHeartbeatTimeout).count());
    const uint64_t hs_timeout_ms = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(kHandshakeTimeout).count());
    while (is_running()) {
        std::this_thread::sleep_for(kHeartbeatInterval);
        if (!is_running())
            break;
        const uint64_t now = now_ms();
        std::vector<std::shared_ptr<Session>> sessions;
        {
            std::lock_guard<std::mutex> lock(m_sessions_mutex);
            sessions.reserve(m_sessions.size());
            for (auto& kv : m_sessions)
                sessions.push_back(kv.second);
        }
        for (auto& s : sessions) {
            // 未完成身份验证的会话：10s 清理（含走到阶段2但被拒/放弃的——
            // 这些僵尸会话若按心跳超时算会滞留 30s 占满每源配额）
            if (!s->authenticated.load()) {
                if (now - static_cast<uint64_t>(s->created_at_ms.load()) > hs_timeout_ms) {
                    fprintf(stderr, "[UDP] 握手超时，销毁未认证会话 %s\n", s->peer_key.c_str());
                    release_session(s->peer_key);
                }
                continue;
            }
            // 认证会话：心跳超时 → 判失联销毁
            const int64_t last = s->last_rx_ms.load();
            if (last != 0 && (now - static_cast<uint64_t>(last)) > timeout_ms) {
                fprintf(stderr, "[UDP] heartbeat timeout, destroy session %s\n", s->peer_key.c_str());
                release_session(s->peer_key);
                continue;
            }
            // 主动发送心跳
            std::vector<uint8_t> sendbuf;
            if (!send_packet(*s, static_cast<uint8_t>(m_heart), nullptr, 0, sendbuf)) {
                fprintf(stderr, "[UDP] send heartbeat failed: %s\n", s->peer_key.c_str());
            }
        }
    }
}

// 注册/登录数据库（文本文件）
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
    std::fclose(f);
    return found;
}

bool UDP::file_append_line(const std::string& path, const std::string& line)
{
    FILE* f = std::fopen(path.c_str(), "a");
    if (f == nullptr)
        return false;
    const bool ok = std::fprintf(f, "%s\n", line.c_str()) > 0;
    std::fclose(f);
    return ok;
}

// 删除一行（用于作废一次性注册令牌）；返回是否真的删除了一行
bool UDP::file_remove_line(const std::string& path, const std::string& line)
{
    FILE* f = std::fopen(path.c_str(), "r");
    if (f == nullptr)
        return false;
    std::vector<std::string> keep;
    char buf[512] = {0};
    bool removed = false;
    while (std::fgets(buf, sizeof(buf), f) != nullptr) {
        std::string s(buf);
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
            s.pop_back();
        if (!removed && s == line) {
            removed = true;   // 匹配到令牌：丢弃该行（作废）
            continue;
        }
        keep.push_back(s);
    }
    std::fclose(f);

    FILE* out = std::fopen(path.c_str(), "w");
    if (out == nullptr)
        return false;
    for (const auto& s : keep) {
        std::fprintf(out, "%s\n", s.c_str());
    }
    std::fclose(out);
    return removed;
}

// 线程管理
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
