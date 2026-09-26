#include "UDP.h"
#include "../Crypt/crypt.h"
#include "../core/log.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
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

// 数据包级日志开关：1=打印每个收发数据包（诊断用），0=只打关键事件（见 core/log.h）

namespace {

// 注册/登录数据库（registered_clients.txt / register_tokens.txt）的
// 进程内互斥：UDP recv 线程与 TCP epoll 线程都可能执行注册/登录；
// "令牌消费 + 客户端登记"必须作为整体串行（配合文件级 flock 防跨进程竞争）
static std::mutex g_keys_db_mutex;

// 跨进程令牌锁：所有写 register_tokens.txt 的进程（服务端消费令牌、
// 管理员 --gen-token 追加）都先 flock <tokens>.lock 再操作，令牌文件
// 本体以"临时文件 + rename"原子替换——进程崩溃不会留下半截文件，
// 并发追加也不会被截断丢失
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

// 心跳保活参数
constexpr auto kHeartbeatInterval = std::chrono::seconds(10);   // 每 10s 发一次心跳
constexpr auto kHeartbeatTimeout  = std::chrono::seconds(30);   // 30s 未收到对端任何报文判失联
// 未认证（pending）会话独立防护：客户端连接失败/重试风暴不能占满整张会话表
// 30s（原 10s）太紧：整条握手链要跑 auth_hello→ServerHello→auth_client_hello
// →identity（再回 identity_ok），手机在移动网下 RTT 常达 2~4s、还有丢包重传，
// 实测一次成功握手要 3~4s（日志里 22411 会话重传 7 轮才走完），10s 会把
// 慢链路客户端的会话在握手途中清掉——客户端随后拿着旧 nonce 继续握手，
// 服务端已是新会话（新 nonce），最终"会话上下文不匹配"被拒。
// 放宽后资源仍受限：未认证会话另有 32 条全局配额 + 每源 3 条上限（超限先淘汰
// 最早的未认证会话），单个手机重连风暴最多占 3 条 pending。
constexpr auto kHandshakeTimeout  = std::chrono::seconds(30);   // 未认证会话 30s 未完成握手即清理
constexpr size_t kMaxPendingSessions = 32;                      // 未认证会话独立配额（不挤占已认证容量）
constexpr size_t kMaxSessionsPerIp   = 3;                       // 每来源 IP 最多同时持有的会话数

// 单套会话密钥的寿命上限（毫秒）：到期由 heartbeat_work 主动换会话（客户端重连
// 即重新握手、全新密钥）。本协议没有 in-protocol rekey，用这条给前向安全窗口
// 设上界——否则一条长连接（序号上限 2^31 包 ≈ 3TB）可以用同一套密钥跑很多天。
// 24h 一次、重连约 0.3s，对使用者几乎无感。
constexpr uint64_t kSessionMaxLifetimeMs = 24ull * 60ull * 60ull * 1000ull;

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
std::shared_ptr<Session> UDP::get_or_create_session(const sockaddr_in& addr, bool tcp)
{
    const std::string key = Session::peer_addr_to_key(addr, tcp);
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
        // 淘汰必须走统一断开流程：被淘汰的 TCP 会话置 tcp_drop 交 epoll
        // 线程 close（否则连接滞留在 TCPServer 内，逃过心跳/握手超时清理，
        // 持续消耗 fd 与内存）；UDP 会话无连接，仅摘表。
        // 注意：本函数持有 m_sessions_mutex，不能直接调 release_session（会自锁），
        // 因此在这里补上同样的收尾——归还虚拟 IP + 置失效标志。否则"已分配 IP 但
        // handshaked 尚未置位"的会话被摘表后，那个地址会永远留在池里（慢慢耗尽
        // /24 地址池，最终所有新连接都拿不到 IP = 连不上）
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
    if (victim->ip_assigned && victim->virtual_ip != 0) {
        release_virtual_ip(victim->virtual_ip);
    }
    // 摘表后立刻让会话"失效"：released 让后续帧在下发入口直接丢弃（TCP 连接可能
    // 还挂着几十毫秒），enc_ready=false 让密文帧连解密都不做——否则僵尸会话能重新
    // 走完握手再占一个虚拟 IP（池泄漏），或与踢它的新会话抢同一个地址
    victim->released.store(true);
    victim->enc_ready.store(false);
    victim->authenticated.store(false);
    victim->handshaked.store(false);
    victim->hs_stage.store(HS_STAGE_NONE);
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

// 握手重算限速（令牌桶，按来源 IP 网络序）。
// 只有"新 nonce 的 auth_hello"会走到调用点：它要生成临时 X25519 密钥对 +
// 做一次 Ed25519 签名（都是 CPU 开销），伪造源地址狂刷这类包既是 CPU 放大，
// 也是"小请求换大响应"的反射放大（28B 请求 → 124B ServerHello，约 4.4×）。
// 同一 nonce 的重传走幂等分支（查表 + 重发缓存的 ServerHello），不消耗令牌，
// 所以合法客户端 500ms 重传完全不受影响；正常客户端每次连接最多消耗 1 个令牌。
// 参数取 20 次/秒、突发 40：人类操作/客户端重连（最多几秒一次）永远打不到，
// 单 IP 的自动化洪泛被压到每秒 20 次以内（分布式洪泛需上游清洗，见 README 部署建议）。
bool UDP::allow_handshake_recompute(uint32_t ip_net)
{
    constexpr double kRatePerSec = 20.0;
    constexpr double kBurst = 40.0;
    const int64_t now = static_cast<int64_t>(now_ms());

    std::lock_guard<std::mutex> lock(m_hs_rl_mutex);
    // 表大小兜底：恶意源 IP 太多时清掉闲置项，仍过大就整体清空（等价全部重新给满桶），
    // 保证限速表本身不会被撑爆内存
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
        b.tokens = kBurst;   // 首次见到的来源：满桶
        b.last_ms = now;
    }
    const double elapsed = static_cast<double>(now - b.last_ms) / 1000.0;
    b.tokens += elapsed * kRatePerSec;
    if (b.tokens > kBurst)
        b.tokens = kBurst;
    b.last_ms = now;
    if (b.tokens < 1.0) {
        ++b.logged;
        // 每 IP 最多报 3 条，避免被刷屏
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

// 生命周期
bool UDP::start(const std::string& local_ip, uint16_t local_port,
                const std::string& tun_ip, int tun_prefix,
                size_t max_clients, bool udp_enabled)
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
        // 放大收发缓冲：普通 SO_RCVBUF/SO_SNDBUF 会被内核静默钳制到
        // net.core.rmem_max / wmem_max（默认仅 ~208KB，写的 4MB 根本不生效）！
        // 服务端以 root 运行：优先用 *_FORCE 强制生效，失败再退回普通调用。
        // 8MB 足以吸收 1Gbps×~50ms RTT 的带宽延迟积
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
            // inet_pton 返回 1=成功 0=格式非法 -1=地址族错误；两者都必须视为失败
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
    } else {
        // --transport tcp：不绑定 UDP socket（m_sock = -1，recv_work 空转待命）；
        // 会话/认证/加密/心跳机制照常服务 TCP 会话
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
    if (!s->send_queue.push(std::move(buf))) {
        // 发送队列满：该客户端持续消费不动（TCP 对端不收 / 链路劣化）。
        // 按既定策略直接断开而非无限堆积——否则内存无界增长，且
        // TCP-over-TCP 队头阻塞会把其他会话一起拖死。
        // TCP 交 epoll 线程统一 close（fd 唯一 owner），UDP 无连接直接释放
        fprintf(stderr, "[UDP] 发送队列满，断开会话 %s\n", s->peer_key.c_str());
        if (s->is_tcp)
            s->tcp_drop.store(true);   // epoll 线程收尾时 close + release_session
        else
            release_session(key);
        return false;
    }
    wake_send_waiters();   // 有下行数据：精确唤醒 send_work（无 sleep 轮询）
    return true;
}

// 队列消费者唤醒：入队后置标志并 notify，等待方用带谓词的 wait_for
// 在锁内检查标志，杜绝"先判空再睡"的丢失唤醒窗口
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

// 发送
// 通用发送；密钥/序号/目标地址取自 Session（多用户隔离）。
// UDP：sendto 数据报；TCP：已加密整帧入会话 tcp_tx 队列，由 TCPServer
// 事件线程统一写 socket（EPOLLOUT 驱动），本线程永不阻塞在慢对端上
bool UDP::send_packet(Session& s, uint8_t type, const uint8_t* data, size_t len,
                      std::vector<uint8_t>& tmp_buf)
{
    // 数据面明文载荷统一按 KMax_data_payload(1400) 限长：密文封装后不超过 Max_payload_len(1429)，
    // 与客户端 send_packet 的入口检查一致
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
    // 版本字节即传输标识：TCP 会话标 v_tcp，UDP 会话标 v_udp
    hdr.version = s.is_tcp ? static_cast<uint8_t>(v_tcp)
                           : static_cast<uint8_t>(v_udp);
    hdr.type = type;
    hdr.payload_len = htons(static_cast<uint16_t>(len));
    uint32_t seq = s.seq.fetch_add(1);
    // 序号安全上限：达到 2^31 强制断开换会话（重连=新密钥=新反重放窗口），
    // 防止 32 位序号回绕后被滑窗误判；返回 false 让上层走超时清理
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
        // AAD = 实际发出的头部：先按密文长度更新 payload_len 再加密。
        // 零临时 vector：内层 type 字节作第一段明文、载荷作第二段直接加密，
        // 输出（nonce||ct||tag）直写 tmp_buf 帧头之后。
        // 注意必须先按密文尺寸扩容：out_cap = 明文长度会把 seal 撑爆
        // （曾因此所有密文发送抛 length_error，客户端永远收不到 identity_ok）
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
        // 已加密整帧入队：TCPServer 事件线程是 socket 唯一写者。
        // 积压超限（慢客户端持续不收）= 断开连接（与 send_queue 满同策略），
        // 绝不阻塞发送线程——共享发送线程/心跳线程被一个慢对端拖 5s
        // 是原 send_all_fd 轮询模型的头号吞吐瓶颈
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
            s.tcp_drop.store(true);   // epoll 线程收尾时 close + release_session
            return false;
        }
        tcp_tx_wake();   // eventfd 唤醒事件线程排空队列
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

// 隧道内 IP 包合法性 + 源地址绑定检查（防已认证客户端冒用他人虚拟 IP）：
// 仅 IPv4；IHL 合法；总长字段与实际载荷一致；源 IP == 会话分配的 virtual_ip
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

// 被 tunnel_packet_source_ok 拒绝的【具体原因】（只在拒绝路径调用，不在热路径）：
// 把"源地址不等于本会话虚拟 IP"与"包本身不合法（非 IPv4 / IHL / 总长字段）"分开报。
// 两种原因原先共用一条"拒绝冒用源地址"日志，排查时会把方向带偏——看到它未必是
// 源地址问题，也可能是客户端把非 IPv4 包塞进了隧道。
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
            // 每会话本轮最多排空 64 包：持续下载时不再"每轮只发 1 包"
            // （高负载下吞吐被遍历节奏限制），同时预算防热会话饿死其他会话
            for (int n = 0; n < 64 && s->send_queue.pop(buf); ++n) {
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
                    // TCP 连接级失败已在 send_packet 内标记 tcp_drop（epoll 线程断开）
                    fprintf(stderr, "[UDP] 发送数据失败: %s\n", s->peer_key.c_str());
                }
                buf.clear();
                any = true;
            }
        }
        if (!any) {
            // 无下行数据：条件等待 TUN 入队唤醒（事件驱动，替代 1ms sleep 轮询）；
            // 200ms 超时兜底检查 is_running
            std::unique_lock<std::mutex> lk(m_wake_mutex);
            m_send_cv.wait_for(lk, std::chrono::milliseconds(200),
                               [this] { return m_send_wake || !is_running(); });
            m_send_wake = false;
        }
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
        // --transport tcp 模式：无 UDP socket，本线程空转待命（200ms 醒来检查停止）
        if (m_sock < 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }
        // poll 短超时等数据（非阻塞 socket + 事件驱动，替代 1ms sleep 轮询）：
        // 数据到达立即唤醒，超时回循环头检查 is_running
        struct pollfd pfd{};
        pfd.fd = m_sock;
        pfd.events = POLLIN;
        const int pr = poll(&pfd, 1, 200);
        if (pr <= 0)
            continue;   // 超时/被信号打断/停止唤醒：回循环头检查 is_running
        if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))
            continue;

        // 批处理：一次 poll 唤醒后排空内核接收缓冲（突发流量下把 N 次
        // poll+recvfrom 压成 1 次 poll + N 次 recvfrom，降低系统调用开销）。
        // 每轮上限 64 包：给心跳/停止检查留节奏，也防止单连接长期独占收包线程
        for (int budget = 0; budget < 64 && is_running(); ++budget) {
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
                    break;   // 内核缓冲已排空：回 poll 等下一批
                }
                // 瞬时错误（ENETUNREACH/ENOBUFS 等）：记日志后继续。
                // 绝不能 break——recv 线程退出后认证/转发/心跳全部停摆且 watchdog 无法感知
                fprintf(stderr, "[UDP] recvfrom() failed: %s\n", strerror(errno));
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                break;
            }
            if (ret < static_cast<int>(Ktunnel_header))
                continue;   // 包太短

            tunnel_header hdr{};
            memcpy(&hdr, recvbuf.data(), Ktunnel_header);
            // 注意：版本字段在此不校验——TCP 帧标 v_tcp、UDP 标 v_udp，
            // 由 handle_framed 按会话传输类型（expect_ver）统一校验
            if (hdr.magic != Kmagic)
                continue;
            size_t pay_len = ntohs(hdr.payload_len);
            if (pay_len > Max_payload_len || pay_len + Ktunnel_header > static_cast<size_t>(ret))
                continue;

            // 按源地址取/建会话（新来源创建 pending 会话；达到上限则丢弃）
            std::shared_ptr<Session> s = get_or_create_session(peer_addr, false);
            if (!s)
                continue;
            // 任何合法报文都视为对端存活 + 解密分发/阶段1握手：UDP 与 TCP 两条路径共用
            handle_framed(*s, hdr, recvbuf.data() + Ktunnel_header, pay_len);
        }
    }
}

// 处理一条已分帧的完整消息（UDP recv 循环与 TCPServer 共用）：
// 明文阶段1认证 / 密文解密分发（data/heart/identity/disconnect）。
// TCP 会话（s.tcp_fd >= 0）按 v_tcp 校验/标记版本，UDP 会话按 v_udp
void UDP::handle_framed(Session& s, const tunnel_header& hdr,
                        const uint8_t* payload, size_t pay_len)
{
    // 存活时间不再在此处无条件刷新：未认证报文（伪造/扫描）不应阻止
    // 心跳超时清理；已认证报文在解密成功后才刷新 last_rx_ms
    if (g_packet_log) {
        char ipstr[INET_ADDRSTRLEN] = {0};
        inet_ntop(AF_INET, &s.peer_addr.sin_addr, ipstr, sizeof(ipstr));
        fprintf(stderr, "[UDP][RX] type=%d len=%zu from=%s (tcp=%d)\n",
                hdr.type, pay_len, s.peer_key.c_str(), s.is_tcp ? 1 : 0);
    }
    // 已下线会话（release_session 后 TCP 连接可能还挂着几十毫秒）：到达的帧一律丢弃。
    // 否则一个明文 auth_hello 就能让僵尸会话重新走完握手、再占一个虚拟 IP
    if (s.released.load()) {
        return;
    }

    // 期望的协议版本：按会话传输类型区分（错误传输的报文在此被丢弃）；
    // 传输类型随会话创建固定（会话键含协议，TCP/UDP 不会混用同一会话）
    const uint8_t expect_ver = s.is_tcp ? static_cast<uint8_t>(v_tcp)
                                        : static_cast<uint8_t>(v_udp);
    if (hdr.version != expect_ver) {
        fprintf(stderr, "[UDP] 协议版本不匹配: 收到 v%u 期望 v%u (%s)，丢弃\n",
                static_cast<unsigned>(hdr.version), static_cast<unsigned>(expect_ver),
                s.peer_key.c_str());
        return;
    }
    // AAD = 本帧帧头起始地址（UDP = 数据报起始；TCP = 接收缓冲中帧起始），
    // 两条路径均满足 payload - Ktunnel_header
    const uint8_t* aad = payload - Ktunnel_header;

    // 加密类型：密钥就绪后 data/heart/identity/disconnect 均为密文
    if (hdr.type == static_cast<uint8_t>(m_data) ||
        hdr.type == static_cast<uint8_t>(m_heart) ||
        hdr.type == static_cast<uint8_t>(m_heart_response) ||
        hdr.type == static_cast<uint8_t>(m_identity) ||
        hdr.type == static_cast<uint8_t>(m_identity_ok) ||
        hdr.type == static_cast<uint8_t>(m_identity_deny) ||
        hdr.type == static_cast<uint8_t>(disconnect)) {
        if (!s.enc_ready.load()) {
            return;   // 密钥未就绪，丢弃
        }
        const uint32_t seq_host = ntohl(hdr.sequence);
        // 反重放分两步：解密前只做"不修改状态"的过旧预检（未认证报文
        // 不能污染窗口——伪造高序号会把窗口推高，后续合法报文被误判太旧）；
        // GCM 验证成功后才提交窗口
        if (s.replay.too_old(seq_host)) {
            if (g_packet_log) {
                fprintf(stderr, "[UDP] 过旧帧丢弃 seq=%u (%s)\n", seq_host, s.peer_key.c_str());
            }
            return;
        }
        // 零临时 vector：密文段（nonce||ct||tag）直接从接收缓冲解密到栈上
        // 明文缓冲（内层明文 = type(1)+载荷 ≤ KMax_data_payload）。tag 校验
        // 失败 = 静默丢弃（不推进窗口、不刷新存活）
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
            // 认证失败（GCM tag 不匹配 / 密钥不一致）：不推进窗口、不刷新存活。
            // 限流报前 3 条——静默丢弃会让"密钥不匹配"看起来和"对端不可达"一样
            const uint32_t n = s.auth_fail_logged.fetch_add(1);
            if (n < 3) {
                fprintf(stderr, "[UDP] 密文帧认证失败（密钥不匹配/帧被篡改），丢弃 (%s)%s\n",
                        s.peer_key.c_str(), (n == 2) ? "（同类日志已抑制）" : "");
            }
            return;
        }
        // 验证通过才提交窗口与存活时间（提交在单会话接收路径上天然串行）
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
                break;   // 身份未验证通过前禁止把数据转发进 TUN
            // 源地址绑定：隧道内 IP 包的源 IP 必须等于该会话分配的虚拟 IP，
            // 防止已认证客户端冒用其他虚拟地址（破坏用户隔离/源地址 ACL）
            {
                std::vector<uint8_t> pkt(inner_data, inner_data + inner_len);
                if (!tunnel_packet_source_ok(s, pkt)) {
                    // 限流：每会话最多详报 3 条（持续发错包时日志会被刷爆），
                    // 但必须打出【具体原因】——是源地址不匹配，还是包本身不合法，
                    // 决定了该改客户端网卡地址还是查客户端的发包路径
                    const uint32_t n = s.src_reject_logged.fetch_add(1);
                    if (n < 3) {
                        const std::string why = tunnel_packet_reject_reason(s, pkt);
                        fprintf(stderr, "[UDP] 拒绝上行数据包 (%s): %s%s\n",
                                s.peer_key.c_str(), why.c_str(),
                                (n == 2) ? "（同类日志已抑制）" : "");
                    }
                    break;
                }
                if (m_queue_recv.push(packet_buffer(std::move(pkt))))
                    wake_recv_waiters();   // 上行入队：精确唤醒 VpnCore 转发线程
            }
            break;
        case m_heart:
            reply_heartbeat(s);
            break;
        case m_heart_response:
            break;
        case m_identity:
            // 阶段3：身份报文（验签 + 注册/登录）
            handle_identity(s,
                            std::vector<uint8_t>(inner_data, inner_data + inner_len));
            break;
        case m_identity_ok:
        case m_identity_deny:
            // 服务端角色不应收到这些，忽略
            break;
        case disconnect:
            // 客户端显式断开（密文内层）：立即释放会话，每源配额即时归还。
            // TCP 连接同时标记断开：epoll 线程统一 close（fd 唯一 owner），
            // 不留"会话已释放、连接还挂着"的僵尸
            fprintf(stderr, "[UDP] 客户端断开: %s\n", s.peer_key.c_str());
            if (s.is_tcp)
                s.tcp_drop.store(true);   // epoll 线程收尾时 close + release_session
            else
                release_session(s.peer_key);
            break;
        default:
            break;
        }
        return;
    }

    // 明文类型：阶段1 认证 / 断开
    switch (hdr.type) {
    case m_auth_hello:
        handle_auth_hello(s, payload, pay_len);
        break;
    case m_auth_client_hello:
        handle_auth_client_hello(s, payload, pay_len);
        break;
    case m_data: {
        // 明文数据兼容路径已删除：握手后的明文 m_data 可被伪造源地址
        // 未认证注入 TUN（高危）。数据面只接受 AES-256-GCM 密文（上方密文分支）。
        break;
    }
    case m_heart:
        reply_heartbeat(s);
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
    // 签名结果按会话缓存（Ed25519 确定性签名，同会话 nonce/临时公钥不变）：
    // 重传路径只做查表+重发，不再逐帧重算签名（见 Session::server_hello_payload）
    auto send_server_hello = [&]() -> bool {
        if (s.server_hello_payload.size() != KAuthServerHelloLen) {
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

    // 已认证会话：拒绝一切明文握手——防止攻击者观察握手后注入明文报文
    // 覆盖密钥/重置状态，继承原会话的认证状态
    if (s.hs_stage.load() >= HS_STAGE_AUTHED || s.authenticated.load()) {
        fprintf(stderr, "[UDP][AUTH] 已认证会话拒绝明文 auth_hello (%s)\n", s.peer_key.c_str());
        return;
    }

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
    if ((s.hs_stage.load() >= HS_STAGE_KEYS || s.authenticated.load() ||
         s.enc_ready.load() || s.handshaked.load()) &&
        !s.nonce_c.empty() && s.nonce_c.size() == KAuthNonceLen &&
        std::memcmp(s.nonce_c.data(), payload, KAuthNonceLen) != 0) {
        fprintf(stderr, "[UDP][AUTH] 已建立会话收到不同 nonce 的 auth_hello，拒绝重置 (%s)\n",
                s.peer_key.c_str());
        return;
    }

    // 走到这里 = 要为一个"新 nonce 的 auth_hello"重算握手（临时密钥对 + 签名）。
    // 先过按源 IP 的令牌桶：合法客户端每次连接只消耗 1 个令牌（重传走上面的
    // 幂等分支），伪造源地址狂刷则被压制，避免 CPU/反射放大
    if (!allow_handshake_recompute(s.peer_addr.sin_addr.s_addr))
        return;

    // 新会话：重置上一会话的认证/密钥状态（客户端重连时不复用旧密钥）
    if (s.dh_srv_priv != nullptr) {
        EVP_PKEY_free(s.dh_srv_priv);
        s.dh_srv_priv = nullptr;
    }
    secure_wipe(s.key_c2s);
    secure_wipe(s.key_s2c);
    s.server_hello_payload.clear();   // 旧 ServerHello 签名缓存随 nonce/临时公钥一起作废
    s.enc_ready.store(false);
    s.authenticated.store(false);
    s.handshaked.store(false);
    s.hs_stage.store(HS_STAGE_HELLO);   // 阶段机：进入握手阶段1
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
    // 阶段机限制：auth_client_hello 只允许在"已发 ServerHello、密钥未派生"
    // 的阶段出现。已认证/已派生密钥的会话拒绝——否则攻击者观察握手后注入
    // 自己的临时公钥即可覆盖会话密钥并继承认证状态（严重缺陷）。
    // 客户端不重传 auth_client_hello，因此无需幂等重算分支。
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
    // 阶段2 完成：密钥已派生，服务端临时私钥立即销毁（前向安全，
    // 且保证阶段机推进后不可能再重算/重置密钥）
    if (s.dh_srv_priv != nullptr) {
        EVP_PKEY_free(s.dh_srv_priv);
        s.dh_srv_priv = nullptr;
    }
    s.hs_stage.store(HS_STAGE_KEYS);
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
    // 已认证会话再次收到身份报文 = 客户端没收到上一次 identity_ok 的【重传】。
    // 必须幂等重发 identity_ok，不能静默忽略：identity_ok 是单个报文（UDP 会丢），
    // 一旦丢失，客户端按 500ms 间隔重传至 10 次 / 5s 超时 —— 那次握手必然失败，
    // 表现为"连上（阶段2/3 走完）之后立刻断开重连"。阶段1 的 ServerHello 已是
    // 幂等重发语义，阶段3 与此保持一致。
    // 安全性：本帧先通过 AES-GCM 验证与反重放窗口才会走到这里（旧序号帧已在
    // handle_framed 被丢弃），只有持有本会话密钥的合法客户端能触发，无放大风险。
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

    // 注册 / 登录分支。
    // 进程内互斥：UDP recv 线程与 TCP epoll 线程都可能走到这里；
    // "令牌消费 + 客户端登记"在同一把锁内完成，避免并发消费同一令牌。
    // 跨进程（管理员 --gen-token 追加）由文件锁 flock 保护（见 file_* 实现）。
    const std::string cli_pub_hex = to_hex(cli_pub.data(), cli_pub.size());
    const std::string clients_path = m_keys_dir + "/registered_clients.txt";
    const std::string tokens_path  = m_keys_dir + "/register_tokens.txt";
    {
        std::lock_guard<std::mutex> db_lock(g_keys_db_mutex);
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
    }
    s.client_id = client_id;
    s.cli_pub_hex = cli_pub_hex;

    // 同一身份重复登录：按【已验证的公钥】识别并踢掉旧在线会话
    // （client_id 是客户端自行提交的显示名，可被冒填用来踢人；
    //   公钥才与注册记录绑定，同一把钥匙同时只保留最新会话）。
    // TCP 旧连接同时标记断开：epoll 线程统一 close，不留僵尸连接
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
                victim->tcp_drop.store(true);   // fd 由 epoll 线程统一 close
            // 无论 TCP/UDP 都【立即】释放会话（含虚拟 IP）：下面几行就要给新会话
            // 分配地址，若把 TCP 的释放推给事件线程下一轮，旧会话的 VIP 还占着，
            // 新会话只能拿到另一个地址 → 客户端网卡跟着改地址，改地址瞬间发出的包
            // 源地址还是旧 IP，会被源地址防伪校验丢掉（日志实证：连续重连时
            // 分配结果在 10.8.0.2 / 10.8.0.3 之间来回跳）。
            // release_session 幂等：事件线程收尾时再调一次不会重复释放。
            release_session(victim->peer_key);
        }
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
    s.hs_stage.store(HS_STAGE_AUTHED);   // 阶段机：会话完全建立（明文握手自此全拒）
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
    // 首次扫描在 10s 后，之后每 10s 一次；期间每 100ms 醒一次检查停止标志，
    // 保证 stop()/SIGTERM 能快速 join 本线程（原先整段睡 10s 会让优雅退出卡近 10s，
    // 导致 stop/restart 看起来无效、需 kill -9，甚至被 watchdog 漏杀成孤儿）
    auto next_due = std::chrono::steady_clock::now() + kHeartbeatInterval;
    while (is_running()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        if (!is_running())
            break;
        if (std::chrono::steady_clock::now() < next_due)
            continue;
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
            // 统一销毁路径：TCP 会话标记 tcp_drop 由 epoll 线程 close+release
            // （fd 唯一 owner）；UDP 会话无连接直接释放
            auto destroy = [&](const char* why) {
                fprintf(stderr, "[UDP] %s，销毁会话 %s\n", why, s->peer_key.c_str());
                if (s->is_tcp)
                    s->tcp_drop.store(true);
                else
                    release_session(s->peer_key);
            };
            // 未完成身份验证的会话：10s 清理（含走到阶段2但被拒/放弃的——
            // 这些僵尸会话若按心跳超时算会滞留 30s 占满每源配额）
            if (!s->authenticated.load()) {
                if (now - static_cast<uint64_t>(s->created_at_ms.load()) > hs_timeout_ms)
                    destroy("握手超时");
                continue;
            }
            // 认证会话：心跳超时 → 判失联销毁
            const int64_t last = s->last_rx_ms.load();
            if (last != 0 && (now - static_cast<uint64_t>(last)) > timeout_ms) {
                destroy("heartbeat timeout");
                continue;
            }
            // 会话密钥寿命上限：到点主动换会话（客户端重连 = 重新握手 = 全新密钥，
            // 前向安全窗口从此有上界）。本协议没有 in-protocol rekey，只能这样折中：
            // 先尽力发一条密文 disconnect 让客户端立刻重连，再按统一路径断开。
            // 24h 一次、重连约 0.3s，对使用者几乎无感；断链窗口由客户端重连兜底。
            {
                const uint64_t age_ms = now - static_cast<uint64_t>(s->created_at_ms.load());
                if (age_ms > kSessionMaxLifetimeMs) {
                    fprintf(stderr, "[UDP] 会话时长达到上限（%llu 小时），换新会话重协商密钥: %s\n",
                            static_cast<unsigned long long>(kSessionMaxLifetimeMs / 3600000ull),
                            s->peer_key.c_str());
                    std::vector<uint8_t> bye_buf;
                    // 尽力而为：TCP 下由 epoll 线程本轮 pump_tx 先刷出再 close
                    send_packet(*s, static_cast<uint8_t>(disconnect), nullptr, 0, bye_buf);
                    destroy("会话时长上限");
                    continue;
                }
            }
            // 主动发送心跳
            std::vector<uint8_t> sendbuf;
            if (!send_packet(*s, static_cast<uint8_t>(m_heart), nullptr, 0, sendbuf)) {
                // TCP 连接级失败已在 send_packet 内标记 tcp_drop
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
    ::flock(fileno(f), LOCK_SH);   // 与重写/追加互斥，避免读到截断瞬间
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
    // 跨进程锁：管理员 --gen-token 追加令牌与服务端重写令牌文件并发时不丢数据
    ::flock(fileno(f), LOCK_EX);
    const bool ok = std::fprintf(f, "%s\n", line.c_str()) > 0;
    std::fflush(f);
    ::flock(fileno(f), LOCK_UN);
    std::fclose(f);
    return ok;
}

// 删除一行（用于作废一次性注册令牌）；返回是否真的删除了一行。
// 跨进程互斥走 <tokens>.lock（--gen-token 追加同锁）；文件本体用
// "读出保留行 → 写同目录临时文件 → fsync → rename" 原子替换：
// 进程崩溃不留半截文件，并发追加也不丢失（原实现原地截断重写，
// 崩溃窗口会丢掉整个令牌库）
bool UDP::file_remove_line(const std::string& path, const std::string& line)
{
    return with_token_lock(path, [&]() -> bool {
        FILE* src = std::fopen(path.c_str(), "r");
        if (src == nullptr)
            return false;   // 令牌文件不存在 = 令牌无效
        std::vector<std::string> keep;
        char buf[512] = {0};
        bool removed = false;
        while (std::fgets(buf, sizeof(buf), src) != nullptr) {
            std::string s(buf);
            while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
                s.pop_back();
            if (!removed && s == line) {
                removed = true;   // 匹配到令牌：丢弃该行（作废）
                continue;
            }
            keep.push_back(s);
        }
        std::fclose(src);
        if (!removed)
            return false;   // 没找到该令牌（无效/已使用）

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
