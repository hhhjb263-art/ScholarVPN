#pragma once

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>
#include <netinet/in.h>
#include <set>
#include <string>
#include <vector>

#include "../Buffer/QueueBuffer.h"
#include "../Crypt/crypt.h"

// 序号安全上限：达到 2^31 强制换会话（重连协商新密钥），防止 32 位序号
// 回绕后被反重放窗口误判（按 100k 包/s 也需 ~6h，实际会先触发本上限）
constexpr uint32_t kSeqRekeyLimit = 0x80000000u;

// ===================================================================
// 反重放滑动窗口（WireGuard/IPsec 同款语义，对密文帧生效）：
//   每帧 sequence 在 AAD 内不可篡改，且客户端每次发送都递增（重传也是
//   新序号），故"同一序号再次出现"必然是重放/网络复制：
//     seq > highest             → 放行并滑动窗口
//     highest-窗口内且未见过     → 放行（正常 UDP 乱序）
//     其余                      → 静默丢弃（不断连，防注入式 DoS）
//   窗口 64 位位图，实例随 Session 销毁（新会话新密钥自然重置）；
//   带互斥锁：UDP recv 线程与 TCP epoll 线程可能并发触碰同一会话。
//
//   重要：accept() 会修改状态，必须在 AES-GCM 验证成功【之后】调用；
//   解密前只允许调用 too_old()（不修改状态）做廉价预检，防止未认证
//   报文污染窗口（伪造高序号把窗口推高 → 后续合法报文被误判太旧）。
class ReplayWindow
{
public:
    // seq 为主机序；@return true=放行 false=重放（丢弃）。
    // 只应在帧通过 GCM 验证后调用
    bool accept(uint32_t seq)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return accept_locked(seq);
    }

    // 不修改状态的"过旧"预检（解密前调用）：未初始化/比最高序号新/窗口内
    // 均返回 false（需进一步验签）；已见最高序号之外太旧的返回 true
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
    static constexpr uint64_t kNone = ~0ull;   // 未初始化哨兵
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

// 握手阶段（明文阶段1只允许在正确阶段出现，防止认证后换钥）
enum HandshakeStage : int
{
    HS_STAGE_NONE = 0,       // 未开始（收到 auth_hello 时置 HELLO）
    HS_STAGE_HELLO = 1,      // 已发 ServerHello，等待 auth_client_hello
    HS_STAGE_KEYS = 2,       // 会话密钥已派生（ECDH 完成，临时私钥已销毁）
    HS_STAGE_AUTHED = 3,     // 身份认证通过（会话完全建立）
};

// TCP 会话发送积压上限（字节）：加密整帧先入本会话队列，事件线程经 socket
// 尽力写出；慢客户端（对端不收/链路劣化）积压到此即断开，防无界内存。
// 帧上限 1441 字节，2MB ≈ 1400 帧，远大于内核 SNDBUF 已吸收的部分
constexpr size_t kMaxTcpTxBufBytes = 2 * 1024 * 1024;

// ===================================================================
// 多用户架构导读：
//   单用户时代，UDP 类直接保存"那一个客户端"的认证/密钥状态（成员变量）。
//   多用户改造后，把"一个客户端连接"的全部状态抽到独立的 Session 对象，
//   服务端按 (源IP,端口,传输协议) 识别客户端，把收到的报文交给对应 Session。
//
//   一次完整的客户端生命周期：
//     1) 客户端发 auth_hello  → 服务端建 Session（pending，未认证，stage=NONE→HELLO）
//     2) 三阶段认证（nonce → ECDH → 身份报文）在 Session 内完成，stage 逐级推进
//     3) 认证通过：分配虚拟 IP，stage=AUTHED，可转发流量
//     4) 心跳保活 / 收发数据 都由 Session 承载
//     5) 断线/超时：从会话表移除，Session 析构（自动销毁临时密钥）
//
//   并发模型：认证状态机只在 recv 线程（UDP）或 epoll 事件线程（TCP）跑，
//   单会话内天然串行；send 线程/heartbeat 线程只读原子标志与队列；
//   发送用 send_mutex 串行化；tcp_fd 为原子量，close 与 send 借 send_mutex 协调。
// ===================================================================
struct Session
{
    // tcp=true 生成 TCP 会话（传输类型创建后不可变，会话键含协议）；
    // 发送队列 512：吸收 TUN 下行突发（64 会话 × 512 × ~1.5KB ≈ 峰值 ~48MB，可控）
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
            EVP_PKEY_free(dh_srv_priv);   // 销毁临时私钥（前向安全）
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

    sockaddr_in peer_addr{};          // 客户端地址（UDP=recvfrom 源地址；TCP=accept 对端）
    std::string peer_key;             // "ip:port/tcp|udp"，会话表键（含传输，防混用）
    std::string peer_ip;              // 客户端来源 IP（每源会话数限制用）
    const bool is_tcp;                // 传输类型（创建后不可变）
    std::atomic<int> tcp_fd{ -1 };    // TCP 会话的连接 socket（原子：send 线程读 /
                                      // epoll 线程写；close 在 send_mutex 内协调，
                                      // 见 TCPServer::drop_conn）
    std::atomic<bool> tcp_drop{ false };  // TCP 连接请求断开（发送队列满/发送失败/
                                          // 心跳超时/disconnect/同身份互踢/淘汰）：
                                          // fd 由 epoll 事件线程统一 shutdown+close
                                          // （唯一 owner），其他线程只置本标志

    // 阶段3 通过后填充
    std::string client_id;            // 客户端标识（仅显示用；互踢按公钥判定）
    std::string cli_pub_hex;          // 客户端 Ed25519 公钥十六进制（注册/登录数据库 + 互踢键）
    uint32_t virtual_ip = 0;          // 分配的虚拟 IP（网络字节序，identity_ok 通告用）
    bool ip_assigned = false;

    // 三阶段认证状态（仅在单会话的 recv/事件线程读写，天然串行）
    std::atomic<int> hs_stage{ HS_STAGE_NONE };  // 握手阶段机（见 HandshakeStage）
    std::vector<uint8_t> nonce_c;
    std::vector<uint8_t> nonce_s;
    std::vector<uint8_t> dh_cli_pub;
    std::vector<uint8_t> dh_srv_pub;
    EVP_PKEY* dh_srv_priv = nullptr;  // 本端临时 X25519 私钥（阶段2 派生完成后立即销毁）
    std::vector<uint8_t> key_c2s;     // 客户端→服务端（接收解密）
    std::vector<uint8_t> key_s2c;     // 服务端→客户端（发送加密）
    std::atomic<bool> enc_ready{ false };
    std::atomic<bool> authenticated{ false };
    std::atomic<bool> handshaked{ false };

    PacketQueue send_queue;           // 本会话待发数据（TUN 下行，明文 IP 包）
    std::mutex send_mutex;            // 发送串行化（多个线程可能同时发送）；
                                      // TCP 连接 close 也必须持有它（与发送互斥）
    // TCP 跨线程发送队列：非事件线程（send_work/heartbeat）把【已加密整帧】
    // 提交到这里，TCPServer 事件线程是 socket 唯一写者（flush_conn_tx 搬运
    // + EPOLLOUT）。事件线程自己（recv 路径回心跳/identity_ok）也走同一队列，
    // 保证同会话帧序与"单线程写 socket"的所有权模型。
    std::mutex tcp_tx_mutex;
    std::deque<std::vector<uint8_t>> tcp_tx;
    size_t tcp_tx_bytes = 0;          // 仅在 tcp_tx_mutex 内读写
    std::atomic<uint32_t> seq{ 0 };
    ReplayWindow replay;              // 上行密文帧反重放滑窗（验签成功后提交）

    std::atomic<int64_t> last_rx_ms{ 0 };     // 最近收到【已认证】对端报文的时间
    std::atomic<int64_t> created_at_ms{ 0 };  // 会话创建时间（握手超时清理用）
};

// 虚拟 IP 池：以服务端 TUN 地址为网关，在网段内分配未占用地址（排除网络/广播/网关）。
class VirtualIpPool
{
public:
    explicit VirtualIpPool(uint32_t gateway_net, int prefix)
    {
        const uint32_t mask = (prefix <= 0) ? 0u
                            : (prefix >= 32) ? 0xFFFFFFFFu
                            : (~((1u << (32 - prefix)) - 1));
        const uint32_t gw = ntohl(gateway_net);
        const uint32_t net = gw & mask;
        first = net + 1;              // 排除网络地址
        last = net | (~mask);
        if (last > 0)
            last -= 1;                // 排除广播地址
        this->gw = gw;
    }

    // 分配一个未占用地址（网络字节序）；池满返回 0
    uint32_t allocate()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
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

    void release(uint32_t ip_net)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        used.erase(ntohl(ip_net));
    }

    size_t used_count() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return used.size();
    }

private:
    mutable std::mutex m_mutex;
    std::set<uint32_t> used;          // 已占用（主机序）
    uint32_t first = 0;
    uint32_t last = 0;
    uint32_t gw = 0;
};
