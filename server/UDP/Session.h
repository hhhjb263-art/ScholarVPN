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
    // 会话已下线（release_session 置位，不可逆）：用于兜住"会话已从会话表摘除、
    // 但 TCP 连接还挂着几十毫秒"的窗口——期间到达的帧必须直接丢弃，否则一个
    // 明文 auth_hello 就能让僵尸会话重新走完握手、再拿一个虚拟 IP（池里泄漏一个地址）
    std::atomic<bool> released{ false };
    // 已签名的 ServerHello 载荷缓存（nonce_s || dh_srv_pub || sig_srv，只含公开数据）。
    // 未认证会话的 auth_hello 重传每 500ms 一次，原先每次都重新做 Ed25519 签名
    // （伪造源地址狂刷可以放大成 CPU 消耗）；Ed25519 是确定性签名，同一会话的
    // nonce_s/dh_srv_pub 不变 → 缓存后重传只做"查表 + 重发"。新 nonce 重置时清空。
    std::vector<uint8_t> server_hello_payload;

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
    // "拒绝上行数据包"日志的已打印次数（限流用）：客户端网卡残留旧虚拟 IP 时会
    // 持续发错源地址，每个包都打日志会把日志刷爆、淹没真实告警。每会话只详报几条。
    std::atomic<uint32_t> src_reject_logged{ 0 };
    // "密文帧认证失败"日志的已打印次数（限流用）：密钥不匹配（如客户端实例残帧、
    // 会话被踢后旧连接的余包）会持续解密失败。原先完全静默，两侧都表现为
    // "对端不可达"，排查时无法区分"没收到"和"收到了但解不开"
    std::atomic<uint32_t> auth_fail_logged{ 0 };

    std::atomic<int64_t> last_rx_ms{ 0 };     // 最近收到【已认证】对端报文的时间
    std::atomic<int64_t> created_at_ms{ 0 };  // 会话创建时间（握手超时清理用）
};

// 虚拟 IP 池：以服务端 TUN 地址为网关，在网段内分配未占用地址（排除网络/广播/网关）。
class VirtualIpPool
{
public:
    explicit VirtualIpPool(uint32_t gateway_net, int prefix)
        // 随机分配虚拟 IP：每次进程启动重新播种（random_device + 高精度时钟混合）
        : rng(std::random_device{}() ^
              static_cast<uint32_t>(std::chrono::steady_clock::now()
                                        .time_since_epoch().count()))
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
        // /31、/32 这类没有可用主机地址的网段：置为无效，allocate 直接返回 0
        if (last < first)
        {
            first = 0;
            last = 0;
        }
    }

    // 分配一个未占用地址（网络字节序）；池满返回 0。
    //
    // 注意：这是【最后兜底】。正常分配走 allocate_virtual_ip() 的
    // "租约 → 身份派生" 两级策略（见 server/UDP/UDP.cpp），只有池接近满、
    // 身份派生的候选地址被别人占着时才会落到这里。
    //
    // 2026-10-19 历史：这个函数原先被直接当作主分配器改成纯随机，
    // 结果同一客户端每次重连拿到不同地址 → 客户端必须改网卡地址 →
    // 改地址窗口内的上行包源地址还是旧的 → 被服务端源地址防伪整片丢弃
    // （网速降到几十 K、隧道内 TCP 握手 SYN 都发不出去）。
    // 教训：虚拟 IP 必须【按身份稳定】，随机只能是"候选地址被占用时的兜底"。
    uint32_t allocate()
    {
        if (first == 0 || last < first)
            return 0;                    // 网段没有可用主机地址（/31、/32）
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

        // 兜底：池接近满时随机碰撞概率变高，线性扫描把剩余地址找出来
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

    // 按身份键【确定性】地给出一个候选地址（主机序；0 = 网段无可用地址）。
    //
    // 同一个身份永远得到同一个候选值 —— 这是"随机分配事故"的根治点：
    // 客户端重连、服务端重启、租约文件丢失/不可写，地址都不会变，
    // 于是客户端网卡根本不需要改地址，"改地址窗口"整类丢包从源头消失。
    //
    // 同时保留原随机方案想要的隐私性：地址既不是按接入顺序递增的，
    // 也不是外部能猜的（要算出来得先知道调用方传进来的身份键）。
    //
    // 哈希用 FNV-1a 自实现，不用 std::hash<std::string>：后者的实现随
    // 标准库版本/编译器而变，服务端升级编译器就会让所有人的地址全变一次。
    uint32_t preferred_for(const std::string& key) const
    {
        if (first == 0 || last < first)
            return 0;
        uint64_t h = 14695981039346656037ull;             // FNV-1a 64 位 offset basis
        for (unsigned char c : key)
        {
            h ^= c;
            h *= 1099511628211ull;                        // FNV prime 0x100000001B3
        }
        const uint64_t span = static_cast<uint64_t>(last - first) + 1ull;
        uint32_t ip = first + static_cast<uint32_t>(h % span);
        // 网关地址不参与分配：撞上就顺延一个（本函数只给候选，占用与否由
        // try_acquire 判定，这里只保证不进保留地址）
        if (ip == gw)
            ip = (ip < last) ? ip + 1 : first;
        return ip;
    }

    void release(uint32_t ip_net)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        used.erase(ntohl(ip_net));
    }

    // 指定地址获取（租约归还用）：该地址空闲则占用并返回 true。
    // 网关地址 / 越界地址一律拒绝。用于"同一 ClientID 优先拿回上次地址"。
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
    std::set<uint32_t> used;          // 已占用（主机序）
    std::mt19937 rng;                 // 随机分配用；仅在持锁时访问
    uint32_t first = 0;
    uint32_t last = 0;
    uint32_t gw = 0;
};
