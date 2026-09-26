#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "../Buffer/tunnel_protoco.h"
#include "../Buffer/QueueBuffer.h"
#include "../Crypt/crypt.h"
#include "Session.h"

// UDP 隧道（服务端，多用户版）：监听一个端口，按 (源IP,端口) 分发到独立 Session，
// 每个会话各自维护认证 / 密钥 / 发送队列 / 心跳；TUN 下行按目的虚拟 IP 查表转发。
class UDP
{
public:
    UDP() = default;
    ~UDP();

    UDP(const UDP&) = delete;
    UDP& operator=(const UDP&) = delete;

    bool is_running() const { return m_running.load(); }

    // tun_ip / tun_prefix：虚拟 IP 池基准；max_clients：最大并发会话数（0=默认 64）；
    // udp_enabled=false（--transport tcp）：不绑定 UDP socket，仅服务 TCP 会话
    // （recv 线程空转待命，会话/认证/加密机制全部照常工作）
    bool start(const std::string& local_ip, uint16_t local_port,
               const std::string& tun_ip, int tun_prefix,
               size_t max_clients = 64, bool udp_enabled = true);
    void stop();
    void close();

    // sig_priv：服务器持久身份私钥 SIG_SRV_PRI；keys_dir：注册/登录数据库目录
    void set_identity(std::shared_ptr<EVP_PKEY> sig_priv, const std::string& keys_dir = "keys");

    // TUN 读到的 IP 包按目的 IP 转发到对应会话；无匹配会话返回 false。
    // 目标会话发送队列满 = 客户端持续消费不动：按既定策略断开该会话
    // （TCP 交 epoll 线程统一 close，UDP 直接释放），而非无限堆积
    bool forward_tun_packet(packet_buffer&& buf);
    // 从全局接收队列取一个解密后的 IP 包（VpnCore 写入 TUN）
    bool recv_ip_packet(packet_buffer& buf);
    // 队列空时最多等 timeout_ms（入队即被唤醒，事件驱动）：
    // 供 VpnCore 转发线程替代固定 sleep 轮询
    void wait_recv_queue(int timeout_ms);

    int client_count() const;
    size_t max_clients() const { return m_max_clients; }

    // 处理一条已分帧的完整消息（TCPServer 与 UDP recv 循环共用）：
    // 明文阶段1认证 / 密文解密分发（data/heart/identity/disconnect）。
    // TCP 会话（s.tcp_fd >= 0）按 v_tcp 校验/标记版本，UDP 会话按 v_udp
    void handle_framed(Session& s, const tunnel_header& hdr,
                       const uint8_t* payload, size_t pay_len);
    // 从表移除 + 释放虚拟 IP + 标记下线（TCPServer 连接断开时也调用）
    void release_session(const std::string& key);
    // 取/建会话（TCPServer accept 后也调用；pending 配额/每源上限对 TCP 同样生效）。
    // 会话键含传输协议（"ip:port/tcp|udp"），TCP/UDP 不会混用同一会话
    std::shared_ptr<Session> get_or_create_session(const sockaddr_in& addr, bool tcp);

    // TCPServer 注册的唤醒钩子：send_packet 把 TCP 已加密整帧提交进会话
    // tcp_tx 队列后调用（写 eventfd），事件线程立即排空队列写 socket。
    // 未注册时（TCP 未启用/停止中）由事件线程 200ms 周期兜底扫描
    void set_tcp_tx_wake(std::function<void()> wake);
    void tcp_tx_wake() const;   // 有 TCP 帧入队后调用（读钩子并执行，可空）

private:
    void send_work();
    void recv_work();
    void heartbeat_work();
    bool start_threads();
    void stop_threads();

    // 队列入队后的消费者唤醒（替代固定 sleep 轮询）：
    //   wake_send_waiters：TUN 下行包入会话发送队列后唤醒 send_work
    //   wake_recv_waiters：上行 IP 包入全局接收队列后唤醒 VpnCore 转发线程
    void wake_send_waiters();
    void wake_recv_waiters();

    uint32_t allocate_virtual_ip();
    void release_virtual_ip(uint32_t ip);

    // 握手重算限速（令牌桶，按来源 IP）：只有"需要重算握手"的 auth_hello
    // （携带新 nonce → 要生成临时 X25519 密钥对 + Ed25519 签名）才消耗令牌；
    // 同一 nonce 的重传走幂等分支（查表 + 重发缓存），合法客户端不受影响。
    // 用途：把"伪造源地址狂刷 new-nonce auth_hello"能烧掉的 CPU / 反射放大
    // 限制在可控范围。@return false = 超出速率，丢弃本帧（不回包）
    bool allow_handshake_recompute(uint32_t ip_net);

    // 认证处理（仅在 recv 线程执行）
    void handle_auth_hello(Session& s, const uint8_t* payload, size_t len);
    void handle_auth_client_hello(Session& s, const uint8_t* payload, size_t len);
    void handle_identity(Session& s, const std::vector<uint8_t>& inner);

    bool send_packet(Session& s, uint8_t type, const uint8_t* data, size_t len,
                     std::vector<uint8_t>& tmp_buf);
    void reply_heartbeat(Session& s);

    // 注册/登录数据库（文本文件）
    static bool file_contains_line(const std::string& path, const std::string& line);
    static bool file_append_line(const std::string& path, const std::string& line);
    static bool file_remove_line(const std::string& path, const std::string& line);
    static std::string to_hex(const uint8_t* data, size_t len);

private:
    int m_sock = -1;
    std::thread send_thread;
    std::thread recv_thread;
    std::thread heartbeat_thread;
    std::atomic<bool> m_running{ false };

    std::shared_ptr<EVP_PKEY> m_sig_priv;
    std::string m_keys_dir;

    // TCP 发送唤醒钩子（TCPServer::start 注册；互斥保护，
    // 注册/注销与发送线程并发安全）
    mutable std::mutex m_tcp_tx_wake_mutex;
    std::function<void()> m_tcp_tx_wake;

    // 全局接收队列（各会话解密后的 IP 包 → TUN）
    PacketQueue m_queue_recv{ 4096 };

    // 会话表（peer_key → Session）
    size_t m_max_clients = 64;
    uint8_t m_tun_prefix = 24;
    mutable std::mutex m_sessions_mutex;
    std::unordered_map<std::string, std::shared_ptr<Session>> m_sessions;
    // 虚拟 IP（网络字节序）→ 会话键（TUN 下行转发查表用）
    mutable std::mutex m_vip_mutex;
    std::unordered_map<uint32_t, std::string> m_vip_to_key;
    std::shared_ptr<VirtualIpPool> m_ip_pool;

    // 握手重算限速表（来源 IP 网络序 → 令牌桶）；见 allow_handshake_recompute。
    // logged 只为"每条 IP 最多打 3 条日志"限流用，避免被刷屏
    struct HandshakeRateBucket
    {
        double tokens{ 0.0 };
        int64_t last_ms{ 0 };
        uint32_t logged{ 0 };
    };
    std::mutex m_hs_rl_mutex;
    std::unordered_map<uint32_t, HandshakeRateBucket> m_hs_rl;

    // 队列消费者唤醒（m_wake_mutex 保护两个唤醒标志，杜绝丢失唤醒）
    std::mutex m_wake_mutex;
    std::condition_variable m_send_cv;
    std::condition_variable m_recv_cv;
    bool m_send_wake{ false };
    bool m_recv_wake{ false };

    // 数据面明文载荷上限 KMax_data_payload(1400) 定义在 Buffer/tunnel_protoco.h（两端一致）；
    // KMax_packet_size = 头部 12 + Max_payload_len 1429，作收发缓冲上限
    static constexpr size_t KMax_packet_size = 1441;
};
