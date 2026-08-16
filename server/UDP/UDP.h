#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
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

    // tun_ip / tun_prefix：虚拟 IP 池基准；max_clients：最大并发会话数（0=默认 64）
    bool start(const std::string& local_ip, uint16_t local_port,
               const std::string& tun_ip, int tun_prefix,
               size_t max_clients = 64);
    void stop();
    void close();

    // sig_priv：服务器持久身份私钥 SIG_SRV_PRI；keys_dir：注册/登录数据库目录
    void set_identity(std::shared_ptr<EVP_PKEY> sig_priv, const std::string& keys_dir = "keys");

    // TUN 读到的 IP 包按目的 IP 转发到对应会话；无匹配会话返回 false
    bool forward_tun_packet(packet_buffer&& buf);
    // 从全局接收队列取一个解密后的 IP 包（VpnCore 写入 TUN）
    bool recv_ip_packet(packet_buffer& buf);

    int client_count() const;
    size_t max_clients() const { return m_max_clients; }

private:
    void send_work();
    void recv_work();
    void heartbeat_work();
    bool start_threads();
    void stop_threads();

    std::shared_ptr<Session> get_or_create_session(const sockaddr_in& addr);
    void release_session(const std::string& key);   // 从表移除 + 释放虚拟 IP + 标记下线

    uint32_t allocate_virtual_ip();
    void release_virtual_ip(uint32_t ip);

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

    static constexpr size_t VPN_MTU = 1400;
    static constexpr size_t KMax_packet_size = 1441;
};
