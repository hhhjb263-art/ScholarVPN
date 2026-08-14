#pragma once

#include <cstdint>
#include <cstddef>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <atomic>
#include <thread>
#include <string>
#include <memory>
#include <vector>
#include "../Buffer/tunnel_protoco.h"
#include "../Buffer/QueueBuffer.h"
#include "../Crypt/crypt.h"

/*
虚拟网卡 IP 数据包 → send_ip_packet → 封装隧道协议头 → 
推入 m_queue_send 发送队列 → send_thread 线程循环取出，通过 UDP socket 发给对端 VPN 客户端
*/
class UDP
{
private:
    static constexpr size_t VPN_MTU = 1400;
        // 12 (header) + 1429 (max payload) = 1441, match client
    static constexpr size_t KMax_packet_size = 1441;
private:
    int m_sock = -1;
    sockaddr_in clt_addr{};
    socklen_t clt_len {sizeof(clt_addr)};
    std::thread send_thread;
    std::thread recv_thread;
    std::thread heartbeat_thread;   // 心跳保活线程
    PacketQueue m_queue_send;
    PacketQueue m_queue_recv;

    uint32_t m_client_isn = 0;    // 客户端随机初始序列号（本机）
    uint32_t m_server_isn = 0;

    std::atomic <bool> m_running = false;
    std::atomic <bool> m_has_client = false;
    std::atomic <bool> m_handshaked = false;
    std::atomic <bool> m_need_connect = false;
    std::atomic<uint32_t> m_seq {0};
    std::atomic<uint64_t> m_last_heartbeat_ms{0};   // 最近收到对端心跳的时间(ms)
    mutable std::mutex m_client_mutex;

    // ===== 身份认证（Ed25519 + 临时 X25519 三阶段）=====
    std::shared_ptr<EVP_PKEY> m_sig_priv;      // 服务器持久身份私钥 SIG_SRV_PRI
    std::string m_keys_dir;                    // register_tokens.txt / registered_clients.txt 所在目录
    std::vector<uint8_t> m_nonce_c;            // 客户端 nonce_c
    std::vector<uint8_t> m_nonce_s;            // 服务器 nonce_s
    std::vector<uint8_t> m_dh_srv_pub;         // 服务器临时 X25519 公钥
    std::vector<uint8_t> m_dh_cli_pub;         // 客户端临时 X25519 公钥
    EVP_PKEY* m_dh_srv_priv = nullptr;         // 服务器临时 X25519 私钥（会话级，前向安全）
    std::atomic<bool> m_authenticated{false};  // 阶段3 身份认证通过 → 放行 TUN 流量

    // ===== 加密（临时 X25519 + HKDF + AES-256-GCM）=====
    std::vector<uint8_t> m_key_c2s;            // key_tx 客户端→服务端（服务端接收解密用）
    std::vector<uint8_t> m_key_s2c;            // key_rx 服务端→客户端（服务端发送加密用）
    std::atomic<bool> m_enc_ready{false};      // 阶段2 密钥派生完成标志
private:
    void send_work();
    void recv_work();

    bool handle_heartbeat();
    void heartbeat_work();          // 周期发送心跳 + 对端超时检测
    bool start_threads();           // 启动 send/recv/heartbeat 线程
    void stop_threads();            // join 全部线程

    // ---- 三阶段身份认证 ----
    void handle_auth_hello(const uint8_t* payload, size_t len);        // 阶段1a：nonce_c → 签名响应
    void handle_auth_client_hello(const uint8_t* payload, size_t len); // 阶段1b+2：DH 公钥 → 派生密钥
    void handle_identity(const std::vector<uint8_t>& inner);           // 阶段3：验签 + 注册/登录
    void reset_auth_state();                                           // 新会话/停止时重置认证与密钥

    // ---- 注册/登录数据库（文件）----
    static bool file_contains_line(const std::string& path, const std::string& line);
    static bool file_append_line(const std::string& path, const std::string& line);
    static bool file_remove_line(const std::string& path, const std::string& line);
    static std::string to_hex(const uint8_t* data, size_t len);
public:
    UDP() = default;
    ~UDP();
    UDP(const UDP&) = delete;
    UDP &operator=(const UDP &) = delete; 
    UDP(UDP&& other) noexcept;
    UDP &operator=(UDP&& other) noexcept;

    bool is_running() const;
    bool is_handshaked() const;

    bool set_peer(const std::string &ip, uint16_t port);
    bool start(const std::string &local_ip, uint16_t local_port);      // 服务端：绑定并启动收发线程
    void stop();                                                       // 停止线程并关闭 socket
    void close();

    bool send_ip_packet(packet_buffer && buf);
    bool send_packet(uint8_t type,const uint8_t *data,size_t len,std::vector<uint8_t>& tmp_buf);
    bool recv_ip_packet(packet_buffer &buf);
    uint32_t GenerateISN();

    // 配置服务器身份（三阶段认证）
    //   sig_priv : 服务器持久身份私钥 SIG_SRV_PRI（Ed25519）
    //   keys_dir : register_tokens.txt / registered_clients.txt 所在目录（默认 keys）
    void set_identity(std::shared_ptr<EVP_PKEY> sig_priv, const std::string& keys_dir = "keys");
    bool is_authenticated() const { return m_authenticated.load(); }
    bool is_encrypted() const;
};