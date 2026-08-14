#pragma once

#include "tunnel_protoco.h"
#include "PacketQueue.h"
#include "Crypt.h"

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>


class UDP{
public:
    UDP(
        const char* remoteip,
        uint16_t port,
        bool is_running = false,
        size_t queueMax = 4096
    );
    ~UDP();
    bool init();
    void stop();
    // ---- 重连状态机查询接口 ----
    bool is_handshaked() const { return m_handshaked.load(); }
    bool is_authenticated() const { return m_authenticated.load(); }
    // identity_deny 携带的原因码：0=未注册/签名失败 1=注册令牌无效或已使用；-1=未收到拒绝
    int auth_deny_reason() const { return m_auth_deny_reason.load(); }
    bool needs_reconnect() const { return m_need_reconnect.load(); }
    int64_t last_rx_ms() const { return m_last_rx_ms.load(); }
    void send_ip_packet(
        packet_buffer&& buf
    );
    bool recv_ip_packet(packet_buffer& buf);
    bool try_recv_ip_packet(packet_buffer& buf); // 非阻塞接收（轮询/测试用）
    bool send_packet(uint8_t type,
        const uint8_t* data,
        size_t len,
        std::vector<uint8_t>& sendbuf);

    // 配置身份（三阶段认证）：
    //   ed25519_priv       : 客户端持久身份私钥 SIG_CLI_PRI（内存中，DPAPI 解密后）
    //   server_sig_pub_pem : 内置的服务器身份公钥 SIG_SRV_PUB（PEM 文本，硬编码进程序）
    //   client_id          : 客户端标识
    //   register_token     : 一次性注册令牌（空串 = 登录模式）
    void set_identity(
        std::shared_ptr<EVP_PKEY> ed25519_priv,
        const std::string& server_sig_pub_pem,
        const std::string& client_id,
        const std::string& register_token);
    uint32_t GenerateISN();
public:
    void send_work();
    void recv_work();
private:
    // 阶段3：组装并签名身份报文（不含内层 type 字节，send_packet 会补）
    bool build_identity_message(std::vector<uint8_t>& out);
private:
    SOCKET m_sock;
    sockaddr_in m_sockaddr{};
    PacketQueue m_sendqueue;
    PacketQueue m_recvqueue;
    std::thread send_thread;
    std::thread recv_thread;
    std::atomic<bool> m_running{ false };
    std::atomic<bool> m_handshaked{ false };
    std::atomic<bool> m_need_reconnect{ false };
    std::atomic<uint32_t> m_seq{ 0 };
	std::atomic<int64_t> m_last_rx_ms{ 0 };	// 最近一次收到合法报文的时间（steady_clock ms）
    HandshakeState m_hs_state = HS_IDLE;
    uint32_t m_client_isn = 0;    // 客户端随机初始序列号（模仿TCP ISN）
    uint32_t m_server_isn = 0;

    // ============ 身份认证状态（Ed25519 + 临时 X25519 三阶段） ============
    std::shared_ptr<EVP_PKEY> m_ed25519_priv;      // 客户端身份私钥 SIG_CLI_PRI
    std::string m_server_sig_pub_pem;              // 内置服务器身份公钥 PEM（硬编码）
    std::string m_client_id;                       // 客户端标识
    std::string m_register_token;                  // 一次性注册令牌（空=登录）
    std::vector<std::uint8_t> m_nonce_c;           // 阶段1 nonce_c
    std::vector<std::uint8_t> m_nonce_s;           // 阶段1 nonce_s
    std::vector<std::uint8_t> m_dh_cli_pub;        // 本端临时 X25519 公钥
    std::vector<std::uint8_t> m_dh_srv_pub;        // 对端临时 X25519 公钥
    EVP_PKEY* m_dh_cli_priv = nullptr;             // 本端临时 X25519 私钥（会话级）
    EVP_PKEY* m_server_sig_pub = nullptr;          // 解析后的服务器身份公钥（本类释放）
    std::atomic<bool> m_server_hello_ok{ false };  // 阶段1 服务器签名验证通过
    std::atomic<bool> m_authenticated{ false };    // 阶段3 身份认证通过
    std::atomic<bool> m_auth_failed{ false };      // 认证失败（中间人 / 身份被拒）
    std::atomic<int> m_auth_deny_reason{ -1 };     // 服务器 identity_deny 原因码（0=未注册 1=令牌无效/已使用）

    // ============ 加密状态（临时 X25519 + HKDF + AES-256-GCM） ============
    std::vector<std::uint8_t> m_key_c2s;        // key_tx 客户端→服务端（本端发送加密）
    std::vector<std::uint8_t> m_key_s2c;        // key_rx 服务端→客户端（本端接收解密）
    std::atomic<bool> m_enc_ready{ false };     // 密钥派生完成（阶段2 结束）
private:
    static constexpr size_t VPN_MTU = 1400;
    static constexpr size_t KMax_packet_size = 1441;
};