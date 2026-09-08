#pragma once

#include "tunnel_protoco.h"
#include "PacketQueue.h"
#include "Crypt.h"

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

// 传输方式：一条隧道连接二选一（协议层完全一致，仅承载不同）
enum class Transport : uint8_t { UDP = 0, TCP = 1 };

// ============================================================
// 隧道对端基类：三阶段认证 / AES-256-GCM / 心跳 / 收发队列全部在此实现，
// 传输差异（UDP 数据报 / TCP 流式）由子类覆写 4 个钩子：
//   open_socket / establish / raw_send / recv_frame
// 子类：UDP（本文件，默认）与 TCP（tcp.h）
// 协议版本字节即传输标识：发送打标 / 接收校验（proto_version 虚函数）
// ============================================================
class UDP {
public:
    UDP(
        const char* remoteip,
        uint16_t port,
        bool is_running = false,
        size_t queueMax = 4096
    );
    virtual ~UDP();
    virtual bool init();
    virtual void stop();
    // 协议版本字节随传输变化：UDP 报文标 v_udp，TCP 子类覆写为 v_tcp。
    // 发送时打标、接收时校验——错误传输的报文在 version 检查处自然被丢弃
    virtual uint8_t proto_version() const
    {
        return static_cast<uint8_t>(v_udp);
    }
    // ---- 重连状态机查询接口 ----
    bool is_handshaked() const { return m_handshaked.load(); }
    bool is_authenticated() const { return m_authenticated.load(); }
    // identity_deny 携带的原因码：0=未注册/签名失败 1=注册令牌无效或已使用；-1=未收到拒绝
    int auth_deny_reason() const { return m_auth_deny_reason.load(); }
    bool needs_reconnect() const { return m_need_reconnect.load(); }
    int64_t last_rx_ms() const { return m_last_rx_ms.load(); }
    // 服务端分配的虚拟 IP（identity_ok 通告，0=未收到）；多用户服务端下需采用它配置网卡
    uint32_t assigned_ip() const { return m_assigned_ip.load(); }
    uint8_t assigned_prefix() const { return m_assigned_prefix; }
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
    void recv_work();   // 收包循环：recv_frame 取一条消息 -> handle_frame 统一处理
protected:
    // ---- 传输钩子（子类覆写；基类实现 = UDP）----
    virtual SOCKET open_socket();      // UDP: SOCK_DGRAM；TCP: SOCK_STREAM
    virtual bool establish();          // UDP: 无连接 no-op；TCP: connect + TCP_NODELAY
    virtual bool raw_send(const uint8_t* data, size_t len);   // UDP: sendto；TCP: send_all
    // 取一条完整消息（数据报天然一条；TCP 由子类分帧凑齐）
    // 返回 false = 连接已死亡（收包线程退出，实例随后被销毁）
    // got = true 时 payload 指针在下次调用前有效
    virtual bool recv_frame(tunnel_header& hdr, const uint8_t*& payload,
                            size_t& pay_len, bool& got);
private:
    // 阶段3：组装并签名身份报文（不含内层 type 字节，send_packet 会补）
    bool build_identity_message(std::vector<uint8_t>& out);
protected:
    SOCKET m_sock;
    sockaddr_in m_sockaddr{};
    std::vector<uint8_t> m_udpBuf;                // UDP recvfrom 缓冲（成员保证 payload 指针有效）
    std::mutex m_send_mutex;                      // 串行化 send_packet 的 socket 写：
                                                  // send_work 与 recv_work（心跳应答）两个线程
                                                  // 可能同时发送，TCP 流式写必须整帧原子（防粘帧交错）
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

    // 身份认证状态（Ed25519 + 临时 X25519 三阶段）
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

    // 服务端通告（identity_ok）
    std::atomic<uint32_t> m_assigned_ip{ 0 };      // 服务端分配的虚拟 IP（主机序，0=未收到）
    uint8_t m_assigned_prefix = 24;                // 服务端通告的网段前缀

    // 加密状态（临时 X25519 + HKDF + AES-256-GCM）
    std::vector<std::uint8_t> m_key_c2s;        // key_tx 客户端→服务端（本端发送加密）
    std::vector<std::uint8_t> m_key_s2c;        // key_rx 服务端→客户端（本端接收解密）
    std::atomic<bool> m_enc_ready{ false };     // 密钥派生完成（阶段2 结束）
protected:
    // 数据面明文载荷上限 KMax_data_payload(1400) 定义在 tunnel_protoco.h（两端一致）；
    // KMax_packet_size = 头部 12 + Max_payload_len 1429，作收发缓冲上限
    static constexpr size_t KMax_packet_size = 1441;

    void handle_frame(const tunnel_header& header, const uint8_t* payload,
                      size_t payload_len, std::vector<uint8_t>& sendbuf);
};