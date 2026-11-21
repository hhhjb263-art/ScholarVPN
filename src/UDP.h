#pragma once

#include "tunnel_protoco.h"
#include "PacketQueue.h"
#include "Crypt.h"
#include "replay_window.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

enum class Transport : uint8_t { UDP = 0, TCP = 1 };

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
    virtual uint8_t proto_version() const
    {
        return static_cast<uint8_t>(v_udp);
    }
    bool is_handshaked() const { return m_handshaked.load(); }
    bool is_authenticated() const { return m_authenticated.load(); }
    int auth_deny_reason() const { return m_auth_deny_reason.load(); }
    bool needs_reconnect() const { return m_need_reconnect.load(); }
    int64_t last_rx_ms() const { return m_last_rx_ms.load(); }
    uint32_t assigned_ip() const { return m_assigned_ip.load(); }
    uint8_t assigned_prefix() const { return m_assigned_prefix; }
    void send_ip_packet(
        packet_buffer&& buf
    );
    bool recv_ip_packet(packet_buffer& buf);
    bool try_recv_ip_packet(packet_buffer& buf);
    bool send_packet(uint8_t type,
        const uint8_t* data,
        size_t len,
        std::vector<uint8_t>& sendbuf);

    void set_identity(
        std::shared_ptr<EVP_PKEY> ed25519_priv,
        const std::string& server_sig_pub_pem,
        const std::string& client_id,
        const std::string& register_token);
    uint32_t GenerateISN();
public:
    void send_work();
    void recv_work();
protected:
    virtual sock_t open_socket();
    virtual bool establish();
    virtual bool raw_send(const uint8_t* data, size_t len);
    virtual bool recv_frame(tunnel_header& hdr, const uint8_t*& payload,
                            size_t& pay_len, bool& got);
private:
    bool build_identity_message(std::vector<uint8_t>& out);
protected:
    sock_t m_sock;
    sockaddr_in m_sockaddr{};
    std::vector<uint8_t> m_udpBuf;
    std::mutex m_send_mutex;
    PacketQueue m_sendqueue;
    PacketQueue m_recvqueue;
    std::thread send_thread;
    std::thread recv_thread;
    std::atomic<bool> m_running{ false };
    std::atomic<bool> m_handshaked{ false };
    std::atomic<bool> m_need_reconnect{ false };
    std::atomic<uint32_t> m_seq{ 0 };
	std::atomic<int64_t> m_last_rx_ms{ 0 };

    std::chrono::steady_clock::duration m_heartbeatTimeout{ std::chrono::seconds(5) };
    HandshakeState m_hs_state = HS_IDLE;
    uint32_t m_client_isn = 0;
    uint32_t m_server_isn = 0;

    std::shared_ptr<EVP_PKEY> m_ed25519_priv;
    std::string m_server_sig_pub_pem;
    std::string m_client_id;
    std::string m_register_token;
    std::vector<std::uint8_t> m_nonce_c;
    std::vector<std::uint8_t> m_nonce_s;
    std::vector<std::uint8_t> m_dh_cli_pub;
    std::vector<std::uint8_t> m_dh_srv_pub;
    EVP_PKEY* m_dh_cli_priv = nullptr;
    EVP_PKEY* m_server_sig_pub = nullptr;
    std::atomic<bool> m_server_hello_ok{ false };
    std::atomic<bool> m_authenticated{ false };
    std::atomic<bool> m_auth_failed{ false };
    std::atomic<int> m_auth_deny_reason{ -1 };

    std::atomic<uint32_t> m_assigned_ip{ 0 };
    uint8_t m_assigned_prefix = 24;

    std::vector<std::uint8_t> m_key_c2s;
    std::vector<std::uint8_t> m_key_s2c;
    std::atomic<bool> m_enc_ready{ false };
    ReplayWindow m_replay;
    std::atomic<uint32_t> m_auth_fail_logged{ 0 };
    std::atomic<uint32_t> m_replay_reject_logged{ 0 };
    std::atomic<uint32_t> m_tx_queue_drop{ 0 };
protected:
    static constexpr size_t KMax_packet_size = 1441;

    void handle_frame(const tunnel_header& header, const uint8_t* payload,
                      size_t payload_len, std::vector<uint8_t>& sendbuf);
};
