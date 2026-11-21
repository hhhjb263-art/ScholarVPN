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

#include "../ServiceDB.h"

class UDP
{
public:
    UDP() = default;
    ~UDP();

    UDP(const UDP&) = delete;
    UDP& operator=(const UDP&) = delete;

    bool is_running() const { return m_running.load(); }

    bool start(const std::string& local_ip, uint16_t local_port,
               const std::string& tun_ip, int tun_prefix,
               size_t max_clients = 64, bool udp_enabled = true);
    void stop();
    void close();

    void set_identity(std::shared_ptr<EVP_PKEY> sig_priv, const std::string& keys_dir = "keys");
    void set_service_db(const std::string& db_path);

    bool forward_tun_packet(packet_buffer&& buf);
    bool recv_ip_packet(packet_buffer& buf);
    void wait_recv_queue(int timeout_ms);

    int client_count() const;
    size_t max_clients() const { return m_max_clients; }

    void handle_framed(Session& s, const tunnel_header& hdr,
                       const uint8_t* payload, size_t pay_len);
    void release_session(const std::string& key);
    std::shared_ptr<Session> get_or_create_session(const sockaddr_in& addr, bool tcp);

    void set_tcp_tx_wake(std::function<void()> wake);
    void tcp_tx_wake() const;

private:
    void send_work();
    void recv_work();
    void heartbeat_work();
    bool start_threads();
    void stop_threads();

    void wake_send_waiters();
    void wake_recv_waiters();

    uint32_t allocate_virtual_ip(const std::string& client_id);
    void release_virtual_ip(uint32_t ip);
    void load_vip_leases();
    void save_vip_leases(const std::unordered_map<std::string, uint32_t>& leases);

    bool allow_handshake_recompute(uint32_t ip_net);

    void handle_auth_hello(Session& s, const uint8_t* payload, size_t len);
    void handle_auth_client_hello(Session& s, const uint8_t* payload, size_t len);
    void handle_identity(Session& s, const std::vector<uint8_t>& inner);

    bool send_packet(Session& s, uint8_t type, const uint8_t* data, size_t len,
                     std::vector<uint8_t>& tmp_buf);
    void reply_heartbeat(Session& s);

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
    std::unique_ptr<service::ServiceDB> m_svc;

    mutable std::mutex m_tcp_tx_wake_mutex;
    std::function<void()> m_tcp_tx_wake;

    PacketQueue m_queue_recv{ 4096 };

    size_t m_max_clients = 64;
    uint8_t m_tun_prefix = 24;
    mutable std::mutex m_sessions_mutex;
    std::unordered_map<std::string, std::shared_ptr<Session>> m_sessions;
    mutable std::mutex m_vip_mutex;
    std::unordered_map<uint32_t, std::string> m_vip_to_key;
    std::shared_ptr<VirtualIpPool> m_ip_pool;
    std::unordered_map<std::string, uint32_t> m_last_vip;

    struct HandshakeRateBucket
    {
        double tokens{ 0.0 };
        int64_t last_ms{ 0 };
        uint32_t logged{ 0 };
    };
    std::mutex m_hs_rl_mutex;
    std::unordered_map<uint32_t, HandshakeRateBucket> m_hs_rl;

    std::mutex m_wake_mutex;
    std::condition_variable m_send_cv;
    std::condition_variable m_recv_cv;
    bool m_send_wake{ false };
    bool m_recv_wake{ false };

    static constexpr size_t KMax_packet_size = 1441;
};
