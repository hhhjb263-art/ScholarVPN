#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "UDP.h"
#include "Crypt.h"

enum class ConnState
{
    Stopped = 0,
    Connecting,
    Connected,
    Reconnecting,
    Error,
};

class ReconnectManager
{
public:
    using StateCallback = std::function<void(ConnState)>;
    using ConnectedCallback = std::function<void()>;
    using RegisterTokenRejectedCallback = std::function<void()>;

    ReconnectManager(std::string remoteIp, uint16_t port, size_t queueMax = 256);
    ~ReconnectManager();

    ReconnectManager(const ReconnectManager&) = delete;
    ReconnectManager& operator=(const ReconnectManager&) = delete;

    void set_identity(std::shared_ptr<EVP_PKEY> ed25519_priv,
                      const std::string& server_sig_pub_pem,
                      const std::string& client_id,
                      const std::string& register_token);

    bool start();
    void stop();

    ConnState state() const { return m_state.load(); }
    std::shared_ptr<UDP> udp() const;

    void set_state_callback(StateCallback cb);
    void set_connected_callback(ConnectedCallback cb);
    void set_register_token_rejected_callback(RegisterTokenRejectedCallback cb);
    void clear_register_token() { m_register_token.clear(); }

    void set_transport(Transport t) { m_transport = t; }

    void force_disconnect_for_test();

    static const char* state_name(ConnState s);

private:
    void worker_loop();
    bool connect_once();
    void teardown_current_locked();
    void set_state(ConnState s);

private:
    std::string m_remote;
    uint16_t m_port;
    size_t m_queueMax;
    Transport m_transport{ Transport::UDP };

    std::shared_ptr<EVP_PKEY> m_ed25519_priv;
    std::string m_server_sig_pub_pem;
    std::string m_client_id;
    std::string m_register_token;

    std::atomic<bool> m_running{ false };
    std::atomic<ConnState> m_state{ ConnState::Stopped };
    std::atomic<bool> m_forceBreak{ false };
    std::thread m_worker;

    std::shared_ptr<UDP> m_current;
    mutable std::mutex m_mutex;

    StateCallback m_onState;
    ConnectedCallback m_onConnected;
    RegisterTokenRejectedCallback m_onTokenRejected;
};
