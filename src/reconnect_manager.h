#pragma once

#include <atomic>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "UDP.h"
#include "Crypt.h"

// 连接状态机
enum class ConnState
{
    Stopped = 0,   // 未启动 / 已停止
    Connecting,    // 首次连接中（正在握手）
    Connected,     // 握手成功，数据通路可用
    Reconnecting,  // 检测到断线，正在退避重连
    Error,         // 参数错误等不可恢复错误
};

// 重连管理：负责 UDP 隧道的创建、握手等待、断线检测与自动重连。
// 每次连接使用全新的 UDP 实例（旧实例 stop() 后队列不可复用），
// 泵线程应通过 udp() 每次获取当前实例。
class ReconnectManager
{
public:
    using StateCallback = std::function<void(ConnState)>;
    using ConnectedCallback = std::function<void()>;
    // 注册模式被拒且原因=令牌无效/已使用 时触发（已自动清除令牌，下次以登录模式重试）
    using RegisterTokenRejectedCallback = std::function<void()>;

    ReconnectManager(std::string remoteIp, uint16_t port, size_t queueMax = 256);
    ~ReconnectManager();

    ReconnectManager(const ReconnectManager&) = delete;
    ReconnectManager& operator=(const ReconnectManager&) = delete;

    // 配置身份（三阶段认证），每次连接时转发给新的 UDP 实例
    void set_identity(std::shared_ptr<EVP_PKEY> ed25519_priv,
                      const std::string& server_sig_pub_pem,
                      const std::string& client_id,
                      const std::string& register_token);

    bool start();                       // 启动重连状态机（首次连接）
    void stop();                        // 停止并清理

    ConnState state() const { return m_state.load(); }
    std::shared_ptr<UDP> udp() const;   // 当前隧道；未建立时返回 nullptr

    void set_state_callback(StateCallback cb);
    void set_connected_callback(ConnectedCallback cb);
    void set_register_token_rejected_callback(RegisterTokenRejectedCallback cb);
    // 注册成功后调用：清除内存中的令牌，后续重连直接走登录
    void clear_register_token() { m_register_token.clear(); }

    // 选择传输方式（必须在 start() 之前调用；默认 UDP）
    void set_transport(Transport t) { m_transport = t; }

    // 测试用：模拟一次断线，触发状态机自动重连
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
    Transport m_transport{ Transport::UDP };   // 传输方式：UDP（默认）/ TCP

    // 身份（三阶段认证）
    std::shared_ptr<EVP_PKEY> m_ed25519_priv;      // 客户端身份私钥 SIG_CLI_PRI
    std::string m_server_sig_pub_pem;              // 内置服务器身份公钥 PEM
    std::string m_client_id;                       // 客户端标识
    std::string m_register_token;                  // 一次性注册令牌（空=登录）

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