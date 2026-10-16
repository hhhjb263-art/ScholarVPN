// ============================================================================
// Agent.h —— admin_agent：部署在 VPN 服务器侧，出站反连 vpn_controller（中转）
// ----------------------------------------------------------------------------
// 职责（计划书 3.5 的 agent 客户端，因"不内嵌 vpn_server"故独立成可执行）：
//   握手准入（Ed25519 签名）→ 心跳保活 → 收 command 帧 → 转发给本机 AdminServer
//   （HTTP+Bearer，业务执行层）→ 回 reply 帧。
// 线协议见 AdminWire.h（明文 TCP + 长度前缀 JSON 帧，一期）。
// 断线指数退避重连：1s 起步、60s 封顶 + 随机抖动（计划书 3.5）。
// ============================================================================
#pragma once

#include <atomic>
#include <cstdint>
#include <string>

#include <openssl/evp.h>

class Agent {
public:
    struct Options {
        std::string controller_host = "127.0.0.1";   // 中转服务器地址
        uint16_t    controller_port = 19090;
        std::string admin_host = "127.0.0.1";        // 本机 AdminServer（业务执行层）
        uint16_t    admin_port = 18080;
        std::string key_path = "keys/server_sig.key";// 本机 Ed25519 身份私钥（准入指纹来源）
        std::string admin_token;                     // 访问本机 AdminServer 的 Bearer
        std::string name;                            // 展示名（可空，controller 回退用指纹前 8 位）
    };

    explicit Agent(Options opt);
    ~Agent();

    Agent(const Agent&) = delete;
    Agent& operator=(const Agent&) = delete;

    // 阻塞运行：连接 → 握手 → 心跳/命令循环；断线自动退避重连，直到 stop()
    void run();
    void stop() { running_.store(false); }

private:
    // 一次完整的连接生命周期。@return true = 收到 stop()（正常收尾），false = 断线需重连
    bool connect_and_serve();
    // 用本机私钥对 controller 下发的挑战签名，返回 128 位 hex（失败返回空串）
    std::string sign_challenge(const std::string& nonce_hex);

    Options opt_;
    std::atomic<bool> running_{ false };
    EVP_PKEY* priv_ = nullptr;      // 本机身份私钥（run 里载入，析构释放）
    std::string pub_hex_;           // 本机身份公钥 hex（hello 上报，controller 据此比对白名单）
};
