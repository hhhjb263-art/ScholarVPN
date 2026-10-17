// ============================================================================
// Controller.h —— vpn_controller（中转/控制面）
// ----------------------------------------------------------------------------
// 只实现「VPN 服务器 ↔ 中转服务器」这一段的业务接口（用户明确：客户端无需实现）：
//   · agent 通道：接受各 VPN 服务器**出站**反连，Ed25519 指纹白名单准入，心跳保活
//   · 业务转发：把 info / tokens 四个操作原样转发给指定 agent 并回传结果
//   · 一个最小的 HTTP 入口（JSON，非 Web 页）用于驱动转发——完整管理端后续再接
// 线协议见 AdminWire.h（明文 TCP + 长度前缀 JSON 帧，一期）。
// ============================================================================
#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "AdminWire.h"   // wire::Framer：每条 agent 连接各自的收帧缓冲

class Controller {
public:
    struct Options {
        std::string agent_bind = "0.0.0.0";   // agent 通道监听地址
        uint16_t    agent_port = 19090;
        std::string http_bind = "127.0.0.1";  // 最小 HTTP 入口（默认仅环回）
        uint16_t    http_port = 18081;
        std::string admin_token;              // HTTP 入口的 Bearer（空 = 不鉴权，仅限本机调试）
        std::string agents_file = "agents.txt"; // 允许接入的 agent 公钥指纹（每行一个 hex）
    };

    explicit Controller(Options opt);
    ~Controller();

    Controller(const Controller&) = delete;
    Controller& operator=(const Controller&) = delete;

    bool start();   // 读白名单 + 起 agent 通道 + 起 HTTP 入口
    void run();     // 阻塞运行（HTTP 在调用线程，agent 通道在内部线程）
    void stop();

private:
    // 一个已接入的 agent
    struct Agent {
        int fd = -1;
        std::string id;            // 展示名（agent 自报；空则用指纹前 8 位）
        std::string pubkey_hex;
        std::string ip;
        long long connected_at = 0;
        long long last_seen = 0;
        wire::Framer fr;           // 本连接的收帧缓冲（半包续读）

        std::mutex wmtx;           // 串行化对 fd 的写（命令帧不能交错）

        // 一次一条在途命令（管理流量极低，够用）
        std::mutex pmtx;
        std::condition_variable pcv;
        long long pending_id = 0;
        bool pending_done = false;
        int pending_status = 0;
        std::string pending_body;
    };

    // ---- agent 通道 ----
    void agent_loop();
    bool in_whitelist(const std::string& pubkey_hex) const;
    std::shared_ptr<Agent> find_agent(const std::string& id) const;

    // ---- 业务转发（"vpn服务器 ↔ 中转" 的核心接口）----
    // @return true = 拿到 agent 回传结果（status/resp_body 有效）；false = 失败（err 说明）
    bool forward(const std::string& server_id, const std::string& method,
                 const std::string& path, const std::string& body,
                 int& status, std::string& resp_body, std::string& err);

    // ---- 最小 HTTP 入口 ----
    struct HttpReq {
        std::string method, path, body;
        std::unordered_map<std::string, std::string> headers;   // key 小写
    };
    void http_loop();
    void handle_http(int fd, const std::string& raw, const std::string& ip);
    bool check_auth(const HttpReq& req) const;

    Options opt_;
    std::atomic<bool> running_{ false };
    int agent_fd_ = -1;
    int http_fd_ = -1;
    std::thread agent_thread_;
    std::thread http_thread_;

    std::vector<std::string> whitelist_;
    mutable std::mutex mtx_;
    std::unordered_map<std::string, std::shared_ptr<Agent>> agents_;
};
