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

#include "AdminWire.h"

class Controller {
public:
    struct Options {
        std::string agent_bind = "0.0.0.0";
        uint16_t    agent_port = 19090;
        std::string http_bind = "127.0.0.1";
        uint16_t    http_port = 18081;
        std::string admin_token;
        std::string agents_file = "agents.txt";
        std::string tls_cert;
        std::string tls_key;
    };

    explicit Controller(Options opt);
    ~Controller();

    Controller(const Controller&) = delete;
    Controller& operator=(const Controller&) = delete;

    bool start();
    void run();
    void stop();

private:
    struct Agent {
        wire::Conn conn;
        std::string id;
        std::string pubkey_hex;
        std::string ip;
        long long connected_at = 0;
        long long last_seen = 0;
        wire::Framer fr;

        std::mutex wmtx;

        std::mutex pmtx;
        std::condition_variable pcv;
        long long pending_id = 0;
        bool pending_done = false;
        int pending_status = 0;
        std::string pending_body;
    };

    void agent_loop();
    bool in_whitelist(const std::string& pubkey_hex) const;
    std::shared_ptr<Agent> find_agent(const std::string& id) const;

    bool forward(const std::string& server_id, const std::string& method,
                 const std::string& path, const std::string& body,
                 int& status, std::string& resp_body, std::string& err);

    struct HttpReq {
        std::string method, path, body;
        std::unordered_map<std::string, std::string> headers;
    };
    void http_loop();
    void handle_http(int fd, const std::string& raw, const std::string& ip);
    bool check_auth(const HttpReq& req) const;

    Options opt_;
    std::atomic<bool> running_{ false };
    int agent_fd_ = -1;
    int http_fd_ = -1;
    SSL_CTX* tls_ctx_ = nullptr;
    std::thread agent_thread_;
    std::thread http_thread_;

    std::vector<std::string> whitelist_;
    mutable std::mutex mtx_;
    std::unordered_map<std::string, std::shared_ptr<Agent>> agents_;
};
