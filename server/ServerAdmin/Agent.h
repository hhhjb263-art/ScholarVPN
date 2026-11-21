#pragma once

#include <atomic>
#include <cstdint>
#include <string>

#include <openssl/evp.h>
#include <openssl/ssl.h>

class Agent {
public:
    struct Options {
        std::string controller_host = "127.0.0.1";
        uint16_t    controller_port = 19090;
        std::string admin_host = "127.0.0.1";
        uint16_t    admin_port = 18080;
        std::string key_path = "keys/server_sig.key";
        std::string admin_token;
        std::string name;
        bool tls = false;
        std::string tls_ca;
        std::string tls_server_name;
    };

    explicit Agent(Options opt);
    ~Agent();

    Agent(const Agent&) = delete;
    Agent& operator=(const Agent&) = delete;

    void run();
    void stop() { running_.store(false); }

private:
    bool connect_and_serve();
    std::string sign_challenge(const std::string& nonce_hex);

    Options opt_;
    std::atomic<bool> running_{ false };
    EVP_PKEY* priv_ = nullptr;
    SSL_CTX* tls_ctx_ = nullptr;
    std::string pub_hex_;
};
