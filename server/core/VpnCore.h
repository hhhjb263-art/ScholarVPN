#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <cstdint>
#include <cstddef>

#include "../tun/tun.h"
#include "../UDP/UDP.h"
#include "../TCP/tcpserver.h"
#include "../LinuxAdapter/LinuxAdapter.h"

class VpnCore
{
public:
    struct Config
    {
        std::string tun_name = "vpn0";
        std::string tun_ip;
        int tun_prefix = 24;
        int tun_mtu = 1400;
        bool add_default_route = false;

        std::string listen_ip = "0.0.0.0";
        uint16_t listen_port = 51820;

        size_t max_clients = 0;

        std::string key_sig_path = "keys/server_sig.key";
        std::string key_sig_pub_path = "keys/server_sig.pub";

        int gen_tokens = 0;

        std::string transport_mode = "both";
    };

public:
    VpnCore() = default;
    ~VpnCore();

    VpnCore(const VpnCore&) = delete;
    VpnCore &operator=(const VpnCore&) = delete;

    bool init(const Config &cfg);
    bool start();
    void stop();
    bool is_running() const;

private:
    void forward_tun_to_udp();
    void forward_udp_to_tun();

private:
    Config m_cfg;
    Tun m_tun;
    UDP m_udp;
    TCPServer m_tcp{m_udp};
    LinuxAdapter m_adapter;
    std::thread m_thread_t2u;
    std::thread m_thread_u2t;
    std::atomic<bool> m_running{false};
    bool m_tun_ready{false};
};
