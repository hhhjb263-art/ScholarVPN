#pragma once

#include <string>
#include <thread>
#include <atomic>
#include <cstdint>
#include <cstddef>

#include "../tun/tun.h"
#include "../UDP/UDP.h"
#include "../TCP/tcpserver.h"
#include "../Socks5/socks5.h"
#include "../HttpsProxy/httpsproxy.h"
#include "../LinuxAdapter/LinuxAdapter.h"

// VPN 核心（服务端）：把 TUN 虚拟网卡与 UDP 隧道桥接起来。
// 转发层两条数据通路：
//   1) tun → UDP : forward_tun_to_udp() 线程循环 tun.read_buf() 读到 IP 包
//                  → udp.send_ip_packet() 推入发送队列，由 UDP.send_thread 封装隧道头发给对端
//   2) UDP → tun : forward_udp_to_tun() 线程循环 udp.recv_ip_packet() 从接收队列取出
//                  → tun.write_buf() 写入虚拟网卡
// 生命周期：init(建TUN+配地址+启动UDP收发线程) → start(启动转发线程) → stop(停止+清理)
class VpnCore
{
public:
    struct Config
    {
        // TUN 网卡
        std::string tun_name = "vpn0";
        std::string tun_ip;             // 隧道内网 IP，如 10.8.0.1
        int tun_prefix = 24;
        int tun_mtu = 1400;
        bool add_default_route = false; // 是否把默认路由指向 TUN

        // 服务端监听配置
        std::string listen_ip = "0.0.0.0";
        uint16_t listen_port = 51820;

        // 多用户：最大并发客户端数（0=默认 64），服务端自动为每个客户端分配虚拟 IP
        size_t max_clients = 0;

        // 身份认证：服务器持久 Ed25519 身份密钥（SIG_SRV_PRI / SIG_SRV_PUB）
        std::string key_sig_path = "keys/server_sig.key";
        std::string key_sig_pub_path = "keys/server_sig.pub";

        // 管理员：--gen-token 一次性注册令牌数量（>0 时生成后退出）
        int gen_tokens = 0;

        // 传输开关：both（默认，同端口双栈）/ udp（禁用 TCP 监听）/ tcp（禁用 UDP 监听）
        std::string transport_mode = "both";

        // 浏览器插件专用代理入口（默认全部关闭）：给 MV3 扩展的 chrome.proxy
        // 提供出口，只代理浏览器流量、不安装系统级 VPN。
        //   --socks5-port      SOCKS5（标准协议，链路明文，最快）
        //   --http-proxy-port  HTTP CONNECT（明文；仅内网/前置 stunnel 用）
        //   --https-proxy-port HTTPS CONNECT（TLS 加密，公网推荐；需证书）
        // proxy_user 非空则三个入口都要求认证
        uint16_t socks5_port = 0;       // 0 = 不启用
        uint16_t http_proxy_port = 0;
        uint16_t https_proxy_port = 0;
        std::string https_cert_path;    // TLS 证书链（PEM）
        std::string https_key_path;     // TLS 私钥（PEM）
        std::string proxy_user;         // 三个代理入口共用
        std::string proxy_pass;
        // 目标地址 ACL：默认（false）拒绝代理访问服务端内网/回环/链路本地/
        // 组播/TUN 网段目标；true = 内网自用场景放行（--proxy-allow-private）
        bool proxy_allow_private = false;
    };

public:
    VpnCore() = default;
    ~VpnCore();

    VpnCore(const VpnCore&) = delete;
    VpnCore &operator=(const VpnCore&) = delete;

    // 初始化：建 TUN → 配置地址/MTU/up →（可选）路由 → udp.start() 启动收发线程
    bool init(const Config &cfg);
    // 启动 TUN↔UDP 两条转发线程（转发层）
    bool start();
    // 停止全部并清理：停转发线程、udp.stop()、down 网卡、删路由
    void stop();
    bool is_running() const;

private:
    // 转发层
    void forward_tun_to_udp();     // 通读TUN: 读 IP 包 → udp.send_ip_packet()
    void forward_udp_to_tun();     // 通读UDP: udp.recv_ip_packet() → tun.write_buf()

private:
    Config m_cfg;
    Tun m_tun;                     // 虚拟网卡
    UDP m_udp;                     // UDP 隧道（服务端：绑定监听，含会话表/认证/心跳）
    TCPServer m_tcp{m_udp};        // TCP 监听（同端口双栈，会话表与 UDP 共用）
    Socks5Proxy m_socks5;          // 浏览器插件专用 SOCKS5 代理（默认关闭）
    HttpConnectProxy m_http_proxy;   // 浏览器插件专用 HTTP CONNECT 代理（明文）
    HttpConnectProxy m_https_proxy;  // 浏览器插件专用 HTTPS CONNECT 代理（TLS 加密）
    LinuxAdapter m_adapter;        // 系统网卡配置（IP/MTU/路由）
    std::thread m_thread_t2u;      // 转发线程1: tun → udp
    std::thread m_thread_u2t;      // 转发线程2: udp → tun
    std::atomic<bool> m_running{false};
    bool m_tun_ready{false};       // TUN 是否已成功创建（控制网卡清理）
};
