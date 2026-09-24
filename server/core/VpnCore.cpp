#include "VpnCore.h"
#include "../Crypt/crypt.h"
#include "log.h"

#include <cstdio>
#include <cstring>
#include <cerrno>
#include <filesystem>
#include <poll.h>
#include <system_error>
#include <chrono>
#include <thread>
#include <utility>   // std::pair（端口判重表）
#include <vector>

VpnCore::~VpnCore()
{
    stop();
}

bool VpnCore::init(const Config &cfg)
{
    if(is_running()){
        return true;   // 已在运行
    }
    m_cfg = cfg;

    // 1) 创建 TUN 虚拟网卡（非阻塞）
    if(!m_tun.create_tun(m_cfg.tun_name.c_str())){
        fprintf(stderr, "[VpnCore] create_tun(%s) failed\n", m_cfg.tun_name.c_str());
        return false;
    }
    m_tun_ready = true;
    m_tun.setNoBlock();

    // 2) 配置网卡地址 / 掩码 / MTU / up
    if(!m_cfg.tun_ip.empty()){
        if(!m_adapter.set_address(m_cfg.tun_name, m_cfg.tun_ip, m_cfg.tun_prefix)){
            fprintf(stderr, "[VpnCore] set_address(%s, %s/%d) failed\n",
                    m_cfg.tun_name.c_str(), m_cfg.tun_ip.c_str(), m_cfg.tun_prefix);
            return false;
        }
    }
    if(!m_adapter.set_mtu(m_cfg.tun_name, m_cfg.tun_mtu)){
        fprintf(stderr, "[VpnCore] set_mtu(%s, %d) failed\n",
                m_cfg.tun_name.c_str(), m_cfg.tun_mtu);
        return false;
    }
    if(!m_adapter.set_up(m_cfg.tun_name)){
        fprintf(stderr, "[VpnCore] set_up(%s) failed\n", m_cfg.tun_name.c_str());
        return false;
    }

    // 3) 可选：把默认路由指向 TUN
    if(m_cfg.add_default_route){
        if(!m_adapter.route_add("0.0.0.0", 0, m_cfg.tun_name)){
            fprintf(stderr, "[VpnCore] route_add(0.0.0.0/0 -> %s) failed\n",
                    m_cfg.tun_name.c_str());
            return false;
        }
    }

    // 4) 服务器持久身份密钥（Ed25519，SIG_SRV_PRI/SIG_SRV_PUB）：首次运行自动生成
    if(!m_cfg.key_sig_path.empty()){
        if(!std::filesystem::exists(m_cfg.key_sig_path)){
            std::error_code ec;
            std::filesystem::path key_dir =
                std::filesystem::path(m_cfg.key_sig_path).parent_path();
            if(!key_dir.empty()){
                std::filesystem::create_directories(key_dir, ec);
            }
            std::string pub_pem;
            if(!generate_ed25519_keypair(m_cfg.key_sig_path, m_cfg.key_sig_pub_path, pub_pem)){
                fprintf(stderr, "[VpnCore] 自动生成服务器身份密钥失败: %s / %s\n",
                        m_cfg.key_sig_path.c_str(), m_cfg.key_sig_pub_path.c_str());
                stop();
                return false;
            }
            fprintf(stderr,
                    "[VpnCore] 首次运行：已自动生成服务器身份密钥 %s / %s\n"
                    "--- 请把以下公钥硬编码进客户端程序（kServerSigPubPem 常量）---\n%s",
                    m_cfg.key_sig_path.c_str(), m_cfg.key_sig_pub_path.c_str(),
                    pub_pem.c_str());
        }
        try {
            EVP_PKEY *priv = load_ed25519_private_key(m_cfg.key_sig_path.c_str());
            std::string keys_dir =
                std::filesystem::path(m_cfg.key_sig_path).parent_path().string();
            m_udp.set_identity(std::shared_ptr<EVP_PKEY>(priv, EVP_PKEY_free), keys_dir);
            fprintf(stderr, "[VpnCore] 已加载服务器身份私钥: %s\n", m_cfg.key_sig_path.c_str());
            // 诊断：打印服务器签名用的公钥指纹（与客户端日志的
            // "客户端验签用的服务器公钥指纹"比对——不一致即密钥配置错误）
            {
                unsigned char raw[32];
                size_t raw_len = sizeof(raw);
                if (EVP_PKEY_get_raw_public_key(priv, raw, &raw_len) == 1) {
                    char hex[65] = { 0 };
                    for (size_t i = 0; i < raw_len && i < 32; ++i)
                        snprintf(hex + i * 2, 3, "%02x", raw[i]);
                    fprintf(stderr, "[VpnCore] 服务器身份公钥指纹: %s\n", hex);
                }
            }
        } catch(const std::exception &e){
            fprintf(stderr, "[VpnCore] 加载身份私钥 %s 失败: %s\n", m_cfg.key_sig_path.c_str(), e.what());
            stop();
            return false;
        }
    } else {
        fprintf(stderr, "[VpnCore] 警告: 未配置服务器身份私钥，身份认证不可用\n");
    }

    // 5) 启动 UDP 隧道（服务端绑定监听，多用户：最大会话数 + 虚拟 IP 池）；
    //    --transport tcp 时跳过 UDP 监听（会话机制仍服务 TCP 会话）
    if(!m_udp.start(m_cfg.listen_ip, m_cfg.listen_port,
                    m_cfg.tun_ip, m_cfg.tun_prefix, m_cfg.max_clients,
                    m_cfg.transport_mode != "tcp")){
        fprintf(stderr, "[VpnCore] udp.start(%s:%u) failed\n",
                m_cfg.listen_ip.c_str(), m_cfg.listen_port);
        stop();
        return false;
    }
    // 6) 启动 TCP 监听（同端口双栈）：运营商丢 UDP 的备用通道；
    //    会话表/认证/加密/心跳与 UDP 共用，客户端按条目选择传输；
    //    --transport udp 时关闭 TCP 监听
    if(m_cfg.transport_mode != "udp" && !m_tcp.start(m_cfg.listen_ip, m_cfg.listen_port)){
        fprintf(stderr, "[VpnCore] tcp.start(%s:%u) failed\n",
                m_cfg.listen_ip.c_str(), m_cfg.listen_port);
        stop();
        return false;
    }
    // 7) 浏览器插件专用代理入口（默认全部关闭）：给 Chrome/Edge MV3 扩展的
    //    chrome.proxy 提供出口，只代理浏览器流量。三个入口独立配置端口：
    //      SOCKS5（明文）/ HTTP CONNECT（明文）/ HTTPS CONNECT（TLS 加密，推荐）
    //
    //    ★ 代理入口失败【不影响主隧道】：Windows / Android 客户端与浏览器插件
    //      要能同时使用，任何一个代理入口配置有误（端口冲突 / 证书缺失 /
    //      未配认证等）只跳过该入口并打印原因，VPN 隧道照常提供服务。
    //
    // ---- 端口判重表：四个监听面共用，撞车只跳过后者并说明与谁冲突 ----
    // 隧道先登记，代理依次登记；任何一处撞车都不再是"莫名的 bind failed"，
    // 而是明确告诉运维"这个端口被谁占了"，避免误判成代理功能坏了。
    std::vector<std::pair<uint16_t, std::string>> used_ports;
    used_ports.emplace_back(m_cfg.listen_port, "VPN 隧道入口");
    const auto find_owner = [&used_ports](uint16_t port) -> const char * {
        for(const auto &kv : used_ports){
            if(kv.first == port)
                return kv.second.c_str();
        }
        return nullptr;
    };

    int proxy_ok = 0;
    int proxy_failed = 0;
    // 三个代理入口的最终状态：末尾汇总逐条打印，便于确认三类客户端是否都可用
    std::string st_socks5 = "未启用";
    std::string st_http = "未启用";
    std::string st_https = "未启用";

    m_socks5.set_allow_private(m_cfg.proxy_allow_private);
    m_socks5.set_allow_noauth(m_cfg.proxy_allow_noauth);
    m_socks5.set_conn_limits(m_cfg.proxy_max_per_source, m_cfg.proxy_conn_rate);
    if(m_cfg.socks5_port != 0){
        const char *owner = find_owner(m_cfg.socks5_port);
        if(owner != nullptr){
            fprintf(stderr, "[VpnCore] SOCKS5 代理端口 %u 已被%s占用，已跳过该入口\n",
                    static_cast<unsigned>(m_cfg.socks5_port), owner);
            st_socks5 = std::string("端口被") + owner + "占用，已跳过";
            ++proxy_failed;
        }else if(m_socks5.start(m_cfg.listen_ip, m_cfg.socks5_port,
                                m_cfg.proxy_user, m_cfg.proxy_pass)){
            used_ports.emplace_back(m_cfg.socks5_port, "SOCKS5 代理");
            st_socks5 = "监听中（明文）";
            ++proxy_ok;
        }else{
            fprintf(stderr, "[VpnCore] SOCKS5 代理入口未启动（不影响 VPN 隧道）："
                            "请检查上面的原因\n");
            st_socks5 = "启动失败（原因见上）";
            ++proxy_failed;
        }
    }
    if(m_cfg.http_proxy_port != 0){
        HttpConnectProxy::Config pc;
        pc.bind_ip = m_cfg.listen_ip;
        pc.port = m_cfg.http_proxy_port;
        pc.use_tls = false;              // 明文 HTTP CONNECT（内网/前置 stunnel）
        pc.user = m_cfg.proxy_user;
        pc.pass = m_cfg.proxy_pass;
        pc.allow_private = m_cfg.proxy_allow_private;
        pc.allow_noauth = m_cfg.proxy_allow_noauth;
        pc.max_per_source = m_cfg.proxy_max_per_source;
        pc.conn_rate_per_sec = m_cfg.proxy_conn_rate;
        const char *owner = find_owner(m_cfg.http_proxy_port);
        if(owner != nullptr){
            fprintf(stderr, "[VpnCore] HTTP 代理端口 %u 已被%s占用，已跳过该入口\n",
                    static_cast<unsigned>(m_cfg.http_proxy_port), owner);
            st_http = std::string("端口被") + owner + "占用，已跳过";
            ++proxy_failed;
        }else if(m_http_proxy.start(pc)){
            used_ports.emplace_back(m_cfg.http_proxy_port, "HTTP 代理");
            st_http = "监听中（明文）";
            ++proxy_ok;
        }else{
            fprintf(stderr, "[VpnCore] HTTP 代理入口未启动（不影响 VPN 隧道）："
                            "请检查上面的原因\n");
            st_http = "启动失败（原因见上）";
            ++proxy_failed;
        }
    }
    if(m_cfg.https_proxy_port != 0){
        HttpConnectProxy::Config pc;
        pc.bind_ip = m_cfg.listen_ip;
        pc.port = m_cfg.https_proxy_port;
        pc.use_tls = true;               // TLS 加密（浏览器插件推荐路径）
        pc.cert_path = m_cfg.https_cert_path;
        pc.key_path = m_cfg.https_key_path;
        pc.user = m_cfg.proxy_user;
        pc.pass = m_cfg.proxy_pass;
        pc.allow_private = m_cfg.proxy_allow_private;
        pc.allow_noauth = m_cfg.proxy_allow_noauth;
        pc.max_per_source = m_cfg.proxy_max_per_source;
        pc.conn_rate_per_sec = m_cfg.proxy_conn_rate;
        const char *owner = find_owner(m_cfg.https_proxy_port);
        if(owner != nullptr){
            fprintf(stderr, "[VpnCore] HTTPS 代理端口 %u 已被%s占用，已跳过该入口\n",
                    static_cast<unsigned>(m_cfg.https_proxy_port), owner);
            st_https = std::string("端口被") + owner + "占用，已跳过";
            ++proxy_failed;
        }else if(m_https_proxy.start(pc)){
            used_ports.emplace_back(m_cfg.https_proxy_port, "HTTPS 代理");
            st_https = "监听中（TLS 加密）";
            ++proxy_ok;
        }else{
            fprintf(stderr, "[VpnCore] HTTPS 代理入口未启动（不影响 VPN 隧道）："
                            "请检查上面的原因\n");
            st_https = "启动失败（原因见上）";
            ++proxy_failed;
        }
    }

    // 启动汇总：逐条列出四个监听面，一眼确认"Windows / Android 走隧道、
    // 浏览器插件走代理"是否都可用。代理入口失败只影响浏览器插件，
    // VPN 隧道（Windows / Android）不受影响——这正是本函数不再 return false 的原因。
    const char *tunnel_proto =
        (m_cfg.transport_mode == "udp") ? "UDP" :
        (m_cfg.transport_mode == "tcp") ? "TCP" : "UDP+TCP";
    const auto entry_line = [&](uint16_t port, const std::string &state){
        char buf[192];
        if(port == 0){
            std::snprintf(buf, sizeof(buf), "%s", state.c_str());   // "未启用"
        }else{
            std::snprintf(buf, sizeof(buf), "%s:%u — %s",
                          m_cfg.listen_ip.c_str(), static_cast<unsigned>(port),
                          state.c_str());
        }
        return std::string(buf);
    };
    fprintf(stderr,
            "[VpnCore] 监听汇总（三类客户端可同时在线）：\n"
            "          · Windows / Android 客户端 → VPN 隧道 %s:%u（%s 同端口）\n"
            "          · 浏览器插件 → SOCKS5 %s\n"
            "          · 浏览器插件 → HTTP   %s\n"
            "          · 浏览器插件 → HTTPS  %s\n"
            "          浏览器代理入口：成功 %d 个，失败 %d 个%s\n",
            m_cfg.listen_ip.c_str(), static_cast<unsigned>(m_cfg.listen_port), tunnel_proto,
            entry_line(m_cfg.socks5_port, st_socks5).c_str(),
            entry_line(m_cfg.http_proxy_port, st_http).c_str(),
            entry_line(m_cfg.https_proxy_port, st_https).c_str(),
            proxy_ok, proxy_failed,
            (proxy_failed > 0 && proxy_ok == 0) ? "（浏览器插件当前不可用，VPN 隧道不受影响）" : "");

    // 代理全部起不来时给出可操作的排查方向——这几条覆盖了绝大多数实际配置错误。
    // 强调"VPN 隧道不受影响"是因为这正是本次改动的目的：三类客户端互不牵连。
    if(proxy_ok == 0 && proxy_failed > 0){
        fprintf(stderr,
                "[VpnCore] 提示：代理入口全部未启动，常见原因——\n"
                "          1) 监听 0.0.0.0 但没配 --proxy-user/--proxy-pass\n"
                "             （无认证不允许对外监听；内网自用可加 --proxy-allow-noauth）\n"
                "          2) HTTPS 入口缺 --https-proxy-cert / --https-proxy-key\n"
                "          3) 端口被占用（见上方「已被…占用」提示，隧道端口也会占位，默认 51820）\n"
                "          Windows / Android 客户端的 VPN 隧道不受影响，仍可正常连接。\n");
    }
    return true;
}

bool VpnCore::start()
{
    if(is_running()){
        return true;
    }
    m_running.store(true);
    try{
        m_thread_t2u = std::thread(&VpnCore::forward_tun_to_udp, this);
        m_thread_u2t = std::thread(&VpnCore::forward_udp_to_tun, this);
    }catch(const std::system_error &e){
        fprintf(stderr, "[VpnCore] start forward threads failed: %s\n", e.what());
        m_running.store(false);
        if(m_thread_t2u.joinable()){
            m_thread_t2u.join();
        }
        if(m_thread_u2t.joinable()){
            m_thread_u2t.join();
        }
        return false;
    }
    return true;
}

void VpnCore::stop()
{
    // 停止转发线程
    m_running.store(false);
    if(m_thread_t2u.joinable()){
        m_thread_t2u.join();
    }
    if(m_thread_u2t.joinable()){
        m_thread_u2t.join();
    }
    // 先停 UDP 收发线程：send_work/heartbeat 是 TCP 发送唤醒钩子的生产者
    // （tcp_tx_wake → TCPServer eventfd），生产者先停，事件线程与钩子
    // 注销的生命周期才无竞争
    m_udp.stop();
    // 再停止 TCP 监听（epoll 事件线程退出并统一关闭全部连接 + 注销唤醒钩子）
    m_tcp.stop();
    // 浏览器插件代理入口（与主隧道无共享状态，顺序无关）
    m_socks5.stop();
    m_http_proxy.stop();
    m_https_proxy.stop();
    // 清理路由与网卡（仅在 TUN 创建成功后才做网卡操作）
    if(m_cfg.add_default_route){
        m_adapter.route_del("0.0.0.0", 0);
    }
    if(m_tun_ready){
        m_adapter.set_down(m_cfg.tun_name);
    }
    // 关闭 TUN
    m_tun.close();
}

bool VpnCore::is_running() const
{
    return m_running.load();
}

// 转发层 —— 两条数据通路（各一个线程）：
//   forward_tun_to_udp  (下行): TUN 收包 → 按目的虚拟 IP 查会话 → 加密发给对应客户端
//   forward_udp_to_tun  (上行): 会话解密后的包 → 写 TUN → 内核按路由/NAT 送出
// 谁发给谁完全由"虚拟 IP → 会话"表决定，这就是多用户转发的核心。
// tun → UDP：读虚拟网卡上的 IP 包，按目的虚拟 IP 查会话转发到对应客户端
void VpnCore::forward_tun_to_udp()
{
    packet_buffer buf;
    while(m_running.load()){
        if(m_tun.read_buf(buf)){
            if(!buf.is_empty()){
                if(g_packet_log){
                    fprintf(stderr, "[CORE][TUN→UDP] len=%zu\n", buf.data_size());
                }
                // 无匹配会话（目的 IP 未分配 / 客户端不在线）则丢弃；
                // 目标会话发送队列满则断开该会话（见 forward_tun_packet）
                if(!m_udp.forward_tun_packet(std::move(buf))){
                    if(g_packet_log){
                        fprintf(stderr, "[CORE][TUN→UDP] no session for dst, drop\n");
                    }
                }
            }
        } else {
            // TUN 无数据（非阻塞 EAGAIN）：poll 等待 fd 可读（事件驱动，
            // 替代 1ms sleep 轮询），200ms 超时兜底检查 m_running
            struct pollfd pfd{};
            pfd.fd = m_tun.get_fd();
            pfd.events = POLLIN;
            if(pfd.fd >= 0){
                poll(&pfd, 1, 200);
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            }
        }
    }
}

// UDP → tun：从 UDP 接收队列取 IP 包，写入虚拟网卡
void VpnCore::forward_udp_to_tun()
{
    packet_buffer buf;
    while(m_running.load()){
        if(m_udp.recv_ip_packet(buf)){
            if(!buf.is_empty()){
                if(g_packet_log){
                    fprintf(stderr, "[CORE][UDP→TUN] len=%zu\n", buf.data_size());
                }
                m_tun.write_buf(buf);
            }
        } else {
            // UDP 接收队列空：条件等待入队唤醒（事件驱动，替代 1ms sleep 轮询）
            m_udp.wait_recv_queue(200);
        }
    }
}
