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

VpnCore::~VpnCore()
{
    stop();
}

bool VpnCore::init(const Config &cfg)
{
    if(is_running()){
        return true;
    }
    m_cfg = cfg;

    if(!m_tun.create_tun(m_cfg.tun_name.c_str())){
        fprintf(stderr, "[VpnCore] create_tun(%s) failed\n", m_cfg.tun_name.c_str());
        return false;
    }
    m_tun_ready = true;
    m_tun.setNoBlock();

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

    if(m_cfg.add_default_route){
        if(!m_adapter.route_add("0.0.0.0", 0, m_cfg.tun_name)){
            fprintf(stderr, "[VpnCore] route_add(0.0.0.0/0 -> %s) failed\n",
                    m_cfg.tun_name.c_str());
            return false;
        }
    }

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

    {
        const char* svc_db = std::getenv("SVC_DB");
        if (svc_db != nullptr && *svc_db != '\0') {
            m_udp.set_service_db(svc_db);
        }
    }

    if(!m_udp.start(m_cfg.listen_ip, m_cfg.listen_port,
                    m_cfg.tun_ip, m_cfg.tun_prefix, m_cfg.max_clients,
                    m_cfg.transport_mode != "tcp")){
        fprintf(stderr, "[VpnCore] udp.start(%s:%u) failed\n",
                m_cfg.listen_ip.c_str(), m_cfg.listen_port);
        stop();
        return false;
    }
    if(m_cfg.transport_mode != "udp" && !m_tcp.start(m_cfg.listen_ip, m_cfg.listen_port)){
        fprintf(stderr, "[VpnCore] tcp.start(%s:%u) failed\n",
                m_cfg.listen_ip.c_str(), m_cfg.listen_port);
        stop();
        return false;
    }
    return true;
}

// 启动 TUN 与传输层，并拉起上下行转发线程
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
    m_running.store(false);
    if(m_thread_t2u.joinable()){
        m_thread_t2u.join();
    }
    if(m_thread_u2t.joinable()){
        m_thread_u2t.join();
    }
    m_udp.stop();
    m_tcp.stop();
    if(m_cfg.add_default_route){
        m_adapter.route_del("0.0.0.0", 0);
    }
    if(m_tun_ready){
        m_adapter.set_down(m_cfg.tun_name);
    }
    m_tun.close();
}

bool VpnCore::is_running() const
{
    return m_running.load();
}

void VpnCore::forward_tun_to_udp()
{
    packet_buffer buf;
    while(m_running.load()){
        if(m_tun.read_buf(buf)){
            if(!buf.is_empty()){
                if(g_packet_log){
                    fprintf(stderr, "[CORE][TUN→UDP] len=%zu\n", buf.data_size());
                }
                if(!m_udp.forward_tun_packet(std::move(buf))){
                    if(g_packet_log){
                        fprintf(stderr, "[CORE][TUN→UDP] no session for dst, drop\n");
                    }
                }
            }
        } else {
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
            m_udp.wait_recv_queue(200);
        }
    }
}
