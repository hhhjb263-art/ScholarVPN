#include "UDP.h"
#include "../Crypt/crypt.h"
#include "../core/log.h"
#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <system_error>
#include <openssl/rand.h>
#include <utility>
#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <iostream>
#include <random>
#include <chrono>
#include <thread>

// 数据包级日志开关：1=打印每个收发数据包（诊断用），0=只打关键事件
/*
虚拟网卡 IP 数据包 → send_ip_packet → 封装隧道协议头 → 
推入 m_queue_send 发送队列 → send_thread 线程循环取出，通过 UDP socket 发给对端 VPN 服务 / 客户端
*/



// ===================== 握手负载（模仿 TCP 的 ISN/ACK 语义） =====================
// 三次握手（客户端视角）：
//   1) SYN     : type = m_hand_request , payload = { isn = 本端ISN,   ack = 0           }
//   2) SYN+ACK : type = m_hand_response, payload = { isn = 对端ISN,   ack = 本端ISN + 1 }
//   3) ACK     : type = m_hand_response, payload = { isn = 0,         ack = 对端ISN + 1 }
// 说明：
//   - ack 是确认号，指向对方 ISN 的下一个序号（等价于 TCP 的 ACK Number）；
//   - isn == 0 表示纯 ACK 包（不含 SYN 语义），用于区分 SYN+ACK 与 ACK；
//   - 握手期间 header.sequence 仅作参考，以负载中的 isn/ack 为准。
namespace{
    // 心跳保活参数
    constexpr auto kHeartbeatInterval = std::chrono::seconds(10);   // 每 10s 发一次心跳
    constexpr auto kHeartbeatTimeout  = std::chrono::seconds(30);   // 30s 未收到对端响应判超时

    // 当前 steady_clock 毫秒时间戳
    uint64_t now_ms()
    {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
    }

    // ===== 密钥交换辅助（X25519 + HKDF + AES-256-GCM）=====

    bool get_raw_pubkey(EVP_PKEY* pkey, std::vector<uint8_t>& out)
    {
        if (pkey == nullptr)
            return false;
        size_t len = 0;
        if (EVP_PKEY_get_raw_public_key(pkey, nullptr, &len) != 1)
            return false;
        out.resize(len);
        return EVP_PKEY_get_raw_public_key(pkey, out.data(), &len) == 1;
    }

    EVP_PKEY* make_x25519_public_key(const uint8_t* raw, size_t len)
    {
        return EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, raw, len);
    }

    EVP_PKEY* make_ed25519_public_key(const uint8_t* raw, size_t len)
    {
        return EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, raw, len);
    }

    // 生成一次性临时 X25519 密钥对（每次会话独立，前向安全）
    bool generate_ephemeral_x25519(EVP_PKEY*& priv_out, std::vector<uint8_t>& pub_out)
    {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_from_name(nullptr, "X25519", nullptr);
        if (ctx == nullptr)
            return false;
        if (EVP_PKEY_keygen_init(ctx) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        EVP_PKEY* key = nullptr;
        if (EVP_PKEY_keygen(ctx, &key) <= 0) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
        EVP_PKEY_CTX_free(ctx);
        if (!get_raw_pubkey(key, pub_out)) {
            EVP_PKEY_free(key);
            return false;
        }
        priv_out = key;
        return true;
    }
}

UDP::~UDP()
{
    close();
}

UDP::UDP(UDP&& other) noexcept
{
    std::scoped_lock lock(m_client_mutex, other.m_client_mutex);
    m_sock = std::exchange(other.m_sock, -1);
    m_dh_srv_priv = std::exchange(other.m_dh_srv_priv, nullptr);

    // 客户端地址
    clt_addr = other.clt_addr;
    clt_len = other.clt_len;

    // 移动线程&队列
    send_thread = std::move(other.send_thread);
    recv_thread = std::move(other.recv_thread);
    heartbeat_thread = std::move(other.heartbeat_thread);
    m_queue_send = std::move(other.m_queue_send);
    m_queue_recv = std::move(other.m_queue_recv);

    m_running.store(other.m_running.load());
    m_has_client.store(other.m_has_client.load());
    m_handshaked.store(other.m_handshaked.load());
    m_need_connect.store(other.m_need_connect.load());
    m_seq.store(other.m_seq.load());
    m_last_heartbeat_ms.store(other.m_last_heartbeat_ms.load());
    // 清空源对象
    other.clt_addr = {};
    other.clt_len = 0;
    other.m_dh_srv_priv = nullptr;
    other.m_running.store(false);
    other.m_has_client.store(false);
    other.m_handshaked.store(false);
    other.m_need_connect.store(false);
    other.m_seq.store(0);
    other.m_last_heartbeat_ms.store(0);
}
UDP &UDP::operator=(UDP&& other) noexcept
{
    if(this != &other){
        std::scoped_lock lock(m_client_mutex, other.m_client_mutex);

        m_sock = other.m_sock;
        clt_addr = other.clt_addr;
        clt_len = other.clt_len;
        if (m_dh_srv_priv != nullptr) {
            EVP_PKEY_free(m_dh_srv_priv);
        }
        m_dh_srv_priv = std::exchange(other.m_dh_srv_priv, nullptr);
        m_has_client.store(other.m_has_client.load());
        m_handshaked.store(other.m_handshaked.load());
        m_need_connect.store(other.m_need_connect.load());
        m_seq.store(other.m_seq.load());
        m_last_heartbeat_ms.store(other.m_last_heartbeat_ms.load());

        ::close(other.m_sock);
        other.m_sock = -1;
        other.m_has_client = false;
        other.clt_addr = {};
        other.clt_len = 0;
        other.m_handshaked.store(false);
        other.m_need_connect.store(false);
        other.m_seq.store(0);
        other.m_last_heartbeat_ms.store(0);
    }
    return *this;
}

void UDP::stop()
{
    if(!m_running.exchange(false)){
        // 未运行：仍回收可能残留的线程与 socket
        stop_threads();
        close();
        return;
    }
    // 先置位停止标志，再 shutdown 唤醒可能阻塞的系统调用
    if(m_sock >= 0){
        ::shutdown(m_sock, SHUT_RDWR);
    }
    stop_threads();
    close();
    // 清理认证状态与全部会话密钥
    reset_auth_state();
}

void UDP::close()
{
    if(m_sock< 0){
        return;
    }
    ::shutdown(m_sock,SHUT_RDWR);
    ::close(m_sock);
    m_sock = -1;
}

bool UDP::is_running() const    
{
    return m_running.load() == true;
}

bool UDP::is_handshaked() const
{
    return m_handshaked.load() == true;
}

bool UDP::set_peer(const std::string &ip, uint16_t port)
{
    m_sock = socket(AF_INET,SOCK_DGRAM,IPPROTO_UDP);
    if(m_sock < 0){
        fprintf(stderr, "[UDP] socket() failed: %s\n", strerror(errno));
        return false;
    }
    int reuse = 1;
    if(setsockopt(m_sock,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse)) < 0){
        fprintf(stderr, "[UDP] setsockopt(SO_REUSEADDR) failed: %s\n", strerror(errno));
    }
    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    
    if(ip.empty() || ip == "0.0.0.0"){
        server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    }else{
        int ret = inet_pton(AF_INET,ip.c_str(),&server_addr.sin_addr);
        if(ret != 1){
            fprintf(stderr, "[UDP] inet_pton(%s) failed: %s\n", ip.c_str(),
                    (ret == 0) ? "invalid address" : "unsupported family");
            close();
            return false;
        }
    }
    if(bind(m_sock,(struct sockaddr*)&server_addr,sizeof(server_addr)) < 0){
        fprintf(stderr, "[UDP] bind(%s:%u) failed: %s\n", ip.c_str(), port, strerror(errno));
        close();
        return false;
    }
    return true;
}

bool UDP::start(const std::string &local_ip, uint16_t local_port)
{
    if(is_running()){
        return true;   // 已在运行
    }
    // 服务端：绑定本地端口监听
    if(!set_peer(local_ip, local_port)){
        fprintf(stderr, "[UDP] start: set_peer(%s:%u) failed\n", local_ip.c_str(), local_port);
        return false;
    }
    // 非阻塞：让 recv_work 的 EAGAIN 分支生效，stop() 可快速退出
    int flags = fcntl(m_sock, F_GETFL, 0);
    if(flags != -1){
        fcntl(m_sock, F_SETFL, flags | O_NONBLOCK);
    }
    m_running.store(true);
    m_handshaked.store(false);
    m_need_connect.store(false);
    m_has_client.store(false);
    m_last_heartbeat_ms.store(0);
    reset_auth_state();
    if(!start_threads()){
        fprintf(stderr, "[UDP] start: start_threads failed\n");
        m_running.store(false);
        close();
        return false;
    }
    return true;
}

bool UDP::send_ip_packet(packet_buffer &&buf)
{
    if(!is_running()){
        return false;
    }
   return m_queue_send.push(std::move(buf));
}

bool UDP::send_packet(uint8_t type, const uint8_t *data, size_t len, std::vector<uint8_t> &tmp_buf)
{
    if(len > VPN_MTU)
        return false;
    size_t total_len = Ktunnel_header + len;
    tmp_buf.resize(total_len);
    tunnel_header hdr{};
    memset(&hdr,0,sizeof(hdr));
    hdr.magic = Kmagic;
    hdr.version = Kversion;
    hdr.type = type;
    hdr.payload_len = htons(static_cast<uint16_t>(len));
    uint32_t seq = m_seq.fetch_add(1);
    hdr.sequence = htonl(seq);
    memcpy(tmp_buf.data(),&hdr,Ktunnel_header);
    // 数据面加密：m_data / m_heart / m_heart_response / m_identity 等在密钥就绪后以密文发送（服务端用 k_s2c）
    if((type == static_cast<uint8_t>(m_data) ||
        type == static_cast<uint8_t>(m_heart) ||
        type == static_cast<uint8_t>(m_heart_response) ||
        type == static_cast<uint8_t>(m_identity) ||
        type == static_cast<uint8_t>(m_identity_ok) ||
        type == static_cast<uint8_t>(m_identity_deny))){
        // inner = [type][data]；AAD = 外层头（前 Ktunnel_header 字节）
        if(!m_enc_ready.load()){
            fprintf(stderr, "[UDP] 密钥未就绪，无法加密发送 type=%d\n", type);
            return false;
        }
        std::vector<uint8_t> inner;
        inner.reserve(1 + len);
        inner.push_back(type);
        if(len)
            inner.insert(inner.end(), data, data + len);
        // AAD = the header actually sent: set payload_len to ciphertext length BEFORE encrypting
        hdr.payload_len = htons(static_cast<uint16_t>(len + 1 + AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN));
        memcpy(tmp_buf.data(),&hdr,Ktunnel_header);
        std::vector<uint8_t> enc;
        try {
            enc = aes256_gcm_encrypt(m_key_s2c, inner.data(), inner.size(),
                                     tmp_buf.data(), Ktunnel_header);
        } catch(const std::exception &e){
            fprintf(stderr, "[UDP] 加密失败: %s\n", e.what());
            return false;
        }
        if(Ktunnel_header + enc.size() > KMax_packet_size){
            fprintf(stderr, "[UDP] 加密后包过大: %zu\n", enc.size());
            return false;
        }
        // 更新 payload_len 为密文长度

        tmp_buf.resize(Ktunnel_header + enc.size());
        memcpy(tmp_buf.data() + Ktunnel_header, enc.data(), enc.size());
        total_len = Ktunnel_header + enc.size();
    } else {
        if(len)
            memcpy(tmp_buf.data() + Ktunnel_header,data,len);
    }
    int ret = sendto(m_sock,tmp_buf.data(),total_len,0,(struct sockaddr*)&clt_addr,(socklen_t)clt_len);
    if(ret == -1){
        fprintf(stderr, "[UDP] sendto() failed: %s\n", strerror(errno));
        m_need_connect.store(true);
        return false;
    }
    if(static_cast<size_t>(ret) != total_len){
        fprintf(stderr, "[UDP] sendto() partial send: %d / %zu bytes\n", ret, total_len);
        m_need_connect.store(true);
        return false;
    }
    return true;
}

bool UDP::recv_ip_packet(packet_buffer &buf)
{
    if(!is_running()){
        return false;
    }
    return m_queue_recv.pop(buf);
}
void UDP::send_work()
{
    std::vector<uint8_t> sendbuf;
    sendbuf.reserve(KMax_packet_size);
    packet_buffer buf;

    while(is_running()){
        // data plane must be encrypted: wait for key exchange to finish
        if(!is_handshaked() || !m_enc_ready.load()){
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        if(!m_queue_send.pop(buf)){
            // 队列空：短暂休眠再取，避免忙轮询，线程保持运行
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        if(buf.is_empty()){
            continue;
        }
        size_t pay_size = buf.data_size();
        if(pay_size > Max_payload_len){
            buf.clear();
            continue;
        }
if(g_packet_log){
            fprintf(stderr, "[UDP][TX] 发送数据 len=%zu\n", pay_size);
        }
        if(!send_packet(m_data,buf.get_data(),pay_size,sendbuf)){
            m_need_connect.store(true);
            break;
        }
        buf.clear();
    }
}

void UDP::recv_work()
{
    std::vector<uint8_t> recvbuf;
    std::vector<uint8_t> sendbuf;
    sendbuf.reserve(KMax_packet_size);
    recvbuf.reserve(KMax_packet_size + 64);
    sockaddr_in peer_addr{};

    while(is_running()){
        recvbuf.resize(KMax_packet_size);
        socklen_t peer_addr_size = sizeof(peer_addr);

        int ret = recvfrom(m_sock, recvbuf.data(), recvbuf.size(), 0,
                           (struct sockaddr*)&peer_addr, &peer_addr_size);
        if(ret <= 0){
            if(errno == EAGAIN || errno == EWOULDBLOCK){
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;   // 非阻塞下无数据，短暂休眠后重试
            }
            fprintf(stderr, "[UDP] recvfrom() failed: %s\n", strerror(errno));
            m_need_connect.store(true);
            break;
        }
        if(ret < static_cast<int>(Ktunnel_header)){
            fprintf(stderr, "[UDP] packet too short: %d < %zu bytes\n", ret, Ktunnel_header);
            continue;   // 包太短
        }

        // 解析隧道头
        tunnel_header hdr{};
        memcpy(&hdr, recvbuf.data(), Ktunnel_header);
        if(hdr.magic != Kmagic || hdr.version != Kversion){
            fprintf(stderr, "[UDP] bad header: magic=%#x version=%u (expected magic=%#x version=%u)\n",
                    hdr.magic, hdr.version, Kmagic, Kversion);
            continue;
        }

        size_t pay_len = ntohs(hdr.payload_len);
        if(pay_len > Max_payload_len || pay_len + Ktunnel_header > static_cast<size_t>(ret)){
            fprintf(stderr, "[UDP] invalid payload_len=%zu (received %d bytes)\n", pay_len, ret);
            continue;
        }
        // 记录对端地址: 后续 sendto 需要用它作为目标
        clt_addr = peer_addr;
        clt_len = peer_addr_size;
if(g_packet_log){
            {
                char ipstr[INET_ADDRSTRLEN] = {0};
                inet_ntop(AF_INET, &peer_addr.sin_addr, ipstr, sizeof(ipstr));
                fprintf(stderr, "[UDP][RX] type=%d len=%zu from=%s:%u\n",
                        hdr.type, pay_len, ipstr, ntohs(peer_addr.sin_port));
            }
        }

        // ===== 加密类型：密钥就绪后 m_data / m_heart / m_identity 等均为密文 =====
        if(hdr.type == static_cast<uint8_t>(m_data) ||
           hdr.type == static_cast<uint8_t>(m_heart) ||
           hdr.type == static_cast<uint8_t>(m_heart_response) ||
           hdr.type == static_cast<uint8_t>(m_identity) ||
           hdr.type == static_cast<uint8_t>(m_identity_ok) ||
           hdr.type == static_cast<uint8_t>(m_identity_deny)){
            if(!m_enc_ready.load()){
                fprintf(stderr, "[UDP] 密钥未就绪，丢弃加密数据 type=%d len=%zu\n", hdr.type, pay_len);
                continue;
            }
            std::vector<uint8_t> enc(recvbuf.data() + Ktunnel_header,
                                     recvbuf.data() + Ktunnel_header + pay_len);
            std::optional<std::vector<uint8_t>> plain;
            try {
                plain = aes256_gcm_decrypt(m_key_c2s, enc, recvbuf.data(), Ktunnel_header);
            } catch(const std::exception &e){
                fprintf(stderr, "[UDP] 解密异常: %s\n", e.what());
                continue;
            }
            if(!plain){
                fprintf(stderr, "[UDP] 解密认证失败，丢弃\n");
                continue;
            }
            uint8_t inner_type = 0;
            std::vector<uint8_t> inner_payload;
            if(!parse_inner_packet(*plain, inner_type, inner_payload)){
                continue;
            }
            switch(inner_type){
            case m_data:
                if(inner_payload.empty())
                    break;
                m_last_heartbeat_ms.store(now_ms());   // 数据包也算对端存活
if(g_packet_log){
                    fprintf(stderr, "[UDP][RX] 数据包入队 len=%zu\n", inner_payload.size());
                }
                m_queue_recv.push(packet_buffer(std::move(inner_payload)));
                break;
            case m_heart:
                m_last_heartbeat_ms.store(now_ms());
                fprintf(stderr, "[UDP] 收到心跳\n");
                send_packet(static_cast<uint8_t>(m_heart_response), nullptr, 0, sendbuf);
                break;
            case m_heart_response:
                m_last_heartbeat_ms.store(now_ms());
                fprintf(stderr, "[UDP] 收到心跳确认\n");
                break;
            case m_identity:
                // 阶段3：身份报文（验签 + 注册/登录）
                handle_identity(inner_payload);
                break;
            case m_identity_ok:
            case m_identity_deny:
                // 服务端角色不应收到这些，忽略
                break;
            default:
                break;
            }
            continue;
        }

        // ===== 明文类型：三阶段认证（阶段1）/ 断开 =====
        switch(hdr.type)
        {
        case m_auth_hello:
            // 阶段1a：客户端 nonce_c → 生成 nonce_s + 临时DH + 签名响应
            fprintf(stderr, "[UDP][AUTH] 收到 nonce_c，回复签名 ServerHello\n");
            handle_auth_hello(recvbuf.data() + Ktunnel_header, pay_len);
            break;
        case m_auth_client_hello:
            // 阶段1b+2：客户端临时DH公钥 → ECDH + HKDF 派生会话密钥
            fprintf(stderr, "[UDP][AUTH] 收到客户端临时DH公钥，派生会话密钥\n");
            handle_auth_client_hello(recvbuf.data() + Ktunnel_header, pay_len);
            break;
        case m_data:
            {
                if(!is_handshaked()){
                    break;
                }
                m_last_heartbeat_ms.store(now_ms());   // 数据包也算对端存活
if(g_packet_log){
                    fprintf(stderr, "[UDP][RX] 数据包入队 len=%zu\n", pay_len);
                }
                // 将 IP 数据包推入接收队列
                std::vector<uint8_t> tmp_buf(recvbuf.data() + Ktunnel_header ,recvbuf.data() + Ktunnel_header + pay_len);
                packet_buffer buf(std::move(tmp_buf));
                m_queue_recv.push(std::move(buf));
                break;
            }
        case m_heart:
            m_last_heartbeat_ms.store(now_ms());   // 收到对端心跳 → 存活
            fprintf(stderr, "[UDP] 收到心跳\n");
            handle_heartbeat();
            break;
        case m_heart_response:
            m_last_heartbeat_ms.store(now_ms());   // 心跳确认 → 更新存活时间
            fprintf(stderr, "[UDP] 收到心跳确认\n");
            break;
        case disconnect:
            m_need_connect.store(true);
            m_handshaked.store(false);
            m_authenticated.store(false);
            fprintf(stderr, "[UDP] 收到断开消息\n");
            break;
        default:
            break;
        }
    }
}

// ===================== 三阶段身份认证（Ed25519 + 临时X25519 + HKDF + AES-256-GCM） =====================
//   阶段1（明文）：C→S [nonce_c]；S→C [nonce_s || DH_SRV_EPHEM_PUB || sig_srv]（SIG_SRV_PRI 签名）；
//                  客户端验签失败即断开（防中间人）；C→S [DH_CLI_EPHEM_PUB]
//   阶段2：X25519 ECDH → HKDF-Extract(salt=nonce_c||nonce_s) → Expand 出 key_tx/key_rx
//   阶段3（密文）：客户端身份报文 → 验签 → 注册（令牌）/登录（比对公钥）→ 通过才放行 TUN 流量
void UDP::handle_auth_hello(const uint8_t* payload, size_t len)
{
    if(len != KAuthNonceLen){
        fprintf(stderr, "[UDP][AUTH] auth_hello 长度错误: %zu != %zu\n", len, KAuthNonceLen);
        return;
    }
    if(!m_sig_priv){
        fprintf(stderr, "[UDP][AUTH] 未配置服务器身份私钥 SIG_SRV_PRI\n");
        return;
    }

    // 组装并发送 ServerHello：nonce_s || DH_SRV_EPHEM_PUB || sig_srv
    auto send_server_hello = [&]() -> bool {
        // sig_payload = nonce_c || nonce_s || DH_SRV_EPHEM_PUB，用 SIG_SRV_PRI 签名
        std::vector<uint8_t> sig_payload;
        sig_payload.reserve(KAuthNonceLen * 2 + KAuthDhPubLen);
        sig_payload.insert(sig_payload.end(), m_nonce_c.begin(), m_nonce_c.end());
        sig_payload.insert(sig_payload.end(), m_nonce_s.begin(), m_nonce_s.end());
        sig_payload.insert(sig_payload.end(), m_dh_srv_pub.begin(), m_dh_srv_pub.end());
        std::vector<uint8_t> sig;
        try {
            sig = ed25519_sign(m_sig_priv.get(), sig_payload.data(), sig_payload.size());
        } catch(const std::exception &e){
            fprintf(stderr, "[UDP][AUTH] 服务器签名失败: %s\n", e.what());
            return false;
        }
        if(sig.size() != KAuthSigLen){
            fprintf(stderr, "[UDP][AUTH] 签名长度异常: %zu\n", sig.size());
            return false;
        }
        // 响应：nonce_s || DH_SRV_EPHEM_PUB || sig_srv
        std::vector<uint8_t> reply;
        reply.reserve(KAuthServerHelloLen);
        reply.insert(reply.end(), m_nonce_s.begin(), m_nonce_s.end());
        reply.insert(reply.end(), m_dh_srv_pub.begin(), m_dh_srv_pub.end());
        reply.insert(reply.end(), sig.begin(), sig.end());
        std::vector<uint8_t> sendbuf;
        return send_packet(static_cast<uint8_t>(m_auth_server_hello), reply.data(), reply.size(), sendbuf);
    };

    // 同一会话的 auth_hello 重传（nonce_c 相同且会话已建立）：不重置状态，幂等重发同一 ServerHello。
    // 否则每次重传都会重新生成 nonce_s/临时DH，导致与客户端已采用的会话状态错位。
    if(!m_nonce_c.empty() && m_nonce_c.size() == KAuthNonceLen &&
       std::memcmp(m_nonce_c.data(), payload, KAuthNonceLen) == 0 &&
       m_dh_srv_priv != nullptr && !m_nonce_s.empty() && !m_dh_srv_pub.empty()){
        if(send_server_hello()){
            fprintf(stderr, "[UDP][AUTH] auth_hello 重传：幂等重发 ServerHello\n");
        }
        return;
    }

    // 新会话：重置上一会话的认证/密钥状态（客户端重连时不复用旧密钥）
    reset_auth_state();
    m_nonce_c.assign(payload, payload + KAuthNonceLen);
    m_nonce_s = generate_nonce(KAuthNonceLen);
    if(!generate_ephemeral_x25519(m_dh_srv_priv, m_dh_srv_pub)){
        fprintf(stderr, "[UDP][AUTH] 生成临时 X25519 密钥对失败\n");
        return;
    }
    if(!send_server_hello()){
        fprintf(stderr, "[UDP][AUTH] 发送 ServerHello 失败\n");
        return;
    }
    fprintf(stderr, "[UDP][AUTH] 已回复签名 ServerHello\n");
}

void UDP::handle_auth_client_hello(const uint8_t* payload, size_t len)
{
    if(len != KAuthDhPubLen){
        fprintf(stderr, "[UDP][AUTH] auth_client_hello 长度错误: %zu != %zu\n", len, KAuthDhPubLen);
        return;
    }
    if(m_dh_srv_priv == nullptr || m_nonce_c.empty() || m_nonce_s.empty()){
        fprintf(stderr, "[UDP][AUTH] 会话状态不完整（未先收到 auth_hello）\n");
        return;
    }
    m_dh_cli_pub.assign(payload, payload + KAuthDhPubLen);

    // 阶段2：X25519 ECDH 计算共享秘密
    EVP_PKEY* cli_pub = make_x25519_public_key(m_dh_cli_pub.data(), m_dh_cli_pub.size());
    if(cli_pub == nullptr){
        fprintf(stderr, "[UDP][AUTH] 构造客户端临时公钥失败\n");
        return;
    }
    std::vector<uint8_t> ss;
    try {
        ss = ecdh_derive_shared_secret(m_dh_srv_priv, cli_pub);
    } catch(const std::exception &e){
        EVP_PKEY_free(cli_pub);
        fprintf(stderr, "[UDP][AUTH] ECDH 失败: %s\n", e.what());
        return;
    }
    EVP_PKEY_free(cli_pub);

    // HKDF：Extract(salt=nonce_c||nonce_s, IKM=ss) → prk → Expand 出 key_tx/key_rx
    DirectionalSessionKeys keys;
    try {
        keys = derive_directional_session_keys(ss, m_nonce_c, m_nonce_s);
    } catch(const std::exception &e){
        secure_wipe(ss);
        fprintf(stderr, "[UDP][AUTH] 会话密钥派生失败: %s\n", e.what());
        return;
    }
    secure_wipe(ss);
    m_key_c2s = std::move(keys.key_tx); // 客户端→服务端（接收解密）
    m_key_s2c = std::move(keys.key_rx); // 服务端→客户端（发送加密）
    m_enc_ready.store(true);
    fprintf(stderr, "[UDP][AUTH] 加密隧道已建立（阶段2完成，等待身份报文）\n");
}

// 阶段3：身份报文（AES-GCM 密文内层）
// body = [flags(1: 0=登录 1=注册)] [token_len(1)] [token?] [identity_payload] [sig_cli(64)]
// identity_payload = nonce_c(16) || nonce_s(16) || dh_cli_pub(32) || dh_srv_pub(32)
//                    || sig_cli_pub(32) || id_len(1) || client_id
void UDP::handle_identity(const std::vector<uint8_t>& inner)
{
    // 已认证会话再次收到身份报文 = 客户端在首次成功确认前发出的重传，直接忽略。
    // 否则令牌已被消费后重传会被误判为"无效/已使用"，把正常会话断开。
    if (m_authenticated.load()) {
        return;
    }
    // identity_deny 携带 1 字节原因码（密文内层）：
    //   0 = 身份未注册 / 签名失败等（登录类失败）
    //   1 = 注册令牌无效或已使用（注册类失败）
    // 客户端据此区分，并可在原因=1 时自动清除 RegisterToken 切换登录模式
    auto deny = [&](uint8_t reason) {
        std::vector<uint8_t> r{ reason };
        std::vector<uint8_t> sendbuf;
        send_packet(static_cast<uint8_t>(m_identity_deny), r.data(), r.size(), sendbuf);
        m_authenticated.store(false);
        m_handshaked.store(false);
        m_need_connect.store(true);
    };
    if(inner.size() < 2 + KAuthIdentityFixed + KAuthSigLen){
        fprintf(stderr, "[UDP][AUTH] 身份报文过短: %zu\n", inner.size());
        deny(0);
        return;
    }
    const uint8_t flags = inner[0];
    const size_t token_len = inner[1];
    if(inner.size() < 2 + token_len + KAuthIdentityFixed + KAuthSigLen){
        fprintf(stderr, "[UDP][AUTH] 身份报文长度不匹配\n");
        deny(0);
        return;
    }
    size_t pos = 2;
    const std::string token(reinterpret_cast<const char*>(inner.data() + pos), token_len);
    pos += token_len;

    // 重建 identity_payload（与客户端组装规则完全一致）
    const std::vector<uint8_t> payload(inner.begin() + pos, inner.end() - KAuthSigLen);
    const uint8_t* sig = inner.data() + inner.size() - KAuthSigLen;
    if(payload.size() < KAuthIdentityFixed){
        deny(0);
        return;
    }
    const uint8_t* p = payload.data();
    const std::vector<uint8_t> nc(p, p + KAuthNonceLen);             p += KAuthNonceLen;
    const std::vector<uint8_t> ns(p, p + KAuthNonceLen);             p += KAuthNonceLen;
    const std::vector<uint8_t> dc(p, p + KAuthDhPubLen);             p += KAuthDhPubLen;
    const std::vector<uint8_t> ds(p, p + KAuthDhPubLen);             p += KAuthDhPubLen;
    const std::vector<uint8_t> cli_pub(p, p + KAuthDhPubLen);        p += KAuthDhPubLen;
    const size_t id_len = *p;                                        ++p;
    if(payload.size() != KAuthIdentityFixed + id_len){
        fprintf(stderr, "[UDP][AUTH] identity_payload 长度不匹配\n");
        deny(0);
        return;
    }
    const std::string client_id(reinterpret_cast<const char*>(p), id_len);

    // 会话绑定检查：全部会话上下文必须与本会话一致
    if(nc != m_nonce_c || ns != m_nonce_s || dc != m_dh_cli_pub || ds != m_dh_srv_pub){
        fprintf(stderr, "[UDP][AUTH] 身份报文会话上下文不匹配，拒绝\n");
        deny(0);
        return;
    }

    // 校验 sig_cli
    EVP_PKEY* cli_key = make_ed25519_public_key(cli_pub.data(), cli_pub.size());
    if(cli_key == nullptr){
        fprintf(stderr, "[UDP][AUTH] 构造客户端身份公钥失败\n");
        deny(0);
        return;
    }
    bool sig_ok = false;
    try {
        sig_ok = ed25519_verify(cli_key, payload.data(), payload.size(), sig, KAuthSigLen);
    } catch(const std::exception &){
        sig_ok = false;
    }
    EVP_PKEY_free(cli_key);
    if(!sig_ok){
        fprintf(stderr, "[UDP][AUTH] 客户端身份签名校验失败，拒绝\n");
        deny(0);
        return;
    }

    // 注册 / 登录分支
    const std::string cli_pub_hex = to_hex(cli_pub.data(), cli_pub.size());
    const std::string clients_path = m_keys_dir + "/registered_clients.txt";
    const std::string tokens_path  = m_keys_dir + "/register_tokens.txt";
    if(flags == 1){
        // 注册分支：校验一次性令牌，写入数据库，令牌作废
        if(token.empty()){
            fprintf(stderr, "[UDP][AUTH] 注册模式缺少 register_token\n");
            deny(1);
            return;
        }
        if(!file_remove_line(tokens_path, token)){
            fprintf(stderr, "[UDP][AUTH] 注册令牌无效或已使用\n");
            deny(1);
            return;
        }
        if(!file_append_line(clients_path, cli_pub_hex)){
            fprintf(stderr, "[UDP][AUTH] 写入已注册客户端失败\n");
            deny(1);
            return;
        }
        fprintf(stderr, "[UDP][AUTH] 客户端注册成功 id=%s\n", client_id.c_str());
    } else {
        // 登录分支：数据库比对 SIG_CLI_PUB
        if(!file_contains_line(clients_path, cli_pub_hex)){
            fprintf(stderr, "[UDP][AUTH] 未注册的客户端身份，拒绝登录\n");
            deny(0);
            return;
        }
        fprintf(stderr, "[UDP][AUTH] 客户端登录成功 id=%s\n", client_id.c_str());
    }

    // 全部校验通过 → 放行 TUN 业务流量
    m_authenticated.store(true);
    m_handshaked.store(true);
    m_last_heartbeat_ms.store(now_ms());
    std::vector<uint8_t> sendbuf;
    send_packet(static_cast<uint8_t>(m_identity_ok), nullptr, 0, sendbuf);
    fprintf(stderr, "[UDP][AUTH] 身份认证通过，放行 TUN 流量\n");
}

void UDP::reset_auth_state()
{
    m_authenticated.store(false);
    m_handshaked.store(false);
    m_enc_ready.store(false);
    m_nonce_c.clear();
    m_nonce_s.clear();
    m_dh_srv_pub.clear();
    m_dh_cli_pub.clear();
    if(m_dh_srv_priv != nullptr){
        EVP_PKEY_free(m_dh_srv_priv);   // 销毁临时私钥（前向安全）
        m_dh_srv_priv = nullptr;
    }
    secure_wipe(m_key_c2s);
    secure_wipe(m_key_s2c);
}


bool UDP::handle_heartbeat()
{
    std::vector<uint8_t> sendbuf;
    return send_packet(m_heart_response, nullptr, 0, sendbuf);
}

void UDP::set_identity(std::shared_ptr<EVP_PKEY> sig_priv, const std::string& keys_dir)
{
    m_sig_priv = std::move(sig_priv);
    m_keys_dir = keys_dir;
    if (m_keys_dir.empty())
        m_keys_dir = "keys";
}

bool UDP::is_encrypted() const
{
    return m_enc_ready.load();
}

// ===================== 注册/登录数据库（简单文本文件） =====================

std::string UDP::to_hex(const uint8_t* data, size_t len)
{
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(hex[data[i] >> 4]);
        out.push_back(hex[data[i] & 0x0F]);
    }
    return out;
}

bool UDP::file_contains_line(const std::string& path, const std::string& line)
{
    FILE* f = std::fopen(path.c_str(), "r");
    if (f == nullptr)
        return false;
    char buf[512] = {0};
    bool found = false;
    while (std::fgets(buf, sizeof(buf), f) != nullptr) {
        std::string s(buf);
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
            s.pop_back();
        if (s == line) {
            found = true;
            break;
        }
    }
    std::fclose(f);
    return found;
}

bool UDP::file_append_line(const std::string& path, const std::string& line)
{
    FILE* f = std::fopen(path.c_str(), "a");
    if (f == nullptr)
        return false;
    const bool ok = std::fprintf(f, "%s\n", line.c_str()) > 0;
    std::fclose(f);
    return ok;
}

// 删除一行（用于作废一次性注册令牌）；返回是否真的删除了一行
bool UDP::file_remove_line(const std::string& path, const std::string& line)
{
    FILE* f = std::fopen(path.c_str(), "r");
    if (f == nullptr)
        return false;
    std::vector<std::string> keep;
    char buf[512] = {0};
    bool removed = false;
    while (std::fgets(buf, sizeof(buf), f) != nullptr) {
        std::string s(buf);
        while (!s.empty() && (s.back() == '\n' || s.back() == '\r'))
            s.pop_back();
        if (!removed && s == line) {
            removed = true;   // 匹配到令牌：丢弃该行（作废）
            continue;
        }
        keep.push_back(s);
    }
    std::fclose(f);

    FILE* out = std::fopen(path.c_str(), "w");
    if (out == nullptr)
        return false;
    for (const auto& s : keep) {
        std::fprintf(out, "%s\n", s.c_str());
    }
    std::fclose(out);
    return removed;
}

bool UDP::start_threads()
{
    try{
        send_thread = std::thread(&UDP::send_work, this);
        recv_thread = std::thread(&UDP::recv_work, this);
        heartbeat_thread = std::thread(&UDP::heartbeat_work, this);
    }catch(const std::system_error &e){
        fprintf(stderr, "[UDP] start_threads failed: %s\n", e.what());
        stop_threads();
        return false;
    }
    return true;
}

void UDP::stop_threads()
{
    if(send_thread.joinable()){
        send_thread.join();
    }
    if(recv_thread.joinable()){
        recv_thread.join();
    }
    if(heartbeat_thread.joinable()){
        heartbeat_thread.join();
    }
}

void UDP::heartbeat_work()
{
    while(is_running()){
        std::this_thread::sleep_for(kHeartbeatInterval);
        if(!is_running()){
            break;
        }
        if(!is_handshaked()){
            continue;   // 尚未握手，无需保活
        }
        // 超时检测：超过 kHeartbeatTimeout 未收到对端任何包 → 判定失联
        uint64_t last = m_last_heartbeat_ms.load();
        uint64_t timeout_ms = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(kHeartbeatTimeout).count());
        if(last != 0 && (now_ms() - last) > timeout_ms){
            fprintf(stderr, "[UDP] heartbeat timeout, peer considered dead\n");
            m_handshaked.store(false);
            m_need_connect.store(true);
            continue;
        }
        // 主动发送心跳
        std::vector<uint8_t> sendbuf;
        fprintf(stderr, "[UDP] 发送心跳\n");
        if(!send_packet(m_heart, nullptr, 0, sendbuf)){
            fprintf(stderr, "[UDP] send heartbeat failed\n");
            m_need_connect.store(true);
        }
    }
}

uint32_t UDP::GenerateISN()
{
	static std::random_device rd;
	static std::mt19937 generator(rd());
	static std::uniform_int_distribution<uint32_t> dist;
	return dist(generator);
}