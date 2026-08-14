#include <cstdint>
#include <cstddef>

#pragma pack(push,1)
struct tunnel_header
{
    uint32_t magic;
    uint8_t version;
    uint8_t type;
    uint16_t payload_len;
    uint32_t sequence;
};
#pragma pack(pop)
enum version : uint8_t
{
    v_udp = 1,
    v_tcp = 2
};
enum type : uint8_t
{
    m_hand_request = 0,
    m_hand_response = 1,
    m_data = 2,
    m_heart = 3,
    m_heart_response = 4,
    disconnect = 5,
    m_key_exchange = 6,   // X25519 公钥 + 随机盐（明文），客户端→服务端
    m_key_response = 7,   // X25519 公钥 + 随机盐（明文），服务端→客户端
    // ===== 三阶段身份认证消息（阶段1明文 / 阶段3密文内层） =====
    m_auth_hello = 8,          // 阶段1：客户端→服务器 [nonce_c]
    m_auth_server_hello = 9,   // 阶段1：服务器→客户端 [nonce_s || DH_SRV_EPHEM_PUB || sig_srv]
    m_auth_client_hello = 10,  // 阶段1：客户端→服务器 [DH_CLI_EPHEM_PUB]
    m_identity = 11,           // 阶段3（AES-GCM 密文内层）：客户端身份报文
    m_identity_ok = 12,        // 阶段3（AES-GCM 密文内层）：身份验证通过
    m_identity_deny = 13       // 阶段3（AES-GCM 密文内层）：身份验证失败
};
enum m_hand_request {
    HS_IDLE,
    HS_SEND_REQ,    // 已发送握手请求，等待服务端ACK
    HS_WAIT_ACK,
    HS_SEND_FIN,    // 收到ACK，发送最终确认包
    HS_SUCCESS
};
constexpr uint32_t Kmagic = 0x4D56504E;
constexpr uint8_t Kversion = v_udp;
constexpr size_t Ktunnel_header = sizeof(tunnel_header);
// Max TUN packet 1400 + inner type 1 + nonce 12 + tag 16 = 1429 (match client)
constexpr size_t Max_payload_len = 1429;

// ===== 三阶段身份认证线格式常量 =====
constexpr size_t KAuthNonceLen = 16;             // nonce_c / nonce_s
constexpr size_t KAuthDhPubLen = 32;             // 临时 X25519 公钥 / Ed25519 公钥
constexpr size_t KAuthSigLen = 64;               // Ed25519 签名
constexpr size_t KAuthServerHelloLen = KAuthNonceLen + KAuthDhPubLen + KAuthSigLen;            // 112
constexpr size_t KAuthClientHelloLen = KAuthDhPubLen;                                               // 32
// identity_payload 固定部分：nonce_c(16) || nonce_s(16) || dh_cli(32) || dh_srv(32) || cli_pub(32) || id_len(1)
constexpr size_t KAuthIdentityFixed = KAuthNonceLen * 2 + KAuthDhPubLen * 3 + 1;                     // 129