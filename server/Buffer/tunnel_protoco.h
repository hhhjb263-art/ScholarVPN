#pragma once
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
    m_key_exchange = 6,
    m_key_response = 7,
    m_auth_hello = 8,
    m_auth_server_hello = 9,
    m_auth_client_hello = 10,
    m_identity = 11,
    m_identity_ok = 12,
    m_identity_deny = 13
};
enum m_hand_request {
    HS_IDLE,
    HS_SEND_REQ,
    HS_WAIT_ACK,
    HS_SEND_FIN,
    HS_SUCCESS
};
constexpr uint32_t Kmagic = 0x4D56504E;
constexpr uint8_t Kversion = v_udp;
constexpr size_t Ktunnel_header = sizeof(tunnel_header);
constexpr size_t Max_payload_len = 1429;
constexpr size_t KMax_data_payload = 1400;

constexpr size_t KAuthNonceLen = 16;
constexpr size_t KAuthDhPubLen = 32;
constexpr size_t KAuthSigLen = 64;
constexpr size_t KAuthServerHelloLen = KAuthNonceLen + KAuthDhPubLen + KAuthSigLen;
constexpr size_t KAuthClientHelloLen = KAuthDhPubLen;
constexpr size_t KAuthIdentityFixed = KAuthNonceLen * 2 + KAuthDhPubLen * 3 + 1;
