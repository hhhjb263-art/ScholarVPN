#pragma once

#include <openssl/evp.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

constexpr std::size_t AES256_KEY_LEN = 32;
constexpr std::size_t AES_GCM_NONCE_LEN = 12;
constexpr std::size_t AES_GCM_TAG_LEN = 16;
constexpr std::size_t HKDF_SHA256_MAX_OUTPUT_LEN = 255 * 32;
constexpr std::size_t ED25519_SIG_LEN = 64;      // Ed25519 签名长度（字节）
constexpr std::size_t HANDSHAKE_NONCE_LEN = 16;  // 握手随机数 nonce_c / nonce_s 长度（字节）
constexpr std::size_t REGISTER_TOKEN_LEN = 32;   // 一次性注册令牌长度（字节）


// 擦除 vector 当前已分配区域中的敏感数据；不会释放容量。
void secure_wipe(std::vector<std::uint8_t>& buffer) noexcept;

// 返回的 EVP_PKEY* 由调用方使用 EVP_PKEY_free() 释放。
EVP_PKEY* load_x25519_private_key(const std::string& pem_path);
EVP_PKEY* load_x25519_public_key(const std::string& pem_path);
// Generate a new X25519 key pair and write them as PEM files (client.key / client.pub).
// On success, pub_pem_out receives the PEM-encoded public key for display.
bool generate_x25519_keypair(
    const std::string& priv_path,
    const std::string& pub_path,
    std::string& pub_pem_out);

std::vector<std::uint8_t> ecdh_derive_shared_secret(
    EVP_PKEY* local_private_key,
    EVP_PKEY* peer_public_key);

std::vector<std::uint8_t> hkdf_derive_key(
    const std::vector<std::uint8_t>& shared_secret,
    const std::vector<std::uint8_t>& salt,
    const std::string& info,
    std::size_t output_length);

std::vector<std::uint8_t> aes256_gcm_encrypt(
    const std::vector<std::uint8_t>& key,
    const std::uint8_t* plaintext,
    std::size_t plaintext_length);

std::vector<std::uint8_t> aes256_gcm_encrypt(
    const std::vector<std::uint8_t>& key,
    const std::uint8_t* plaintext,
    std::size_t plaintext_length,
    const std::uint8_t* aad,
    std::size_t aad_length);

std::optional<std::vector<std::uint8_t>> aes256_gcm_decrypt(
    const std::vector<std::uint8_t>& key,
    const std::vector<std::uint8_t>& input);

std::optional<std::vector<std::uint8_t>> aes256_gcm_decrypt(
    const std::vector<std::uint8_t>& key,
    const std::vector<std::uint8_t>& input,
    const std::uint8_t* aad,
    std::size_t aad_length);

std::vector<std::uint8_t> build_inner_packet(
    std::uint8_t packet_type,
    const std::vector<std::uint8_t>& payload);

bool parse_inner_packet(
    const std::vector<std::uint8_t>& inner_plaintext,
    std::uint8_t& output_type,
    std::vector<std::uint8_t>& output_payload);


// ===================== Ed25519 身份密钥（持久身份，公私钥验证） =====================
// 生成持久 Ed25519 身份密钥对：私钥写为 PKCS#8 PEM，公钥写为 SPKI PEM，
// 同时把公钥 PEM 文本返回给调用方（用于展示 / 硬编码进对端程序）。
// 服务器身份用 SIG_SRV_PRI/SIG_SRV_PUB，客户端身份用 SIG_CLI_PRI/SIG_CLI_PUB。
bool generate_ed25519_keypair(
    const std::string& priv_path,
    const std::string& pub_path,
    std::string& pub_pem_out);

// 返回的 EVP_PKEY* 由调用方使用 EVP_PKEY_free() 释放。
EVP_PKEY* load_ed25519_private_key(const std::string& pem_path);
EVP_PKEY* load_ed25519_public_key(const std::string& pem_path);

// Ed25519 签名（纯 EdDSA）：对 message 计算 64 字节签名（ED25519_SIG_LEN）。
// 阶段1示例：sig_payload = nonce_c || nonce_s || DH_SRV_EPHEM_PUB，用 SIG_SRV_PRI 签名。
std::vector<std::uint8_t> ed25519_sign(
    EVP_PKEY* private_key,
    const std::uint8_t* message,
    std::size_t message_length);

// Ed25519 验签：true = 签名有效，false = 签名无效（参数非法时抛异常）。
bool ed25519_verify(
    EVP_PKEY* public_key,
    const std::uint8_t* message,
    std::size_t message_length,
    const std::uint8_t* signature,
    std::size_t signature_length);

// ===================== 随机数与注册令牌 =====================
// 生成 length 字节安全随机数（默认 16 字节，用于 nonce_c / nonce_s）。
std::vector<std::uint8_t> generate_nonce(std::size_t length = HANDSHAKE_NONCE_LEN);

// 生成一次性注册令牌（REGISTER_TOKEN_LEN 字节随机数，返回 64 位十六进制字符串）。
std::string generate_register_token();

// ===================== 会话密钥派生（阶段2：HKDF-Extract + HKDF-Expand） =====================
// HKDF-Extract：prk = HKDF-Extract(salt, IKM)，返回 32 字节 PRK（SHA-256）。
std::vector<std::uint8_t> hkdf_extract(
    const std::vector<std::uint8_t>& ikm,
    const std::vector<std::uint8_t>& salt);

// HKDF-Expand：从 PRK 派生 output_length 字节密钥材料。
std::vector<std::uint8_t> hkdf_expand(
    const std::vector<std::uint8_t>& prk,
    const std::string& info,
    std::size_t output_length);

// 方向性会话密钥：客户端→服务端 与 服务端→客户端 两个方向各 32 字节 AES-256 密钥。
// prk    = HKDF-Extract(salt = nonce_c || nonce_s, IKM = X25519 共享秘密)
// key_tx = HKDF-Expand(prk, "tx", 32)   客户端→服务端
// key_rx = HKDF-Expand(prk, "rx", 32)   服务端→客户端
// 两端传入相同的 nonce_c/nonce_s 得到相同结果；客户端用 key_tx 发送、key_rx 接收，服务端反之。
struct DirectionalSessionKeys
{
    std::vector<std::uint8_t> key_tx; // 客户端→服务端 方向密钥
    std::vector<std::uint8_t> key_rx; // 服务端→客户端 方向密钥
};
DirectionalSessionKeys derive_directional_session_keys(
    const std::vector<std::uint8_t>& shared_secret,
    const std::vector<std::uint8_t>& nonce_c,
    const std::vector<std::uint8_t>& nonce_s);


// 从 PEM 文本加载 Ed25519 密钥（用于内置硬编码公钥 / DPAPI 解密后的私钥）。
// 返回的 EVP_PKEY* 由调用方使用 EVP_PKEY_free() 释放。
EVP_PKEY* load_ed25519_private_key_pem(const std::string& pem_text);
EVP_PKEY* load_ed25519_public_key_pem(const std::string& pem_text);
