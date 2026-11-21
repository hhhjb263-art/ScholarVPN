#pragma once

#include <openssl/evp.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

inline constexpr std::size_t AES256_KEY_LEN = 32;
inline constexpr std::size_t AES_GCM_NONCE_LEN = 12;
inline constexpr std::size_t AES_GCM_TAG_LEN = 16;
inline constexpr std::size_t HKDF_SHA256_MAX_OUTPUT_LEN = 255 * 32;
inline constexpr std::size_t ED25519_SIG_LEN = 64;
inline constexpr std::size_t HANDSHAKE_NONCE_LEN = 16;
inline constexpr std::size_t REGISTER_TOKEN_LEN = 32;

void secure_wipe(std::vector<std::uint8_t>& buffer) noexcept;

EVP_PKEY* load_x25519_private_key(const std::string& pem_path);
EVP_PKEY* load_x25519_public_key(const std::string& pem_path);

bool generate_x25519_keypair(const std::string& private_pem_path,
                             const std::string& public_pem_path);

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

std::size_t aes256_gcm_seal(
    const std::vector<std::uint8_t>& key,
    const std::uint8_t* plaintext1, std::size_t plaintext1_length,
    const std::uint8_t* plaintext2, std::size_t plaintext2_length,
    const std::uint8_t* aad, std::size_t aad_length,
    std::uint8_t* out, std::size_t out_cap);

std::size_t aes256_gcm_open(
    const std::vector<std::uint8_t>& key,
    const std::uint8_t* sealed, std::size_t sealed_length,
    const std::uint8_t* aad, std::size_t aad_length,
    std::uint8_t* out, std::size_t out_capacity);

std::vector<std::uint8_t> build_inner_packet(
    std::uint8_t packet_type,
    const std::vector<std::uint8_t>& payload);

bool parse_inner_packet(
    const std::vector<std::uint8_t>& inner_plaintext,
    std::uint8_t& output_type,
    std::vector<std::uint8_t>& output_payload);

bool generate_ed25519_keypair(const std::string& private_pem_path,
                              const std::string& public_pem_path,
                              std::string& pub_pem_out);

EVP_PKEY* load_ed25519_private_key(const std::string& pem_path);
EVP_PKEY* load_ed25519_public_key(const std::string& pem_path);

std::vector<std::uint8_t> ed25519_sign(
    EVP_PKEY* private_key,
    const std::uint8_t* message,
    std::size_t message_length);

bool ed25519_verify(
    EVP_PKEY* public_key,
    const std::uint8_t* message,
    std::size_t message_length,
    const std::uint8_t* signature,
    std::size_t signature_length);

std::vector<std::uint8_t> generate_nonce(std::size_t length = HANDSHAKE_NONCE_LEN);

std::string generate_register_token();

std::vector<std::uint8_t> hkdf_extract(
    const std::vector<std::uint8_t>& ikm,
    const std::vector<std::uint8_t>& salt);

std::vector<std::uint8_t> hkdf_expand(
    const std::vector<std::uint8_t>& prk,
    const std::string& info,
    std::size_t output_length);

struct DirectionalSessionKeys
{
    std::vector<std::uint8_t> key_tx;
    std::vector<std::uint8_t> key_rx;
};
DirectionalSessionKeys derive_directional_session_keys(
    const std::vector<std::uint8_t>& shared_secret,
    const std::vector<std::uint8_t>& nonce_c,
    const std::vector<std::uint8_t>& nonce_s);
