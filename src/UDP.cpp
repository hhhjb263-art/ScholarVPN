#include "UDP.h"
#include "logger.h"
#include <cstdio>
#include <chrono>
#include <cstring>
#include <random>
#include <string>
#include "Crypt.h"
#include <openssl/rand.h>

namespace {

// 三阶段身份认证（Ed25519 + 临时X25519 + HKDF + AES-256-GCM）
//   阶段1（明文）：C→S [nonce_c]；S→C [nonce_s || DH_SRV_EPHEM_PUB || sig_srv]（SIG_SRV_PRI 签名）；
//                  客户端用内置 SIG_SRV_PUB 验签，失败=中间人直接断开；C→S [DH_CLI_EPHEM_PUB]
//   阶段2：X25519 ECDH → HKDF-Extract(salt=nonce_c||nonce_s) → Expand 出 key_tx/key_rx，加密隧道开启
//   阶段3（密文）：客户端发送身份报文（会话上下文 + client_id + SIG_CLI_PUB + register_token + 签名），
//                  服务器验签后按 注册/登录 分支校验，通过才放行 TUN 流量
constexpr auto kAuthTimeout = std::chrono::seconds(5);          // 每个阶段的总超时
constexpr auto kAuthRetryInterval = std::chrono::milliseconds(500);
constexpr int kAuthMaxRetries = 10;

// 心跳保活
constexpr auto kHeartbeatInterval = std::chrono::seconds(1);
constexpr auto kHeartbeatTimeout = std::chrono::seconds(5);

// 从 EVP_PKEY 中取原始公钥（X25519 / Ed25519 均为 32 字节）
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

} // namespace

UDP::UDP(const char* remoteip, uint16_t port, bool is_running, size_t queueMax) :
	m_sock(INVALID_SOCKET), m_sendqueue(queueMax), m_recvqueue(queueMax)
{
	memset(&m_sockaddr, 0, sizeof(m_sockaddr));
	m_sockaddr.sin_family = AF_INET;
	m_sockaddr.sin_port = htons(port);
	int ret = inet_pton(AF_INET, remoteip, &m_sockaddr.sin_addr);
	if (ret != 1) {
		throw std::invalid_argument("invalid remote ip address");
	}
}

UDP::~UDP()
{
	stop();
	if (m_dh_cli_priv != nullptr) {
		EVP_PKEY_free(m_dh_cli_priv);
		m_dh_cli_priv = nullptr;
	}
	if (m_server_sig_pub != nullptr) {
		EVP_PKEY_free(m_server_sig_pub);
		m_server_sig_pub = nullptr;
	}
	if (m_sock != INVALID_SOCKET) {
		closesocket(m_sock);
		m_sock = INVALID_SOCKET;
	}
	WSACleanup();
}

bool UDP::init()
{
	if (m_running.load() || send_thread.joinable() || recv_thread.joinable()) {
		return false; // 已经初始化过了, 避免重复创建线程/泄漏 socket
	}
	WSADATA wsa;
	if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
		return false;
	}
	m_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (m_sock == INVALID_SOCKET) {
		WSACleanup();
		return false;
	}

	// 三阶段认证状态复位（每次连接全新状态）
	m_handshaked.store(false);
	m_authenticated.store(false);
	m_auth_failed.store(false);
	m_auth_deny_reason.store(-1);
	m_server_hello_ok.store(false);
	m_enc_ready.store(false);
	m_need_reconnect.store(false);
	m_nonce_s.clear();
	m_dh_srv_pub.clear();
	m_dh_cli_pub.clear();
	if (m_dh_cli_priv != nullptr) {
		EVP_PKEY_free(m_dh_cli_priv);
		m_dh_cli_priv = nullptr;
	}
	secure_wipe(m_key_c2s);
	secure_wipe(m_key_s2c);
	m_seq.store(0, std::memory_order_relaxed);
	m_last_rx_ms.store(std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::steady_clock::now().time_since_epoch()).count());

	// 解析内置的服务器身份公钥 SIG_SRV_PUB（硬编码）
	if (m_server_sig_pub != nullptr) {
		EVP_PKEY_free(m_server_sig_pub);
		m_server_sig_pub = nullptr;
	}
	try {
		m_server_sig_pub = load_ed25519_public_key_pem(m_server_sig_pub_pem);
	}
	catch (const std::exception& e) {
		LOG_ERR("[UDP] 无法解析服务器身份公钥 SIG_SRV_PUB: %s\n", e.what());
		closesocket(m_sock);
		m_sock = INVALID_SOCKET;
		WSACleanup();
		return false;
	}

	// 阶段1：生成 nonce_c（16 字节随机数）
	m_nonce_c = generate_nonce(KAuthNonceLen);

	m_running = true;
	send_thread = std::thread(&UDP::send_work, this);
	recv_thread = std::thread(&UDP::recv_work, this);
	return true;
}

void UDP::stop()
{
	m_running = false;
	m_sendqueue.shutdown();
	m_recvqueue.shutdown();
	// 先关闭 socket，让阻塞在 recvfrom 上的接收线程立即返回，再回收线程，避免 stop 卡死
	if (m_sock != INVALID_SOCKET) {
		closesocket(m_sock);
		m_sock = INVALID_SOCKET;
	}
	if (send_thread.joinable())
		send_thread.join();
	if (recv_thread.joinable())
		recv_thread.join();
	m_handshaked.store(false);
	m_authenticated.store(false);
	m_auth_failed.store(false);
	m_auth_deny_reason.store(-1);
	m_server_hello_ok.store(false);
	m_enc_ready.store(false);
	m_need_reconnect.store(false);
	secure_wipe(m_key_c2s);
	secure_wipe(m_key_s2c);
	m_nonce_c.clear();
	m_nonce_s.clear();
	m_dh_cli_pub.clear();
	m_dh_srv_pub.clear();
	if (m_dh_cli_priv != nullptr) {
		EVP_PKEY_free(m_dh_cli_priv);
		m_dh_cli_priv = nullptr;
	}
	m_last_rx_ms.store(0);
	m_hs_state = HS_IDLE;
	m_client_isn = 0;
	m_server_isn = 0;
}

void UDP::set_identity(
	std::shared_ptr<EVP_PKEY> ed25519_priv,
	const std::string& server_sig_pub_pem,
	const std::string& client_id,
	const std::string& register_token)
{
	m_ed25519_priv = std::move(ed25519_priv);
	m_server_sig_pub_pem = server_sig_pub_pem;
	m_client_id = client_id;
	m_register_token = register_token;
}

// 网卡将数据填入队列
void UDP::send_ip_packet(packet_buffer&& buf)
{
	if (!m_running.load()) {
		return;
	}
	m_sendqueue.push(std::move(buf));
}

bool UDP::recv_ip_packet(packet_buffer& buf)
{
	if (!m_running.load()) {
		return false;
	}
	return m_recvqueue.pop(buf);
}

bool UDP::try_recv_ip_packet(packet_buffer& buf)
{
	if (!m_running.load()) {
		return false;
	}
	return m_recvqueue.try_pop(buf);
}

bool UDP::send_packet(uint8_t type, const uint8_t* data, size_t len, std::vector<uint8_t>& sendbuf)
{
	if (len > Max_payload_len)
		return false;
	size_t total_len = Ktunnel_header + len;
	sendbuf.resize(total_len);
	tunnel_header header{};

	header.magic = Kmagic;
	header.version = static_cast<uint8_t>(Kversion);
	header.type = type;
	header.payload_len = htons(static_cast<uint16_t>(len));
	uint32_t seq = m_seq.fetch_add(1);
	header.sequence = htonl(seq);

	memcpy(sendbuf.data(), &header, Ktunnel_header);
	// 数据面加密：密钥就绪后 data/heart/identity 等一律以密文发送（阶段1明文消息除外）
	if (m_enc_ready.load() && (type == static_cast<uint8_t>(m_data) ||
		type == static_cast<uint8_t>(m_heart) ||
		type == static_cast<uint8_t>(m_heart_response) ||
		type == static_cast<uint8_t>(m_identity) ||
		type == static_cast<uint8_t>(m_identity_ok) ||
		type == static_cast<uint8_t>(m_identity_deny)))
	{
		// enc_len = inner明文(1+len) + nonce12 + tag16
		const size_t enc_len = len + 1 + AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN;
		if (enc_len > Max_payload_len)
			return false;
		header.payload_len = htons(static_cast<uint16_t>(enc_len));
		memcpy(sendbuf.data(), &header, Ktunnel_header);
		std::vector<uint8_t> inner;
		inner.reserve(1 + len);
		inner.push_back(type);
		if (len)
			inner.insert(inner.end(), data, data + len);
		std::vector<uint8_t> enc;
		try
		{
			// 客户端发送方向 = key_tx（m_key_c2s）
			enc = aes256_gcm_encrypt(
				m_key_c2s,
				inner.data(), inner.size(),
				sendbuf.data(), Ktunnel_header);
		}
		catch (const std::exception& e)
		{
			LOG_ERR("[UDP] 加密失败: %s\n", e.what());
			return false;
		}
		if (enc.size() != enc_len)
			return false;
		sendbuf.resize(Ktunnel_header + enc.size());
		memcpy(sendbuf.data() + Ktunnel_header, enc.data(), enc.size());
		total_len = Ktunnel_header + enc.size();
		int ret = sendto(m_sock, reinterpret_cast<const char*>(sendbuf.data()), static_cast<int>(total_len), 0,
			reinterpret_cast<const sockaddr*>(&m_sockaddr), sizeof(m_sockaddr));
		if (ret == SOCKET_ERROR)
		{
			int err = WSAGetLastError();
			if (err == WSAECONNRESET)
				m_need_reconnect.store(true);
			return false;
		}
		return true;
	}
	if (len) {
		memcpy(sendbuf.data() + Ktunnel_header, data, len);
	}
	int ret = sendto(m_sock, reinterpret_cast<const char*>(sendbuf.data()), static_cast<int>(total_len), 0,
		reinterpret_cast<const sockaddr*>(&m_sockaddr), sizeof(m_sockaddr));
	if (ret == SOCKET_ERROR)
	{
		int err = WSAGetLastError();
		// 对端端口不可达，标记隧道需要重连
		if (err == WSAECONNRESET)
		{
			m_need_reconnect.store(true);
		}
		return false;
	}
	return true;
}

// 阶段3：组装并签名身份报文（返回不含内层 type 字节的 body，send_packet 会补）
// body = [flags(1: 0=登录 1=注册)] [token_len(1)] [token?] [identity_payload] [sig_cli(64)]
// identity_payload = nonce_c(16) || nonce_s(16) || dh_cli_pub(32) || dh_srv_pub(32)
//                    || sig_cli_pub(32) || id_len(1) || client_id
bool UDP::build_identity_message(std::vector<uint8_t>& out)
{
	if (!m_ed25519_priv) {
		LOG_ERR("[UDP] 未配置客户端身份私钥 SIG_CLI_PRI\n");
		return false;
	}
	if (m_nonce_c.size() != KAuthNonceLen || m_nonce_s.size() != KAuthNonceLen ||
		m_dh_cli_pub.size() != KAuthDhPubLen || m_dh_srv_pub.size() != KAuthDhPubLen) {
		LOG_ERR("[UDP] 会话上下文不完整，无法组装身份报文\n");
		return false;
	}
	if (m_client_id.size() > 255) {
		LOG_ERR("[UDP] client_id 过长（最大 255 字节）\n");
		return false;
	}

	std::vector<uint8_t> cli_pub;
	if (!get_raw_pubkey(m_ed25519_priv.get(), cli_pub) || cli_pub.size() != KAuthDhPubLen) {
		LOG_ERR("[UDP] 无法取出客户端身份公钥\n");
		return false;
	}

	// identity_payload（服务器会按相同规则重建并验签）
	std::vector<uint8_t> payload;
	payload.reserve(KAuthIdentityFixed + m_client_id.size());
	payload.insert(payload.end(), m_nonce_c.begin(), m_nonce_c.end());
	payload.insert(payload.end(), m_nonce_s.begin(), m_nonce_s.end());
	payload.insert(payload.end(), m_dh_cli_pub.begin(), m_dh_cli_pub.end());
	payload.insert(payload.end(), m_dh_srv_pub.begin(), m_dh_srv_pub.end());
	payload.insert(payload.end(), cli_pub.begin(), cli_pub.end());
	payload.push_back(static_cast<uint8_t>(m_client_id.size()));
	payload.insert(payload.end(), m_client_id.begin(), m_client_id.end());

	std::vector<uint8_t> sig;
	try {
		sig = ed25519_sign(m_ed25519_priv.get(), payload.data(), payload.size());
	}
	catch (const std::exception& e) {
		LOG_ERR("[UDP] 身份报文签名失败: %s\n", e.what());
		return false;
	}
	if (sig.size() != KAuthSigLen)
		return false;

	out.clear();
	out.reserve(2 + m_register_token.size() + payload.size() + sig.size());
	const uint8_t flags = m_register_token.empty() ? 0 : 1; // 0=登录 1=注册
	out.push_back(flags);
	if (m_register_token.size() > 255) {
		LOG_ERR("[UDP] register_token 过长\n");
		return false;
	}
	out.push_back(static_cast<uint8_t>(m_register_token.size()));
	if (!m_register_token.empty()) {
		out.insert(out.end(), m_register_token.begin(), m_register_token.end());
	}
	out.insert(out.end(), payload.begin(), payload.end());
	out.insert(out.end(), sig.begin(), sig.end());
	return true;
}

void UDP::send_work()
{
	std::vector<uint8_t> sendbuf;
	sendbuf.reserve(KMax_packet_size);
	packet_buffer buf;

	using clock_type = std::chrono::steady_clock;
	const auto auth_start = clock_type::now();
	auto last_retry = auth_start;
	int retries = 0;

	// 阶段1a：发送 nonce_c（明文），等待服务器带签名的响应
	send_packet(static_cast<uint8_t>(m_auth_hello), m_nonce_c.data(), m_nonce_c.size(), sendbuf);
	last_retry = clock_type::now();
	while (m_running.load() && !m_server_hello_ok.load() && !m_auth_failed.load() && !m_need_reconnect.load())
	{
		const auto now = clock_type::now();
		if (now - auth_start > kAuthTimeout) {
			m_need_reconnect.store(true);
			break;
		}
		if (now - last_retry >= kAuthRetryInterval) {
			if (++retries > kAuthMaxRetries) {
				m_need_reconnect.store(true);
				break;
			}
			// 重传保持同一 nonce
			send_packet(static_cast<uint8_t>(m_auth_hello), m_nonce_c.data(), m_nonce_c.size(), sendbuf);
			last_retry = now;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(20));
	}
	if (!m_server_hello_ok.load() || m_auth_failed.load() || m_need_reconnect.load() || !m_running.load()) {
		if (m_auth_failed.load()) {
			LOG_ERR("[UDP] 服务器身份校验失败：疑似中间人攻击，断开连接\n");
		}
		m_hs_state = HS_IDLE;
		return; // 超时/中间人/被拒：交由上层决定重连
	}

	// 阶段1b：生成本次临时 X25519 密钥对，发送公钥（明文）
	if (!generate_ephemeral_x25519(m_dh_cli_priv, m_dh_cli_pub)) {
		LOG_ERR("[UDP] 生成临时 X25519 密钥对失败\n");
		m_need_reconnect.store(true);
		return;
	}
	send_packet(static_cast<uint8_t>(m_auth_client_hello), m_dh_cli_pub.data(), m_dh_cli_pub.size(), sendbuf);

	// 阶段2：X25519 ECDH + HKDF 派生 key_tx/key_rx，加密隧道开启
	{
		EVP_PKEY* srv_pub = make_x25519_public_key(m_dh_srv_pub.data(), m_dh_srv_pub.size());
		if (srv_pub == nullptr) {
			LOG_ERR("[UDP] 无法构造服务器临时公钥\n");
			m_need_reconnect.store(true);
			return;
		}
		std::vector<uint8_t> ss;
		try {
			ss = ecdh_derive_shared_secret(m_dh_cli_priv, srv_pub);
		}
		catch (const std::exception& e) {
			EVP_PKEY_free(srv_pub);
			LOG_ERR("[UDP] ECDH 失败: %s\n", e.what());
			m_need_reconnect.store(true);
			return;
		}
		EVP_PKEY_free(srv_pub);
		DirectionalSessionKeys keys;
		try {
			keys = derive_directional_session_keys(ss, m_nonce_c, m_nonce_s);
		}
		catch (const std::exception& e) {
			secure_wipe(ss);
			LOG_ERR("[UDP] 会话密钥派生失败: %s\n", e.what());
			m_need_reconnect.store(true);
			return;
		}
		secure_wipe(ss);
		m_key_c2s = std::move(keys.key_tx); // 客户端→服务端（发送加密）
		m_key_s2c = std::move(keys.key_rx); // 服务端→客户端（接收解密）
		m_enc_ready.store(true);
		LOG_ERR("[UDP] 加密隧道已建立（阶段2完成）\n");
	}

	// 阶段3：加密隧道内身份认证
	{
		std::vector<uint8_t> identity_msg;
		if (!build_identity_message(identity_msg)) {
			m_need_reconnect.store(true);
			return;
		}
		const auto id_start = clock_type::now();
		auto last_id = id_start;
		int id_retries = 0;
		send_packet(static_cast<uint8_t>(m_identity), identity_msg.data(), identity_msg.size(), sendbuf);
		last_id = clock_type::now();
		while (m_running.load() && !m_authenticated.load() && !m_auth_failed.load() && !m_need_reconnect.load())
		{
			const auto now = clock_type::now();
			if (now - id_start > kAuthTimeout) {
				m_need_reconnect.store(true);
				break;
			}
			if (now - last_id >= kAuthRetryInterval) {
				if (++id_retries > kAuthMaxRetries) {
					m_need_reconnect.store(true);
					break;
				}
				send_packet(static_cast<uint8_t>(m_identity), identity_msg.data(), identity_msg.size(), sendbuf);
				last_id = now;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(20));
		}
		if (!m_authenticated.load()) {
			if (m_auth_failed.load()) {
				if (m_auth_deny_reason.load() == 1) {
					LOG_ERR("[UDP] 注册令牌无效或已使用，已自动清除 RegisterToken，将以登录模式重试\n");
				} else {
					LOG_ERR("[UDP] 身份认证被服务器拒绝：该身份未注册。\n"
						"      首次使用请在服务器执行 ./build/vpn_server --gen-token 生成令牌，\n"
						"      填入 config.ini 的 [Identity] RegisterToken 后连接完成注册\n");
				}
			}
			m_need_reconnect.store(true);
			return;
		}
		LOG_ERR("[UDP] 身份认证通过，隧道可用（阶段3完成）\n");
		if (!m_register_token.empty()) {
			LOG_ERR("[UDP] 提示：注册成功，register_token 已一次性作废；\n"
				"      已自动清空 config.ini 的 RegisterToken，下次连接自动为登录模式\n");
		}
	}

	m_handshaked.store(true);
	m_hs_state = HS_SUCCESS;

	// 数据面（心跳 + TUN 流量，全部 AES-GCM 加密）
	auto last_heart = clock_type::now();
	while (m_running.load())
	{
		if (m_need_reconnect.load()) {
			break;
		}
		const auto now = clock_type::now();

		// 心跳（TCP keepalive 的简化版）
		if (now - last_heart >= kHeartbeatInterval) {
			send_packet(static_cast<uint8_t>(m_heart), nullptr, 0, sendbuf);
			last_heart = now;
		}
		// 心跳超时：超过 kHeartbeatTimeout 未收到对端任何报文 -> 判定链路失效
		if (m_last_rx_ms.load() != 0 &&
			now - std::chrono::steady_clock::time_point(std::chrono::milliseconds(m_last_rx_ms.load())) > kHeartbeatTimeout) {
			LOG_ERR("[UDP] heartbeat timeout, peer unreachable, reconnecting\n");
			m_need_reconnect.store(true);
			break;
		}

		// 队列为空时短暂休眠，避免阻塞导致心跳无法周期发送
		if (m_sendqueue.empty()) {
			std::this_thread::sleep_for(std::chrono::milliseconds(20));
			continue;
		}
		if (!m_sendqueue.pop(buf)) {
			break;
		}
		if (buf.is_empty()) {
			continue;
		}
		size_t paysize = buf.data_size();
		if (paysize > VPN_MTU) {
			buf.clear();
			continue;
		}
		if (!send_packet(static_cast<uint8_t>(m_data), buf.get_data(), paysize, sendbuf)) {
			m_need_reconnect.store(true);
			break;
		}
		buf.clear();
	}
	if (m_handshaked.load() && !m_need_reconnect.load()) {
		m_hs_state = HS_SEND_FIN;
		send_packet(static_cast<uint8_t>(disconnect), nullptr, 0, sendbuf);
		m_hs_state = HS_IDLE;
	}
}

/*
	struct tunnel_header
{
	uint32_t magic;			    4
	uint8_t version;		    1
	uint8_t type;			    1
	uint16_t payload_len;		2
	uint32_t sequence;			4
};  12
*/
void UDP::recv_work()
{
	std::vector<uint8_t> recv_buf;
	std::vector<uint8_t> sendbuf;
	packet_buffer buf;
	recv_buf.reserve(KMax_packet_size);
	sendbuf.reserve(KMax_packet_size);
	while (m_running.load())
	{
		recv_buf.resize(KMax_packet_size);
		sockaddr_in peer_addr{};
		int peer_len = static_cast<int>(sizeof(peer_addr));
		int ret = recvfrom(
			m_sock,
			reinterpret_cast<char*>(recv_buf.data()),
			static_cast<int>(recv_buf.size()),
			0,
			reinterpret_cast<sockaddr*>(&peer_addr),
			&peer_len
		);
		if (ret <= 0) {
			continue;
		}
		if (static_cast<size_t>(ret) < Ktunnel_header) {
			continue;
		}
		tunnel_header header{};
		memcpy(&header, recv_buf.data(), Ktunnel_header);
		if (header.magic != Kmagic) {
			continue;
		}
		if (header.version != static_cast<uint8_t>(Kversion)) {
			continue;
		}
		size_t payload_len = ntohs(header.payload_len);
		if (payload_len > Max_payload_len) {
			continue;
		}
		// 校验报文完整性：头部 + payload 长度不超过实际收到字节数
		if (static_cast<size_t>(ret) < Ktunnel_header + payload_len) {
			continue;
		}
		// 任何合法报文都视为对端存活
		m_last_rx_ms.store(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
		const uint8_t* payload = recv_buf.data() + Ktunnel_header;

		// 密文类型：密钥就绪后 data/heart/identity 等均为 AES-GCM 密文，先解密再按内层类型分发
		if (header.type == static_cast<uint8_t>(m_data) ||
			header.type == static_cast<uint8_t>(m_heart) ||
			header.type == static_cast<uint8_t>(m_heart_response) ||
			header.type == static_cast<uint8_t>(m_identity) ||
			header.type == static_cast<uint8_t>(m_identity_ok) ||
			header.type == static_cast<uint8_t>(m_identity_deny))
		{
			if (!m_enc_ready.load())
			{
				continue; // 密钥未就绪前收到的数据/心跳一律丢弃
			}
			std::vector<uint8_t> enc(payload, payload + payload_len);
			std::optional<std::vector<uint8_t>> plain;
			try
			{
				// 客户端接收方向 = key_rx（m_key_s2c）
				plain = aes256_gcm_decrypt(
					m_key_s2c,
					enc, recv_buf.data(), Ktunnel_header);
			}
			catch (const std::exception& e)
			{
				LOG_ERR("[UDP] 解密异常: %s\n", e.what());
				continue;
			}
			if (!plain)
			{
				continue; // 认证失败，静默丢弃
			}
			uint8_t inner_type = 0;
			std::vector<uint8_t> inner_payload;
			if (!parse_inner_packet(*plain, inner_type, inner_payload))
			{
				continue;
			}
			switch (inner_type)
			{
			case m_data:
				if (inner_payload.empty())
					break;
				{
					packet_buffer pbuf(inner_payload.data(), inner_payload.size());
					m_recvqueue.push(std::move(pbuf));
				}
				break;
			case m_heart:
				send_packet(static_cast<uint8_t>(m_heart_response), nullptr, 0, sendbuf);
				break;
			case m_heart_response:
				break;
			case m_identity_ok:
				// 阶段3：身份验证通过
				m_authenticated.store(true);
				// 多用户服务端会在 identity_ok 里通告分配的虚拟 IP：
				// payload = [virtual_ip(4, 网络序)] [prefix(1)]
				// 客户端之后用 m_assigned_ip 覆盖 config.ini 的 VirtualIP 配置网卡
				// （见 main.cpp 的 connected_callback），保证与服务端分配一致。
				if (inner_payload.size() >= 5)
				{
					uint32_t ip_net = 0;
					memcpy(&ip_net, inner_payload.data(), 4);
					const uint32_t ip = ntohl(ip_net);
					m_assigned_ip.store(ip);
					m_assigned_prefix = inner_payload[4];
					LOG_ERR("[UDP] 服务端分配虚拟 IP: %u.%u.%u.%u/%u\n",
						(ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
						static_cast<unsigned>(m_assigned_prefix));
				}
				break;
			case m_identity_deny:
				// 阶段3：身份验证被拒绝；内层首字节为原因码 0=未注册 1=令牌无效/已使用
				m_auth_deny_reason.store(inner_payload.empty() ? -1 : static_cast<int>(inner_payload[0]));
				m_auth_failed.store(true);
				break;
			default:
				break;
			}
			continue;
		}

		// 明文类型（阶段1握手消息）
		switch (header.type)
		{
		case m_auth_server_hello:
		{
			// 阶段1：服务器响应 [nonce_s(16) || DH_SRV_EPHEM_PUB(32) || sig_srv(64)]
			if (payload_len != KAuthServerHelloLen) {
				break;
			}
			m_nonce_s.assign(payload, payload + KAuthNonceLen);
			m_dh_srv_pub.assign(payload + KAuthNonceLen, payload + KAuthNonceLen + KAuthDhPubLen);
			const uint8_t* sig = payload + KAuthNonceLen + KAuthDhPubLen;
			// sig_payload = nonce_c || nonce_s || DH_SRV_EPHEM_PUB
			std::vector<uint8_t> sig_payload;
			sig_payload.reserve(KAuthNonceLen * 2 + KAuthDhPubLen);
			sig_payload.insert(sig_payload.end(), m_nonce_c.begin(), m_nonce_c.end());
			sig_payload.insert(sig_payload.end(), m_nonce_s.begin(), m_nonce_s.end());
			sig_payload.insert(sig_payload.end(), m_dh_srv_pub.begin(), m_dh_srv_pub.end());
			if (m_server_sig_pub == nullptr) {
				m_auth_failed.store(true);
				break;
			}
			bool sig_ok = false;
			try {
				sig_ok = ed25519_verify(m_server_sig_pub, sig_payload.data(), sig_payload.size(), sig, KAuthSigLen);
			}
			catch (const std::exception&) {
				sig_ok = false;
			}
			if (!sig_ok) {
				// 中间人攻击：服务器签名校验失败，直接断开
				LOG_ERR("[UDP] SIG_SRV_PUB 验签失败：无法确认服务器身份，断开连接\n");
				m_auth_failed.store(true);
				break;
			}
			m_server_hello_ok.store(true);
			break;
		}
		case m_heart:
			// 对端心跳：回复心跳响应
			send_packet(static_cast<uint8_t>(m_heart_response), nullptr, 0, sendbuf);
			break;
		case m_heart_response:
			// 心跳确认：可用于链路检测，暂不处理
			break;
		case m_data:
		{
			// 密钥未就绪前的明文数据包（兼容/降级路径）
			if (payload_len == 0) {
				break;
			}
			packet_buffer pbuf(const_cast<uint8_t*>(payload), payload_len);
			m_recvqueue.push(std::move(pbuf));
			break;
		}
		case disconnect:
			// 对端 FIN：回复 FIN（近似 FIN+ACK），并标记需要重连
			send_packet(static_cast<uint8_t>(disconnect), nullptr, 0, sendbuf);
			m_need_reconnect.store(true);
			break;
		default:
			break;
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
