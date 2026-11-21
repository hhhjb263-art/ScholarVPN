#include "UDP.h"
#include "logger.h"
#include "tun_macro.h"
#include <cstdio>
#include <chrono>
#include <cstring>
#include <random>
#include <stdexcept>
#include <string>
#include "Crypt.h"
#include <openssl/rand.h>

namespace {

constexpr auto kAuthTimeout = std::chrono::seconds(8);
constexpr auto kAuthRetryInterval = std::chrono::milliseconds(500);
constexpr int kAuthMaxRetries = 10;

constexpr auto kHeartbeatInterval = std::chrono::seconds(1);

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

UDP::UDP(const char* remoteip, uint16_t port, bool is_running, size_t queueMax) :
	m_sock(SOCK_INVALID), m_sendqueue(queueMax), m_recvqueue(queueMax)
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
	if (m_sock != SOCK_INVALID) {
		sock_close(m_sock);
		m_sock = SOCK_INVALID;
	}
	sock_runtime_stop();
}

// 传输层初始化：建套接字、起收发线程，会话状态在这里复位
bool UDP::init()
{
	if (m_running.load() || send_thread.joinable() || recv_thread.joinable()) {
		return false;
	}
	if (!sock_runtime_start()) {
		return false;
	}
	const char* tname = (proto_version() == static_cast<uint8_t>(v_tcp)) ? "TCP" : "UDP";
	m_sock = open_socket();
	if (m_sock == SOCK_INVALID) {
		LOG_ERR("[%s] socket() 创建失败: WSA=%d\n", tname, sock_last_error());
		sock_runtime_stop();
		return false;
	}
	{
		const int bufsize = 8 * 1024 * 1024;
		setsockopt(m_sock, SOL_SOCKET, SO_RCVBUF,
			reinterpret_cast<const char*>(&bufsize), sizeof(bufsize));
		setsockopt(m_sock, SOL_SOCKET, SO_SNDBUF,
			reinterpret_cast<const char*>(&bufsize), sizeof(bufsize));
	}
	if (!establish()) {
		char ipbuf[INET_ADDRSTRLEN] = { 0 };
		sock_ntop(m_sockaddr.sin_addr, ipbuf, sizeof(ipbuf));
		LOG_ERR("[%s] 建立隧道失败：%s:%u（详见上一行原因）\n",
			tname, ipbuf, ntohs(m_sockaddr.sin_port));
		sock_close(m_sock);
		m_sock = SOCK_INVALID;
		sock_runtime_stop();
		return false;
	}

	m_handshaked.store(false);
	m_authenticated.store(false);
	m_auth_failed.store(false);
	m_auth_deny_reason.store(-1);
	m_server_hello_ok.store(false);
	m_enc_ready.store(false);
	m_need_reconnect.store(false);
	m_replay.reset();
	m_nonce_s.clear();
	m_dh_cli_pub.clear();
	m_dh_srv_pub.clear();
	if (m_dh_cli_priv != nullptr) {
		EVP_PKEY_free(m_dh_cli_priv);
		m_dh_cli_priv = nullptr;
	}
	secure_wipe(m_key_c2s);
	secure_wipe(m_key_s2c);
	m_seq.store(0, std::memory_order_relaxed);
	m_last_rx_ms.store(std::chrono::duration_cast<std::chrono::milliseconds>(
		std::chrono::steady_clock::now().time_since_epoch()).count());

	if (m_server_sig_pub != nullptr) {
		EVP_PKEY_free(m_server_sig_pub);
		m_server_sig_pub = nullptr;
	}
	try {
		m_server_sig_pub = load_ed25519_public_key_pem(m_server_sig_pub_pem);
		{
			std::vector<uint8_t> raw;
			size_t klen = 0;
			if (EVP_PKEY_get_raw_public_key(m_server_sig_pub, nullptr, &klen) == 1) {
				raw.resize(klen);
				EVP_PKEY_get_raw_public_key(m_server_sig_pub, raw.data(), &klen);
				char hex[65] = { 0 };
				for (size_t i = 0; i < klen && i < 32; ++i)
					snprintf(hex + i * 2, 3, "%02x", raw[i]);
				LOG_KEY("[Identity] 客户端验签用的服务器公钥指纹: %s", hex);
			}
		}
	}
	catch (const std::exception& e) {
		LOG_ERR("[UDP] 无法解析服务器身份公钥 SIG_SRV_PUB: %s\n", e.what());
		sock_close(m_sock);
		m_sock = SOCK_INVALID;
		sock_runtime_stop();
		return false;
	}

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
	if (m_sock != SOCK_INVALID) {
		sock_close(m_sock);
		m_sock = SOCK_INVALID;
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
	m_replay.reset();
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

void UDP::send_ip_packet(packet_buffer&& buf)
{
	if (!m_running.load()) {
		return;
	}
	if (!m_sendqueue.push(std::move(buf))) {
		const uint32_t n = m_tx_queue_drop.fetch_add(1);
		if (n < 3) {
			LOG_ERR("[%s] 上行发送队列已满（上限 %zu 包），丢弃报文%s\n",
				(proto_version() == static_cast<uint8_t>(v_tcp)) ? "TCP" : "UDP",
				m_sendqueue.size(),
				(n == 2) ? "（同类日志已抑制，累计丢包数见退出前统计）" : "");
		}
	}
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
	if (len > KMax_data_payload)
		return false;
	std::lock_guard<std::mutex> lock(m_send_mutex);
	size_t total_len = Ktunnel_header + len;
	sendbuf.resize(total_len);
	tunnel_header header{};

	header.magic = Kmagic;
	header.version = proto_version();
	header.type = type;
	header.payload_len = htons(static_cast<uint16_t>(len));
	uint32_t seq = m_seq.fetch_add(1);
	if (seq >= kSeqRekeyLimit) {
		LOG_ERR("[UDP] 发送序号达到安全上限，触发重连换会话\n");
		m_need_reconnect.store(true);
		return false;
	}
	header.sequence = htonl(seq);

	memcpy(sendbuf.data(), &header, Ktunnel_header);
	if (m_enc_ready.load() && (type == static_cast<uint8_t>(m_data) ||
		type == static_cast<uint8_t>(m_heart) ||
		type == static_cast<uint8_t>(m_heart_response) ||
		type == static_cast<uint8_t>(m_identity) ||
		type == static_cast<uint8_t>(m_identity_ok) ||
		type == static_cast<uint8_t>(m_identity_deny) ||
		type == static_cast<uint8_t>(disconnect)))
	{
		const size_t enc_len = len + 1 + AES_GCM_NONCE_LEN + AES_GCM_TAG_LEN;
		if (enc_len > Max_payload_len)
			return false;
		header.payload_len = htons(static_cast<uint16_t>(enc_len));
		memcpy(sendbuf.data(), &header, Ktunnel_header);
		sendbuf.resize(Ktunnel_header + enc_len);
		size_t sealed_len = 0;
		try
		{
			sealed_len = aes256_gcm_seal(
				m_key_c2s,
				&type, 1,
				len ? data : nullptr, len,
				sendbuf.data(), Ktunnel_header,
				sendbuf.data() + Ktunnel_header, sendbuf.size() - Ktunnel_header);
		}
		catch (const std::exception& e)
		{
			LOG_ERR("[UDP] 加密失败: %s\n", e.what());
			return false;
		}
		if (sealed_len != enc_len)
			return false;
		sendbuf.resize(Ktunnel_header + sealed_len);
		total_len = Ktunnel_header + sealed_len;
		return raw_send(sendbuf.data(), total_len);
	}
	if (len) {
		memcpy(sendbuf.data() + Ktunnel_header, data, len);
	}
	return raw_send(sendbuf.data(), total_len);
}

sock_t UDP::open_socket()
{
	return socket(AF_INET, SOCK_DGRAM, 0);
}

// UDP 无连接，空实现只为满足传输接口；TCP 分支才真正建连
bool UDP::establish()
{
	return true;
}

bool UDP::raw_send(const uint8_t* data, size_t len)
{
	int ret = sendto(m_sock, reinterpret_cast<const char*>(data), static_cast<int>(len), 0,
		reinterpret_cast<const sockaddr*>(&m_sockaddr), sizeof(m_sockaddr));
	if (ret == SOCK_ERR) {
		if (sock_last_error() == kSockConnReset)
			m_need_reconnect.store(true);
		return false;
	}
	return true;
}

bool UDP::recv_frame(tunnel_header& hdr, const uint8_t*& payload, size_t& pay_len, bool& got)
{
	m_udpBuf.resize(KMax_packet_size);
	sockaddr_in peer_addr{};
	sock_len_t peer_len = static_cast<sock_len_t>(sizeof(peer_addr));
	sock_ssize_t ret = recvfrom(m_sock, reinterpret_cast<char*>(m_udpBuf.data()),
		static_cast<int>(m_udpBuf.size()), 0,
		reinterpret_cast<sockaddr*>(&peer_addr), &peer_len);
	if (ret <= 0) {
		got = false;
		return true;
	}
	if (peer_addr.sin_addr.s_addr != m_sockaddr.sin_addr.s_addr ||
		peer_addr.sin_port != m_sockaddr.sin_port)
	{
		char src_buf[INET_ADDRSTRLEN] = { 0 };
		char dst_buf[INET_ADDRSTRLEN] = { 0 };
		sock_ntop(peer_addr.sin_addr, src_buf, sizeof(src_buf));
		sock_ntop(m_sockaddr.sin_addr, dst_buf, sizeof(dst_buf));
		LOG_DBG("[UDP] 丢弃非目标服务器报文: %s:%u (期望 %s:%u)\n",
			src_buf, ntohs(peer_addr.sin_port),
			dst_buf, ntohs(m_sockaddr.sin_port));
		got = false;
		return true;
	}
	if (static_cast<size_t>(ret) < Ktunnel_header) {
		got = false;
		return true;
	}
	memcpy(&hdr, m_udpBuf.data(), Ktunnel_header);
	if (hdr.magic != Kmagic) {
		LOG_ERR("[UDP] 收到非法 magic=0x%08X 的报文，丢弃\n", hdr.magic);
		got = false;
		return true;
	}
	if (hdr.version != proto_version()) {
		LOG_ERR("[UDP] 协议版本不匹配: 收到 v%u, 本端 v%u —— 服务端版本可能与客户端不一致，丢弃\n",
			static_cast<unsigned>(hdr.version), static_cast<unsigned>(proto_version()));
		got = false;
		return true;
	}
	pay_len = ntohs(hdr.payload_len);
	if (pay_len > Max_payload_len) {
		LOG_ERR("[UDP] payload 超长: %zu 字节，丢弃\n", pay_len);
		got = false;
		return true;
	}
	if (static_cast<size_t>(ret) < Ktunnel_header + pay_len) {
		LOG_ERR("[UDP] 报文不完整: 实际 %d 字节 < 头部+%zu，丢弃\n", ret, pay_len);
		got = false;
		return true;
	}
	payload = m_udpBuf.data() + Ktunnel_header;
	got = true;
	return true;
}

// 组装身份报文（含注册标志与 Ed25519 签名）；协议新增认证字段从这里改
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
	const uint8_t flags = m_register_token.empty() ? 0 : 1;
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
	try {
	std::vector<uint8_t> sendbuf;
	sendbuf.reserve(KMax_packet_size);
	packet_buffer buf;

	using clock_type = std::chrono::steady_clock;
	const auto auth_start = clock_type::now();
	auto last_retry = auth_start;
	int retries = 0;

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
		return;
	}

	if (!generate_ephemeral_x25519(m_dh_cli_priv, m_dh_cli_pub)) {
		LOG_ERR("[UDP] 生成临时 X25519 密钥对失败\n");
		m_need_reconnect.store(true);
		return;
	}
	send_packet(static_cast<uint8_t>(m_auth_client_hello), m_dh_cli_pub.data(), m_dh_cli_pub.size(), sendbuf);

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
		m_key_c2s = std::move(keys.key_tx);
		m_key_s2c = std::move(keys.key_rx);
		m_enc_ready.store(true);
		LOG_INFO("[UDP] 加密隧道已建立（阶段2完成）");
	}

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
				if (!m_dh_cli_pub.empty()) {
					send_packet(static_cast<uint8_t>(m_auth_client_hello),
						m_dh_cli_pub.data(), m_dh_cli_pub.size(), sendbuf);
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
				} else if (m_auth_deny_reason.load() == 2) {
					LOG_ERR("[UDP] 已超出使用范围，请联系管理员\n"
						"      可在「设置 → 服务」刷新状态后重试\n");
				} else {
					LOG_ERR("[UDP] 身份认证被服务器拒绝：该身份未注册。\n"
						"      首次使用请在服务器执行 ./build/vpn_server --gen-token 生成令牌，\n"
						"      填入 config.ini 的 [Identity] RegisterToken 后连接完成注册\n");
				}
			}
			m_need_reconnect.store(true);
			return;
		}
		LOG_INFO("[UDP] 身份认证通过，隧道可用（阶段3完成）");
		if (!m_register_token.empty()) {
			LOG_INFO("[UDP] 提示：注册成功，register_token 已一次性作废；"
				"已自动清空 config.ini 的 RegisterToken，下次连接自动为登录模式");
		}
	}

	m_handshaked.store(true);
	m_hs_state = HS_SUCCESS;

	auto last_heart = clock_type::now();
	while (m_running.load())
	{
		if (m_need_reconnect.load()) {
			break;
		}
		const auto now = clock_type::now();

		if (now - last_heart >= kHeartbeatInterval) {
			send_packet(static_cast<uint8_t>(m_heart), nullptr, 0, sendbuf);
			last_heart = now;
		}
		if (m_last_rx_ms.load() != 0 &&
			now - std::chrono::steady_clock::time_point(std::chrono::milliseconds(m_last_rx_ms.load())) > m_heartbeatTimeout) {
			LOG_ERR("[UDP] heartbeat timeout: %lldms 内未收到任何通过认证的对端报文"
				"（对端不可达，或本端解密失败/被反重放丢弃），重连\n",
				static_cast<long long>(std::chrono::duration_cast<std::chrono::milliseconds>(
					m_heartbeatTimeout).count()));
			m_need_reconnect.store(true);
			break;
		}

		const auto status = m_sendqueue.pop_until(buf, last_heart + kHeartbeatInterval);
		if (status == PacketQueue::PopResult::Shutdown) {
			break;
		}
		if (status == PacketQueue::PopResult::Timeout) {
			continue;
		}
		if (buf.is_empty()) {
			continue;
		}
		size_t paysize = buf.data_size();
		if (paysize > KMax_data_payload) {
			buf.clear();
			continue;
		}
		if (!send_packet(static_cast<uint8_t>(m_data), buf.get_data(), paysize, sendbuf)) {
			buf.clear();
			continue;
		}
		buf.clear();
	}
	if (m_handshaked.load() && !m_need_reconnect.load()) {
		m_hs_state = HS_SEND_FIN;
		send_packet(static_cast<uint8_t>(disconnect), nullptr, 0, sendbuf);
		m_hs_state = HS_IDLE;
	}
	}
	catch (const std::exception& e)
	{
		LOG_ERR("[UDP] send_work 异常: %s，标记重连\n", e.what());
		m_need_reconnect.store(true);
	}
	catch (...)
	{
		LOG_ERR("[UDP] send_work 未知异常，标记重连\n");
		m_need_reconnect.store(true);
	}
}

void UDP::recv_work()
{
	try {
	std::vector<uint8_t> sendbuf;
	sendbuf.reserve(KMax_packet_size);
	while (m_running.load())
	{
		tunnel_header header{};
		const uint8_t* payload = nullptr;
		size_t payload_len = 0;
		bool got = false;
		if (!recv_frame(header, payload, payload_len, got))
			break;
		if (!got)
			continue;
		handle_frame(header, payload, payload_len, sendbuf);
	}
	}
	catch (const std::exception& e)
	{
		LOG_ERR("[UDP] recv_work 异常: %s，标记重连\n", e.what());
		m_need_reconnect.store(true);
	}
	catch (...)
	{
		LOG_ERR("[UDP] recv_work 未知异常，标记重连\n");
		m_need_reconnect.store(true);
	}
}

void UDP::handle_frame(const tunnel_header& header, const uint8_t* payload,
	size_t payload_len, std::vector<uint8_t>& sendbuf)
{
	const uint8_t* aad = payload - Ktunnel_header;

		if (header.type == static_cast<uint8_t>(m_data) ||
			header.type == static_cast<uint8_t>(m_heart) ||
			header.type == static_cast<uint8_t>(m_heart_response) ||
			header.type == static_cast<uint8_t>(m_identity) ||
			header.type == static_cast<uint8_t>(m_identity_ok) ||
			header.type == static_cast<uint8_t>(m_identity_deny) ||
			header.type == static_cast<uint8_t>(disconnect))
		{
			if (!m_enc_ready.load())
			{
				return;
			}
			const uint32_t seq_host = ntohl(header.sequence);
			if (m_replay.too_old(seq_host)) {
				return;
			}
			uint8_t plain[KMax_data_payload + 1];
			size_t plain_len = 0;
			try
			{
				plain_len = aes256_gcm_open(
					m_key_s2c,
					payload, payload_len,
					aad, Ktunnel_header,
					plain, sizeof(plain));
			}
			catch (const std::exception& e)
			{
				LOG_ERR("[UDP] 解密异常: %s\n", e.what());
				return;
			}
			if (plain_len == 0)
			{
				const uint32_t n = m_auth_fail_logged.fetch_add(1);
				if (n < 3)
				{
					LOG_ERR("[UDP] 收到的密文帧认证失败（密钥不匹配/帧被篡改），丢弃%s",
						(n == 2) ? "（同类日志已抑制）" : "");
				}
				return;
			}
			if (!m_replay.accept(seq_host)) {
				const uint32_t n = m_replay_reject_logged.fetch_add(1);
				if (n < 3)
				{
					LOG_ERR("[UDP] 帧被反重放窗口拒绝（seq=%u），丢弃%s",
						seq_host, (n == 2) ? "（同类日志已抑制）" : "");
				}
				return;
			}
			m_last_rx_ms.store(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count());
			if (plain_len < 1)
				return;
			const uint8_t inner_type = plain[0];
			if (inner_type == static_cast<uint8_t>(m_data))
			{
				if (plain_len <= 1)
					return;
				{
					packet_buffer pbuf(plain + 1, plain_len - 1);
					m_recvqueue.push(std::move(pbuf));
				}
				return;
			}
			std::vector<uint8_t> inner_payload(plain + 1, plain + plain_len);
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
				m_authenticated.store(true);
				if (inner_payload.size() >= 5)
				{
					uint32_t ip_net = 0;
					memcpy(&ip_net, inner_payload.data(), 4);
					const uint32_t ip = ntohl(ip_net);
					m_assigned_ip.store(ip);
					m_assigned_prefix = inner_payload[4];
					LOG_INFO("[UDP] 服务端分配虚拟 IP: %u.%u.%u.%u/%u",
						(ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF,
						static_cast<unsigned>(m_assigned_prefix));
				}
				break;
			case m_identity_deny:
				m_auth_deny_reason.store(inner_payload.empty() ? -1 : static_cast<int>(inner_payload[0]));
				m_auth_failed.store(true);
				break;
			case disconnect:
				m_need_reconnect.store(true);
				break;
			default:
				break;
			}
			return;
		}

		switch (header.type)
		{
		case m_auth_server_hello:
		{
			if (payload_len != KAuthServerHelloLen) {
				LOG_ERR("[UDP] ServerHello 长度不匹配: 收到 %u 字节, 期望 %zu —— 服务端版本可能与客户端不一致\n",
					static_cast<unsigned>(payload_len), KAuthServerHelloLen);
				break;
			}
			m_nonce_s.assign(payload, payload + KAuthNonceLen);
			m_dh_srv_pub.assign(payload + KAuthNonceLen, payload + KAuthNonceLen + KAuthDhPubLen);
			const uint8_t* sig = payload + KAuthNonceLen + KAuthDhPubLen;
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
				LOG_ERR("[UDP] SIG_SRV_PUB 验签失败：无法确认服务器身份，断开连接\n"
					"      请核对本条目是否配了正确的 ServerPubKey（留空 = 用内置固定公钥），\n"
					"      以及服务端 keys/server_sig.pub 是否与之一致（服务端启动日志会打印指纹）\n");
				m_auth_failed.store(true);
				break;
			}
			m_server_hello_ok.store(true);
			break;
		}
		case m_heart:
			send_packet(static_cast<uint8_t>(m_heart_response), nullptr, 0, sendbuf);
			break;
		case m_heart_response:
			break;
		case m_data: {
			break;
		}
		case disconnect:
			break;
		default:
			break;
		}
}

uint32_t UDP::GenerateISN()
{
	static std::random_device rd;
	static std::mt19937 generator(rd());
	static std::uniform_int_distribution<uint32_t> dist;
	return dist(generator);
}
