#include "tcp.h"
#include "logger.h"
#include "tun_macro.h"

#include <chrono>

namespace {

constexpr size_t kMaxTxPending = 4 * 1024 * 1024;

void log_connect_error(const char* ip, unsigned port, int err)
{
	switch (err) {
	case kSockConnRefused:
		LOG_ERR("[TCP] connect %s:%u 被拒绝（RST）——服务端没有监听 TCP：\n"
			"      ① 服务端是否以 --transport both 或 tcp 启动（默认 both）；\n"
			"      ② 端口是否被其他进程占用；\n"
			"      ③ 中间设备主动回 RST（部分企业网关/运营商对非 443 端口的 TCP 直接拒绝）\n",
			ip, port);
		break;
	case kSockTimedOut:
		LOG_ERR("[TCP] connect %s:%u 超时——SYN 无响应：\n"
			"      防火墙/安全组只放行了 UDP，或该端口 TCP 被丢包（非 RST）\n",
			ip, port);
		break;
	case kSockNetUnreach:
	case kSockHostUnreach:
		LOG_ERR("[TCP] connect %s:%u 不可达（err=%d）：本机没有到该地址的路由，"
			"或服务器 bypass 路由缺失（隧道已建立时可能把 SYN 送进了隧道）\n", ip, port, err);
		break;
	case kSockAddrNotAvail:
		LOG_ERR("[TCP] connect %s:%u 源地址不可用（err=%d）\n", ip, port, err);
		break;
	case kSockHostDown:
		LOG_ERR("[TCP] connect %s:%u 主机已关闭（err=%d）\n", ip, port, err);
		break;
	default:
		LOG_ERR("[TCP] connect %s:%u 失败，err=%d\n", ip, port, err);
		break;
	}
}

void format_peer(const sockaddr_in& addr, char* out, size_t cap, unsigned& port)
{
	char ip[INET_ADDRSTRLEN] = { 0 };
	sock_ntop(addr.sin_addr, ip, sizeof(ip));
	port = ntohs(addr.sin_port);
	snprintf(out, cap, "%s", ip);
}

}

TCP::TCP(const char* remoteip, uint16_t port,
         bool is_running, size_t queueMax)
    : UDP(remoteip, port, is_running, queueMax)
{
    m_heartbeatTimeout = std::chrono::seconds(20);
}

uint8_t TCP::proto_version() const
{
	return static_cast<uint8_t>(v_tcp);
}

sock_t TCP::open_socket()
{
	return socket(AF_INET, SOCK_STREAM, 0);
}

bool TCP::establish()
{
	char ip[INET_ADDRSTRLEN] = { 0 };
	unsigned port = 0;
	format_peer(m_sockaddr, ip, sizeof(ip), port);

	if (!sock_set_nonblocking(m_sock)) {
		LOG_ERR("[TCP] 设置非阻塞失败: err=%d\n", sock_last_error());
		return false;
	}
	if (connect(m_sock, reinterpret_cast<sockaddr*>(&m_sockaddr), sizeof(m_sockaddr)) == SOCK_ERR) {
		const int err = sock_last_error();
		if (err != kSockInProgress) {
			log_connect_error(ip, port, err);
			return false;
		}
		sock_pollfd pfd{};
		pfd.fd = m_sock;
		pfd.events = POLLOUT;
		const int sel = sock_poll(&pfd, 1, 4000);
		if (sel == SOCK_ERR) {
			LOG_ERR("[TCP] connect %s:%u 等待可写时 poll 失败: err=%d\n",
				ip, port, sock_last_error());
			return false;
		}
		if (sel == 0) {
			log_connect_error(ip, port, kSockTimedOut);
			return false;
		}
		int soerr = 0;
		sock_len_t slen = static_cast<sock_len_t>(sizeof(soerr));
		if (getsockopt(m_sock, SOL_SOCKET, SO_ERROR,
			reinterpret_cast<char*>(&soerr), &slen) == SOCK_ERR) {
			LOG_ERR("[TCP] connect %s:%u 后 getsockopt(SO_ERROR) 失败: err=%d\n",
				ip, port, sock_last_error());
			return false;
		}
		if (soerr != 0) {
			log_connect_error(ip, port, soerr);
			return false;
		}
	}
	int nodelay = 1;
	if (setsockopt(m_sock, IPPROTO_TCP, TCP_NODELAY,
		reinterpret_cast<const char*>(&nodelay), sizeof(nodelay)) == SOCK_ERR) {
		LOG_ERR("[TCP] 设置 TCP_NODELAY 失败: err=%d（继续，但小包延迟会变高）\n",
			sock_last_error());
	}
	LOG_KEY("[TCP] 已连接 %s:%u（TCP_NODELAY 已开启）", ip, port);
	return true;
}

bool TCP::raw_send(const uint8_t* data, size_t len)
{
	if (m_txPendingOff < m_txPending.size())
	{
		if (m_txPending.size() + len > kMaxTxPending)
		{
			LOG_ERR("[TCP] 发送积压超过 %zu 字节（对端长期不收），标记重连\n",
				static_cast<size_t>(kMaxTxPending));
			m_need_reconnect.store(true);
			return false;
		}
		if (m_txPendingOff > 0)
		{
			m_txPending.erase(m_txPending.begin(),
				m_txPending.begin() + static_cast<std::ptrdiff_t>(m_txPendingOff));
			m_txPendingOff = 0;
		}
		m_txPending.insert(m_txPending.end(), data, data + len);
		return flush_tx_pending();
	}

	size_t off = 0;
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
	while (off < len) {
		sock_ssize_t n = send(m_sock, reinterpret_cast<const char*>(data + off),
			static_cast<int>(len - off), 0);
		if (n == SOCK_ERR) {
			int err = sock_last_error();
			if (err == kSockWouldBlock) {
				if (std::chrono::steady_clock::now() >= deadline) {
					m_txPending.assign(data + off, data + len);
					m_txPendingOff = 0;
					if (m_txBacklogLogged < 3) {
						++m_txBacklogLogged;
						LOG_INFO("[TCP] socket 暂不可写，%zu 字节转入积压（不丢帧）",
							len - off);
					}
					return true;
				}
				sock_pollfd pfd{};
				pfd.fd = m_sock;
				pfd.events = POLLOUT;
				const int pr = sock_poll(&pfd, 1, 20);
				if (pr == SOCK_ERR) {
					m_need_reconnect.store(true);
					return false;
				}
				if (pr > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
					m_need_reconnect.store(true);
					return false;
				}
				continue;
			}
			LOG_ERR("[TCP] send 失败: err=%d，标记重连\n", err);
			m_need_reconnect.store(true);
			return false;
		}
		if (n == 0) {
			LOG_ERR("[TCP] send 返回 0（对端已关闭），标记重连\n");
			m_need_reconnect.store(true);
			return false;
		}
		off += static_cast<size_t>(n);
	}
	return true;
}

bool TCP::flush_tx_pending()
{
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(200);
	while (m_txPendingOff < m_txPending.size())
	{
		const size_t remain = m_txPending.size() - m_txPendingOff;
		sock_ssize_t n = send(m_sock,
			reinterpret_cast<const char*>(m_txPending.data() + m_txPendingOff),
			static_cast<int>(remain), 0);
		if (n == SOCK_ERR)
		{
			const int err = sock_last_error();
			if (err == kSockWouldBlock)
			{
				if (std::chrono::steady_clock::now() >= deadline)
					return true;
				sock_pollfd pfd{};
				pfd.fd = m_sock;
				pfd.events = POLLOUT;
				const int pr = sock_poll(&pfd, 1, 20);
				if (pr == SOCK_ERR) { m_need_reconnect.store(true); return false; }
				if (pr > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)))
				{
					m_need_reconnect.store(true);
					return false;
				}
				continue;
			}
			LOG_ERR("[TCP] 冲刷积压失败: err=%d，标记重连\n", err);
			m_need_reconnect.store(true);
			return false;
		}
		if (n == 0)
		{
			m_need_reconnect.store(true);
			return false;
		}
		m_txPendingOff += static_cast<size_t>(n);
	}
	m_txPending.clear();
	m_txPendingOff = 0;
	return true;
}

void TCP::compact_rx()
{
	if (m_rxOff == 0) {
		return;
	}
	if (m_rxOff >= m_rxBuf.size()) {
		m_rxBuf.clear();
		m_rxOff = 0;
		if (m_rxBuf.capacity() > 256 * 1024) {
			std::vector<uint8_t>().swap(m_rxBuf);
		}
		return;
	}
	if (m_rxOff >= 64 * 1024) {
		m_rxBuf.erase(m_rxBuf.begin(),
			m_rxBuf.begin() + static_cast<std::ptrdiff_t>(m_rxOff));
		m_rxOff = 0;
	}
}

int TCP::take_frame(tunnel_header& hdr, const uint8_t*& payload, size_t& pay_len)
{
	const size_t avail = m_rxBuf.size() - m_rxOff;
	if (avail < Ktunnel_header) {
		return 0;
	}
	const uint8_t* base = m_rxBuf.data() + m_rxOff;
	memcpy(&hdr, base, Ktunnel_header);
	if (hdr.magic != Kmagic || hdr.version != proto_version()) {
		LOG_ERR("[TCP] 流中出现非法帧头（magic=0x%08X v=%u），连接作废\n",
			hdr.magic, static_cast<unsigned>(hdr.version));
		return -1;
	}
	pay_len = ntohs(hdr.payload_len);
	if (pay_len > Max_payload_len) {
		LOG_ERR("[TCP] 帧超长: %zu，连接作废\n", pay_len);
		return -1;
	}
	if (avail < Ktunnel_header + pay_len) {
		return 0;
	}
	payload = base + Ktunnel_header;
	m_consumed = Ktunnel_header + pay_len;
	return 1;
}

bool TCP::recv_frame(tunnel_header& hdr, const uint8_t*& payload,
                     size_t& pay_len, bool& got)
{
	got = false;
	if (m_consumed > 0) {
		m_rxOff += m_consumed;
		m_consumed = 0;
		compact_rx();
	}

	const int taken = take_frame(hdr, payload, pay_len);
	if (taken > 0) {
		got = true;
		return true;
	}
	if (taken < 0) {
		m_need_reconnect.store(true);
		return false;
	}

	for (;;) {
		if (!m_running.load()) {
			return true;
		}
		sock_pollfd pfd{};
		pfd.fd = m_sock;
		pfd.events = POLLIN;
		const int pr = sock_poll(&pfd, 1, 200);
		if (pr == SOCK_ERR) {
			LOG_ERR("[TCP] poll 失败: %d，标记重连\n", sock_last_error());
			m_need_reconnect.store(true);
			return false;
		}
		if (pr == 0) {
			return true;
		}
		if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			if ((pfd.revents & POLLNVAL) || !m_running.load()) {
				LOG_INFO("[TCP] 本地已关闭 socket（停止/重连收尾），收包线程退出");
				return false;
			}
			LOG_INFO("[TCP] 对端关闭或连接错误（POLLERR/POLLHUP），标记重连");
			m_need_reconnect.store(true);
			return false;
		}
		break;
	}

	uint8_t tmp[16 * 1024];
	sock_ssize_t n = recv(m_sock, reinterpret_cast<char*>(tmp), static_cast<int>(sizeof(tmp)), 0);
	if (n == 0) {
		LOG_INFO("[TCP] 对端已关闭连接（收到 FIN），标记重连");
		m_need_reconnect.store(true);
		return false;
	}
	if (n < 0) {
		int err = sock_last_error();
		if (err == kSockWouldBlock) {
			return true;
		}
		LOG_ERR("[TCP] recv 失败: %d，标记重连\n", err);
		m_need_reconnect.store(true);
		return false;
	}
	m_rxBuf.insert(m_rxBuf.end(), tmp, tmp + n);

	const int taken2 = take_frame(hdr, payload, pay_len);
	if (taken2 > 0) {
		got = true;
		return true;
	}
	if (taken2 < 0) {
		m_need_reconnect.store(true);
		return false;
	}
	return true;
}
