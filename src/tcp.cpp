#include "tcp.h"
#include "logger.h"
#include "tun_macro.h"   // LOG_INFO

#include <chrono>

// ============================================================================
// TCP 隧道实现（类声明见 tcp.h）
// 帧规则：每条消息 = tunnel_header(12B) + payload；粘包/半包由接收缓冲
// 状态机处理。recv_frame 先吃缓冲（粘包帧连续交付），不够再 poll+recv。
// 协议版本：TCP 帧标 v_tcp。
// ============================================================================

TCP::TCP(const char* remoteip, uint16_t port,
         bool is_running, size_t queueMax)
    : UDP(remoteip, port, is_running, queueMax)
{
}

// 协议版本：TCP 帧标 v_tcp（接收侧 version 校验据此丢弃错误传输的报文）
uint8_t TCP::proto_version() const
{
	return static_cast<uint8_t>(v_tcp);
}

// TCP：流式 socket（具体连接在 establish 里做）
SOCKET TCP::open_socket()
{
	return socket(AF_INET, SOCK_STREAM, 0);
}

// 主动连接服务器（4s 超时，防不可达地址阻塞重连节奏）+ TCP_NODELAY。
// 连接完成后保持非阻塞：读侧 WSAPoll 等数据、写侧 WSAPoll 等可写
// （替代 1ms sleep 轮询）；stop() 靠 closesocket 让 poll 立即出错返回
bool TCP::establish()
{
	u_long nonblock = 1;
	ioctlsocket(m_sock, FIONBIO, &nonblock);
	if (connect(m_sock, reinterpret_cast<sockaddr*>(&m_sockaddr), sizeof(m_sockaddr)) == SOCKET_ERROR) {
		if (WSAGetLastError() != WSAEWOULDBLOCK)
			return false;
		fd_set wset;
		FD_ZERO(&wset);
		FD_SET(m_sock, &wset);
		timeval tv{ 4, 0 };
		if (select(0, nullptr, &wset, nullptr, &tv) <= 0)
			return false;               // 连接超时
		int soerr = 0;
		int slen = sizeof(soerr);
		getsockopt(m_sock, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &slen);
		if (soerr != 0)
			return false;               // 连接被拒
	}
	BOOL nodelay = TRUE;
	setsockopt(m_sock, IPPROTO_TCP, TCP_NODELAY,
		reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
	return true;
}

// TCP：循环写直到整帧发出（send 可能部分写）。
// 非阻塞 socket 的 WSAEWOULDBLOCK 用 WSAPoll 等可写（事件驱动，无 sleep 轮询），
// 总等待上限 5s：对端持续不收视为链路已死，放弃本帧——上层丢包由隧道内
// TCP 重传兜底，链路失效由心跳超时判定重连
bool TCP::raw_send(const uint8_t* data, size_t len)
{
	size_t off = 0;
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
	while (off < len) {
		int n = send(m_sock, reinterpret_cast<const char*>(data + off),
			static_cast<int>(len - off), 0);
		if (n == SOCKET_ERROR) {
			int err = WSAGetLastError();
			if (err == WSAEWOULDBLOCK) {
				// 缓冲满：等 socket 可写后重试；总时长超限放弃本帧
				if (std::chrono::steady_clock::now() >= deadline) {
					LOG_ERR("[TCP] send 持续 5s 不可写（对端消费不动），放弃本帧\n");
					return false;
				}
				WSAPOLLFD pfd{};
				pfd.fd = m_sock;
				pfd.events = POLLOUT;
				const int pr = WSAPoll(&pfd, 1, 100);
				if (pr == SOCKET_ERROR) {
					m_need_reconnect.store(true);
					return false;
				}
				if (pr > 0 && (pfd.revents & (POLLERR | POLLHUP | POLLNVAL))) {
					m_need_reconnect.store(true);
					return false;
				}
				continue;
			}
			// 流式 socket 上 send 失败基本等于连接已死亡（对端关闭/重置/
			// RST/连接被断开），统一标记重连——否则发送线程会一直空转，
			// 数据面"只发不收"的场景要拖到心跳超时才发现断线
			m_need_reconnect.store(true);
			return false;
		}
		off += static_cast<size_t>(n);
	}
	return true;
}

// 从接收缓冲取一帧（不动 socket）：
//   1 = 整帧已交付（payload/m_consumed 已设置）
//   0 = 数据不足一帧（半包/空缓冲）
//  -1 = 非法帧头（连接作废，调用方标记重连）
int TCP::take_frame(tunnel_header& hdr, const uint8_t*& payload, size_t& pay_len)
{
	if (m_rxHave < Ktunnel_header) {
		return 0;
	}
	memcpy(&hdr, m_rxBuf.data(), Ktunnel_header);
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
	if (m_rxHave < Ktunnel_header + pay_len) {
		return 0;   // 半包：等下一段数据
	}
	// 整帧到手：payload 指向载荷起始（下一次调用会先消费已交付字节）；
	// handle_frame 统一按 payload - Ktunnel_header 推导 AAD（帧头起始），
	// 与 UDP 基类（payload = 缓冲起始 + Ktunnel_header）及服务端
	// （tcpserver.cpp 传 rxBuf.data() + Ktunnel_header）保持一致
	payload = m_rxBuf.data() + Ktunnel_header;
	m_consumed = Ktunnel_header + pay_len;
	return 1;
}

// TCP 分帧：先吃接收缓冲，不够再 poll+recv（粘包/半包状态机）。
//   ① 先消费上一帧，再把缓冲里已凑齐的帧直接交付——一次 recv 收到的
//      多条粘包由外层 recv_work 循环连续逐帧处理，帧间零等待，
//      不再"交付一帧就走、下次调用先阻塞 recv"
//   ② 缓冲不足：WSAPoll 200ms 短超时等数据（替代 1ms sleep 轮询），
//      超时让外层循环回来检查 m_running/重连标志
// 返回 false = 连接死亡（对端关闭/致命错误），收包线程应退出
bool TCP::recv_frame(tunnel_header& hdr, const uint8_t*& payload,
                     size_t& pay_len, bool& got)
{
	// 上一次交付的帧：先消费掉（粘包场景下缓冲里可能还有下一条）
	if (m_consumed > 0) {
		m_rxBuf.erase(m_rxBuf.begin(), m_rxBuf.begin() + static_cast<std::ptrdiff_t>(m_consumed));
		m_rxHave -= m_consumed;
		m_consumed = 0;
	}

	// ① 先吃缓冲：不碰 socket，粘包帧直接逐帧交付
	const int taken = take_frame(hdr, payload, pay_len);
	if (taken > 0) {
		got = true;
		return true;
	}
	if (taken < 0) {
		m_need_reconnect.store(true);
		got = false;
		return false;
	}
	// taken == 0：缓冲不足一帧，需要补数据

	// ② 非阻塞 socket：poll 短超时等数据（无 sleep 轮询）
	for (;;) {
		if (!m_running.load()) {
			got = false;
			return true;    // stop()：外层循环回到条件检查后退出
		}
		WSAPOLLFD pfd{};
		pfd.fd = m_sock;
		pfd.events = POLLIN;
		const int pr = WSAPoll(&pfd, 1, 200);
		if (pr == SOCKET_ERROR) {
			LOG_ERR("[TCP] poll 失败: %d，标记重连\n", WSAGetLastError());
			m_need_reconnect.store(true);
			got = false;
			return false;
		}
		if (pr == 0) {
			got = false;
			return true;    // 超时：外层循环继续
		}
		if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			LOG_INFO("[TCP] 连接已被服务端关闭，标记重连");
			m_need_reconnect.store(true);
			got = false;
			return false;
		}
		break;              // POLLIN：有数据可读
	}

	// ③ recv 一段数据入缓冲
	uint8_t tmp[KMax_packet_size];
	int n = recv(m_sock, reinterpret_cast<char*>(tmp), static_cast<int>(sizeof(tmp)), 0);
	if (n == 0) {           // 对端优雅关闭
		LOG_INFO("[TCP] 连接已被服务端关闭，标记重连");
		m_need_reconnect.store(true);
		got = false;
		return false;
	}
	if (n < 0) {
		int err = WSAGetLastError();
		if (err == WSAEWOULDBLOCK) {
			// 与 poll 结果的竞态窗口内数据被取走：直接回到 poll，不 sleep
			got = false;
			return true;
		}
		LOG_ERR("[TCP] recv 失败: %d，标记重连\n", err);
		m_need_reconnect.store(true);
		got = false;
		return false;
	}
	m_rxBuf.insert(m_rxBuf.end(), tmp, tmp + n);
	m_rxHave += static_cast<size_t>(n);

	// ④ 再试交付一帧（仍半包则下轮 poll+recv 补齐）
	const int taken2 = take_frame(hdr, payload, pay_len);
	if (taken2 > 0) {
		got = true;
		return true;
	}
	if (taken2 < 0) {
		m_need_reconnect.store(true);
		got = false;
		return false;
	}
	got = false;
	return true;
}