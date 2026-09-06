#include "tcp.h"
#include "logger.h"
#include "tun_macro.h"   // LOG_INFO

#include <chrono>

// ============================================================================
// TCP 隧道实现（类声明见 tcp.h）
// 帧规则：每条消息 = tunnel_header(12B) + payload；粘包/半包由接收缓冲
// 状态机处理，凑齐一帧交付一次。协议版本：TCP 帧标 v_tcp。
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

// 主动连接服务器（4s 超时，防不可达地址阻塞重连节奏）+ TCP_NODELAY
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
	u_long blockmode = 0;
	ioctlsocket(m_sock, FIONBIO, &blockmode);   // 恢复阻塞（stop 靠 closesocket 解除 recv）
	BOOL nodelay = TRUE;
	setsockopt(m_sock, IPPROTO_TCP, TCP_NODELAY,
		reinterpret_cast<const char*>(&nodelay), sizeof(nodelay));
	return true;
}

// TCP：循环写直到整帧发出（send 可能部分写；对端不可达时标记重连）
bool TCP::raw_send(const uint8_t* data, size_t len)
{
	size_t off = 0;
	while (off < len) {
		int n = send(m_sock, reinterpret_cast<const char*>(data + off),
			static_cast<int>(len - off), 0);
		if (n == SOCKET_ERROR) {
			int err = WSAGetLastError();
			if (err == WSAEWOULDBLOCK) {
				std::this_thread::sleep_for(std::chrono::milliseconds(1));
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

// TCP 分帧：recv -> 喂接收缓冲 -> 凑齐整帧交付（粘包/半包状态机）。
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
			std::this_thread::sleep_for(std::chrono::milliseconds(1));
			got = false;
			return true;    // 无数据，继续
		}
		LOG_ERR("[TCP] recv 失败: %d，标记重连\n", err);
		m_need_reconnect.store(true);
		got = false;
		return false;
	}
	m_rxBuf.insert(m_rxBuf.end(), tmp, tmp + n);
	m_rxHave += static_cast<size_t>(n);

	// 分帧循环：一次 recv 可能携带多条粘包，凑齐一条交付一条
	for (;;)
	{
		if (m_rxHave < Ktunnel_header) {        // 半包：等下一段数据
			got = false;
			return true;
		}
		memcpy(&hdr, m_rxBuf.data(), Ktunnel_header);
		if (hdr.magic != Kmagic || hdr.version != proto_version()) {
			LOG_ERR("[TCP] 流中出现非法帧头（magic=0x%08X v=%u），连接作废\n",
				hdr.magic, static_cast<unsigned>(hdr.version));
			m_need_reconnect.store(true);
			got = false;
			return false;
		}
		pay_len = ntohs(hdr.payload_len);
		if (pay_len > Max_payload_len) {
			LOG_ERR("[TCP] 帧超长: %zu，连接作废", pay_len);
			m_need_reconnect.store(true);
			got = false;
			return false;
		}
		if (m_rxHave < Ktunnel_header + pay_len) {   // 半包：等下一段数据
			got = false;
			return true;
		}
		// 整帧到手：payload 指向载荷起始（下一次调用会先消费已交付字节）；
		// handle_frame 统一按 payload - Ktunnel_header 推导 AAD（帧头起始），
		// 与 UDP 基类（payload = 缓冲起始 + Ktunnel_header）及服务端
		// （tcpserver.cpp 传 rxBuf.data() + Ktunnel_header）保持一致
		payload = m_rxBuf.data() + Ktunnel_header;
		m_consumed = Ktunnel_header + pay_len;
		got = true;
		return true;
	}
}