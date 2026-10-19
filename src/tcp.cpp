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

namespace {

// connect() 失败原因分类打印：这三种情况在用户侧都表现为"TCP 连不上"，
// 但排查方向完全不同（代码 / 防火墙 / 路由），必须能区分开
void log_connect_error(const char* ip, unsigned port, int err)
{
	switch (err) {
	case WSAECONNREFUSED:
		LOG_ERR("[TCP] connect %s:%u 被拒绝（RST）——服务端没有监听 TCP：\n"
			"      ① 服务端是否以 --transport both 或 tcp 启动（默认 both）；\n"
			"      ② 端口是否被其他进程占用；\n"
			"      ③ 中间设备主动回 RST（部分企业网关/运营商对非 443 端口的 TCP 直接拒绝）\n",
			ip, port);
		break;
	case WSAETIMEDOUT:
		LOG_ERR("[TCP] connect %s:%u 超时——SYN 无响应：\n"
			"      防火墙/安全组只放行了 UDP，或该端口 TCP 被丢包（非 RST）\n",
			ip, port);
		break;
	case WSAENETUNREACH:
	case WSAEHOSTUNREACH:
		LOG_ERR("[TCP] connect %s:%u 不可达（WSA=%d）：本机没有到该地址的路由，"
			"或服务器 bypass 路由缺失（隧道已建立时可能把 SYN 送进了隧道）\n", ip, port, err);
		break;
	case WSAEADDRNOTAVAIL:
		LOG_ERR("[TCP] connect %s:%u 源地址不可用（WSA=%d）\n", ip, port, err);
		break;
	case WSAEHOSTDOWN:
		LOG_ERR("[TCP] connect %s:%u 主机已关闭（WSA=%d）\n", ip, port, err);
		break;
	default:
		LOG_ERR("[TCP] connect %s:%u 失败，WSA 错误码=%d\n", ip, port, err);
		break;
	}
}

// 目标地址的 "ip:port" 文本（日志用）
void format_peer(const sockaddr_in& addr, char* out, size_t cap, unsigned& port)
{
	char ip[INET_ADDRSTRLEN] = { 0 };
	::InetNtopA(AF_INET, &addr.sin_addr, ip, sizeof(ip));
	port = ntohs(addr.sin_port);
	snprintf(out, cap, "%s", ip);
}

} // namespace

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
//
// 失败原因必须落在日志里：原先三种失败（RST / SYN 超时 / 不可达）统一
// return false，上层只打一句"UDP init 失败"，用户看到的现象就是
// "TCP 连不上，日志什么也没说"——排查只能靠猜。
bool TCP::establish()
{
	char ip[INET_ADDRSTRLEN] = { 0 };
	unsigned port = 0;
	format_peer(m_sockaddr, ip, sizeof(ip), port);

	u_long nonblock = 1;
	if (ioctlsocket(m_sock, FIONBIO, &nonblock) == SOCKET_ERROR) {
		LOG_ERR("[TCP] ioctlsocket(FIONBIO) 失败: WSA=%d\n", WSAGetLastError());
		return false;
	}
	if (connect(m_sock, reinterpret_cast<sockaddr*>(&m_sockaddr), sizeof(m_sockaddr)) == SOCKET_ERROR) {
		const int err = WSAGetLastError();
		if (err != WSAEWOULDBLOCK) {
			log_connect_error(ip, port, err);
			return false;
		}
		fd_set wset;
		FD_ZERO(&wset);
		FD_SET(m_sock, &wset);
		timeval tv{ 4, 0 };
		const int sel = select(0, nullptr, &wset, nullptr, &tv);
		if (sel == SOCKET_ERROR) {
			LOG_ERR("[TCP] connect %s:%u 等待可写时 select 失败: WSA=%d\n",
				ip, port, WSAGetLastError());
			return false;
		}
		if (sel == 0) {
			// 4s 内既没成功也没失败 = SYN 被静默丢弃：几乎总是放行规则/端口问题
			log_connect_error(ip, port, WSAETIMEDOUT);
			return false;
		}
		int soerr = 0;
		int slen = sizeof(soerr);
		if (getsockopt(m_sock, SOL_SOCKET, SO_ERROR,
			reinterpret_cast<char*>(&soerr), &slen) == SOCKET_ERROR) {
			LOG_ERR("[TCP] connect %s:%u 后 getsockopt(SO_ERROR) 失败: WSA=%d\n",
				ip, port, WSAGetLastError());
			return false;
		}
		if (soerr != 0) {
			log_connect_error(ip, port, soerr);   // 连接被拒（RST）
			return false;
		}
	}
	BOOL nodelay = TRUE;
	if (setsockopt(m_sock, IPPROTO_TCP, TCP_NODELAY,
		reinterpret_cast<const char*>(&nodelay), sizeof(nodelay)) == SOCKET_ERROR) {
		// 非致命：Nagle 未关只是延迟变差，不该因此判定连接失败
		LOG_ERR("[TCP] 设置 TCP_NODELAY 失败: WSA=%d（继续，但小包延迟会变高）\n",
			WSAGetLastError());
	}
	// 收发缓冲已在 UDP::init() 里统一放大（8MB）：这里不再重复设置，
	// 否则后写的值会覆盖前面的，两个数字互相打脸
	LOG_KEY("[TCP] 已连接 %s:%u（TCP_NODELAY 已开启）", ip, port);
	return true;
}

// TCP：循环写直到整帧发出（send 可能部分写）。
// 非阻塞 socket 的 WSAEWOULDBLOCK 用 WSAPoll 等可写（事件驱动，无 sleep 轮询）。
//
// 等待上限 1s（原 5s）。为什么必须缩短：send_packet 全程持有 m_send_mutex，
// 而收包线程处理对端心跳时要拿同一把锁回 heart_response——写侧在对端窗口
// 关闭时卡 5s，收包线程就跟着卡 5s，期间 m_last_rx_ms 不刷新，
// 正好触到客户端 5s 心跳超时阈值 → "网速卡住 + 无故重连"。
// 单帧丢弃有隧道内 TCP 重传兜底，代价远小于拖死收包线程。
bool TCP::raw_send(const uint8_t* data, size_t len)
{
	size_t off = 0;
	const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1000);
	while (off < len) {
		int n = send(m_sock, reinterpret_cast<const char*>(data + off),
			static_cast<int>(len - off), 0);
		if (n == SOCKET_ERROR) {
			int err = WSAGetLastError();
			if (err == WSAEWOULDBLOCK) {
				// 缓冲满：等 socket 可写后重试；总时长超限放弃本帧
				if (std::chrono::steady_clock::now() >= deadline) {
					LOG_ERR("[TCP] send 持续 1s 不可写（对端窗口关闭/消费不动），放弃本帧\n");
					return false;
				}
				WSAPOLLFD pfd{};
				pfd.fd = m_sock;
				pfd.events = POLLOUT;
				const int pr = WSAPoll(&pfd, 1, 20);
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
			LOG_ERR("[TCP] send 失败: WSA=%d，标记重连\n", err);
			m_need_reconnect.store(true);
			return false;
		}
		if (n == 0) {
			// 非阻塞 socket 上 send 返回 0 极罕见：对端已关闭，避免死循环
			LOG_ERR("[TCP] send 返回 0（对端已关闭），标记重连\n");
			m_need_reconnect.store(true);
			return false;
		}
		off += static_cast<size_t>(n);
	}
	return true;
}

// 回收接收缓冲里已消费的前缀。
// 只在"全部读完"或"读了 ≥64KB"时 memmove 一次：原实现每交付一帧就
// vector::erase 一次，高吞吐（>1000 帧/s）下等于每包一次 O(n) 搬运。
void TCP::compact_rx()
{
	if (m_rxOff == 0) {
		return;
	}
	if (m_rxOff >= m_rxBuf.size()) {
		m_rxBuf.clear();
		m_rxOff = 0;
		// 峰值过后释放容量，避免一条大流量连接长期占着几十 KB
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

// 从接收缓冲取一帧（不动 socket）：
//   1 = 整帧已交付（payload/m_consumed 已设置）
//   0 = 数据不足一帧（半包/空缓冲）
//  -1 = 非法帧头（连接作废，调用方标记重连）
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
		return 0;   // 半包：等下一段数据
	}
	// 整帧到手：payload 指向载荷起始（下一次调用会先推进 m_rxOff）。
	// handle_frame 统一按 payload - Ktunnel_header 推导 AAD（帧头起始），
	// 与 UDP 基类及服务端（tcpserver.cpp 传 rxBuf.data() + Ktunnel_header）一致
	payload = base + Ktunnel_header;
	m_consumed = Ktunnel_header + pay_len;
	return 1;
}

// TCP 分帧：先吃接收缓冲，不够再 poll+recv（粘包/半包状态机）。
//   ① 先推进上一帧的读偏移，再把缓冲里已凑齐的帧直接交付——一次 recv
//      收到的多条粘包由外层 recv_work 循环连续逐帧处理，帧间零系统调用
//   ② 缓冲不足：WSAPoll 200ms 短超时等数据（替代 1ms sleep 轮询），
//      超时让外层循环回来检查 m_running/重连标志
//   ③ 一次 recv 取一大块（16KB，原来是 1441B = 一帧）：下载方向上把
//      "每帧 1 次 poll + 1 次 recv + 1 次 erase" 降到 "每 16KB 一次"
// 返回 false = 连接死亡（对端关闭/致命错误），收包线程应退出
bool TCP::recv_frame(tunnel_header& hdr, const uint8_t*& payload,
                     size_t& pay_len, bool& got)
{
	got = false;
	// 上一次交付的帧：只推进读偏移，不在这里搬运内存
	if (m_consumed > 0) {
		m_rxOff += m_consumed;
		m_consumed = 0;
		compact_rx();
	}

	// ① 先吃缓冲：不碰 socket，粘包帧直接逐帧交付
	const int taken = take_frame(hdr, payload, pay_len);
	if (taken > 0) {
		got = true;
		return true;
	}
	if (taken < 0) {
		m_need_reconnect.store(true);
		return false;
	}
	// taken == 0：缓冲不足一帧，需要补数据

	// ② 非阻塞 socket：poll 短超时等数据（无 sleep 轮询）
	for (;;) {
		if (!m_running.load()) {
			return true;    // stop()：外层循环回到条件检查后退出
		}
		WSAPOLLFD pfd{};
		pfd.fd = m_sock;
		pfd.events = POLLIN;
		const int pr = WSAPoll(&pfd, 1, 200);
		if (pr == SOCKET_ERROR) {
			LOG_ERR("[TCP] poll 失败: %d，标记重连\n", WSAGetLastError());
			m_need_reconnect.store(true);
			return false;
		}
		if (pr == 0) {
			return true;    // 超时：外层循环继续
		}
		if (pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) {
			// 必须区分两种情况：本地 stop() 关闭 socket 时 WSAPoll 会返回 POLLNVAL，
			// 与"对端真的关了/链路出错"共用一条日志时，本地断开会被误读成
			// "服务端把我踢了"，排查方向直接跑偏（历史上已发生）
			if ((pfd.revents & POLLNVAL) || !m_running.load()) {
				LOG_INFO("[TCP] 本地已关闭 socket（停止/重连收尾），收包线程退出");
				return false;
			}
			LOG_INFO("[TCP] 对端关闭或连接错误（POLLERR/POLLHUP），标记重连");
			m_need_reconnect.store(true);
			return false;
		}
		break;              // POLLIN：有数据可读
	}

	// ③ recv 一大块数据入缓冲
	uint8_t tmp[16 * 1024];
	int n = recv(m_sock, reinterpret_cast<char*>(tmp), static_cast<int>(sizeof(tmp)), 0);
	if (n == 0) {           // 对端优雅关闭（FIN）
		LOG_INFO("[TCP] 对端已关闭连接（收到 FIN），标记重连");
		m_need_reconnect.store(true);
		return false;
	}
	if (n < 0) {
		int err = WSAGetLastError();
		if (err == WSAEWOULDBLOCK) {
			// 与 poll 结果的竞态窗口内数据被取走：直接回到外层循环，不 sleep
			return true;
		}
		LOG_ERR("[TCP] recv 失败: %d，标记重连\n", err);
		m_need_reconnect.store(true);
		return false;
	}
	m_rxBuf.insert(m_rxBuf.end(), tmp, tmp + n);

	// ④ 再试交付一帧（仍半包则下轮 poll+recv 补齐）
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