#pragma once
#include <cstdio>
#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <chrono>
#include <cstdint>
#include <exception>
#include <fstream>
#include <iterator>
#include <vector>
#include <memory>
#include <functional>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <wincrypt.h>
#endif

#include "../UDP.h"
#include "../tun.h"
#include "../Crypt.h"
#include "../Config.h"
#include "../logger.h"
#include "../AdapterConfig.h"
#include "../route_manager.h"
#include "../reconnect_manager.h"
#include "../DnsLeakGuard.h"

#if defined(_WIN32)
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Crypt32.lib")
#endif

// 客户端核心逻辑封装（纯 C++，无 Qt）：
//   init()  → 一次性初始化（config / 身份密钥 / 网卡 / 路由）
//   start() → 启动 ReconnectManager + 两条桥接线程（立即返回）
//   stop()  → 停止隧道 / 清路由 / join 线程（可重复调用，线程安全）
// 回调在内部 worker 线程触发，UI 侧需自行切线程（如 QMetaObject::invokeMethod）。
class ClientApp {
public:
    using StateCallback = std::function<void(ConnState)>;
	using ConnectedCallback = std::function<void(const std::string&)>;
    using LogCallback = std::function<void(const std::string& line)>;
	using TokenRejectedCallback = std::function<void()>;
public:
	ClientApp();
	~ClientApp();

	bool init();            // 一次性初始化：config/身份/网卡/路由
	bool start();           // 启动 ReconnectManager + 桥接线程
	void stop();            

	// 当前进程是否已提权（管理员）。创建 Wintun 网卡 / 改路由 / 改 DNS 都需要，
	// 因此普通用户（免 UAC）启动时返回 false，init() 会失败、连接功能不可用。
	static bool is_elevated();

	// 多服务器：在 init() 之后、start() 之前调用，
	// 切换目标服务器及其各自的认证身份（ClientID/RegisterToken）
	void set_server(const ServerEntry& entry);
	ConnState state() const;
	std::string assigned_ip() const;   // 服务端分配的虚拟 IP（连接后）
	std::string server_ip() const { return m_remote; }   // 当前连接的目标服务器 IP
	std::string client_id() const;
	uint64_t tx_bytes() const { return m_txBytes.load(); }
	uint64_t rx_bytes() const { return m_rxBytes.load(); }

	// 测试用：模拟一次断线，触发状态机自动重连
	//void force_reconnect();

    void set_state_callback(StateCallback cb);
	void set_connected_callback(ConnectedCallback cb);
	void set_log_callback(LogCallback cb);
	void set_register_token_rejected_callback(TokenRejectedCallback cb);

private:
	void emit_log(const char* fmt, ...);
	void save_config();                
	void tun_to_udp_loop();             
	void udp_to_tun_loop();        

	ClientConfig m_cfg;
	cfgstr m_configPath;                // config.ini 完整路径（Windows=wstring / Linux=UTF-8）
	cfgstr m_configDir;

	std::shared_ptr<EVP_PKEY> m_ed25519Priv;
	std::string m_serverSigPubPem;
	std::string m_builtinServerSigPubPem;   // 内置硬编码公钥备份（切换未配公钥的服务器时恢复，防公钥串台）
	Transport m_transport{ Transport::UDP };   // 当前服务器条目的传输方式（UDP 默认 / TCP）
	std::string m_remote;
	uint16_t m_port = 0;

	// 以下的成员持有保证生命周期
	std::unique_ptr<ITunDevice> m_tun;   // Win: WintunTun / Linux: LinuxTun（create_tun_device）
	std::unique_ptr<AdapterConfig> m_adapter;
	std::unique_ptr<RouteManager> m_route;
	std::unique_ptr<ReconnectManager> m_mgr;
	DnsLeakGuard m_dnsGuard;              // 防 DNS 泄漏（清物理网卡 DNS + 断线恢复）
	// 桥接线程
	std::thread m_threadTunToUdp;
	std::thread m_threadUdpToTun;
	// 回调
	StateCallback m_onState;
	ConnectedCallback m_onConnect;
	LogCallback m_onLog;
	TokenRejectedCallback m_onTokenRejected;
	// 统计
	std::atomic<bool> m_running{ false };
	// 上行闸门：服务端通告的虚拟 IP 还没落到网卡上之前，禁止把 TUN 包送上隧道。
	// 否则"源地址=旧 IP"的包会被服务端源地址防伪整片丢弃（认证成功却一个包都
	// 上不去，表现为网速几十 K / 隧道内 TCP 连不上）。握手成功 -> 改网卡地址
	// -> 置 true 放行，见 start() 的 connected 回调。
	std::atomic<bool> m_tunIpReady{ false };
	std::atomic<ConnState> m_state{ ConnState::Stopped };
	std::atomic<uint64_t> m_txBytes{ 0 }, m_rxBytes{ 0 };
	std::atomic<uint64_t> m_txPkts{ 0 }, m_rxPkts{ 0 };
	// 本地丢弃的非 IPv4 报文计数（Wintun 网卡上的 IPv6 链路本地控制报文等）：
	// 隧道只承载 IPv4，这类报文不该上行（服务端必拒），限流日志用
	std::atomic<uint32_t> m_nonIpv4Dropped{ 0 };
	// 源地址与本会话虚拟 IP 不符而被本地丢弃的上行报文计数：
	// 这类包服务端必按"冒用源地址"丢弃，本地先拦下（限流日志用）
	std::atomic<uint32_t> m_srcMismatchDropped{ 0 };
};
