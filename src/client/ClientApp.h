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
#include "../DnsProxy.h"

#if defined(_WIN32)
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Crypt32.lib")
#endif

class ClientApp {
public:
    using StateCallback = std::function<void(ConnState)>;
	using ConnectedCallback = std::function<void(const std::string&)>;
    // 日志级别：0=信息 1=警告 2=错误
    using LogCallback = std::function<void(int level, const std::string& line)>;
	using TokenRejectedCallback = std::function<void()>;
public:
	ClientApp();
	~ClientApp();

	bool init();
	bool start();
	void stop();

	bool routing_split() const;
	void set_routing_split(bool split);
	bool routing_intranet() const;
	void apply_intranet_routing();
	// 受管服务器一律按 full 处理：内网访问只对自建卡片开放
	bool intranet_active() const { return routing_intranet() && !m_serverManaged; }
	bool server_managed() const { return m_serverManaged; }
	cfgstr routing_mode() const;
	void set_routing_mode(const cfgstr& mode);

	void set_update_blocked(bool blocked) { m_updateBlocked.store(blocked); }
	bool update_blocked() const { return m_updateBlocked.load(); }

	void set_service_blocked(bool blocked) { m_serviceBlocked.store(blocked); }
	bool service_blocked() const { return m_serviceBlocked.load(); }

	static bool is_elevated();

	void set_server(const ServerEntry& entry);
	ConnState state() const;
	std::string assigned_ip() const;
	std::string server_ip() const { return m_remote; }
	std::string client_id() const;
	uint64_t tx_bytes() const { return m_txBytes.load(); }
	uint64_t rx_bytes() const { return m_rxBytes.load(); }

    void set_state_callback(StateCallback cb);
	void set_connected_callback(ConnectedCallback cb);
	void set_log_callback(LogCallback cb);
	void set_register_token_rejected_callback(TokenRejectedCallback cb);

private:
	void emit_log(const char* fmt, ...);
	void emit_warn(const char* fmt, ...);
	void emit_err(const char* fmt, ...);
	void save_config();
	void tun_to_udp_loop();
	void udp_to_tun_loop();

	void apply_split_routing();

	cfgstr effective_dns() const;

	ClientConfig m_cfg;
	cfgstr m_configPath;
	cfgstr m_configDir;

	std::shared_ptr<EVP_PKEY> m_ed25519Priv;
	std::string m_serverSigPubPem;
	std::string m_builtinServerSigPubPem;
	Transport m_transport{ Transport::UDP };
	std::string m_remote;
	std::string m_serverHost;
	std::atomic<bool> m_updateBlocked{ false };
	std::atomic<bool> m_serviceBlocked{ false };

	uint16_t m_port = 0;

	std::unique_ptr<ITunDevice> m_tun;
	std::unique_ptr<AdapterConfig> m_adapter;
	std::unique_ptr<RouteManager> m_route;
	std::unique_ptr<ReconnectManager> m_mgr;
	DnsLeakGuard m_dnsGuard;
	DnsProxy m_dnsProxy;
	std::thread m_threadTunToUdp;
	std::thread m_threadUdpToTun;
	StateCallback m_onState;
	ConnectedCallback m_onConnect;
	LogCallback m_onLog;
	TokenRejectedCallback m_onTokenRejected;
	std::atomic<bool> m_running{ false };
	std::atomic<bool> m_tunIpReady{ false };
	std::atomic<bool> m_intranetApplied{ false };
	bool m_serverManaged = false;
	std::atomic<ConnState> m_state{ ConnState::Stopped };
	std::atomic<uint64_t> m_txBytes{ 0 }, m_rxBytes{ 0 };
	std::atomic<uint64_t> m_txPkts{ 0 }, m_rxPkts{ 0 };
	std::atomic<uint32_t> m_nonIpv4Dropped{ 0 };
	std::atomic<uint32_t> m_srcMismatchDropped{ 0 };
};
