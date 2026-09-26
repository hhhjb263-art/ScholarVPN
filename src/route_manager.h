#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#pragma comment(lib, "iphlpapi.lib")


struct Ipv4RouteParam{
	std::wstring destination;
	uint8_t prefixLength = 0;
	std::wstring nexthop;
	NET_LUID interfaceLuid{};
	uint32_t metric = 0;
};

class RouteManager final
{
public:
	explicit RouteManager(NET_LUID tunnelLuid);
	~RouteManager();

	bool add_ipv4_route(const Ipv4RouteParam& param);
	bool add_tunnel_route(
		const std::wstring& destination,
		uint8_t prefixLength,
		uint32_t metric);

	bool add_default_route(uint32_t metric);
	// IPv6 kill-switch：把 ::/0 指向 TUN（本隧道只承载 IPv4），阻止 IPv6 流量
	// 绕过隧道泄漏真实出口 IP。
	// ⚠️ 当前**不在连接流程中调用**：2026-09-25 实测，加上这条之后客户端只会本地
	// 静默丢弃 IPv6 包，V6 优先的应用要等 10~20s 连接超时才回落 IPv4，表现为
	// "连上了但很多应用打不开/很慢"（Android 端同因已回滚该路由）。
	// 要重新启用，必须先实现对 IPv6 包的 fail-fast 回应（ICMPv6 Destination
	// Unreachable / TCP RST），否则宁可让它走物理网卡。返回 false 只表示系统拒绝
	// 该路由，不影响 IPv4 默认路由，调用方仅记日志即可。
	bool add_ipv6_default_route(uint32_t metric);
	bool add_server_bypass_route(const std::wstring& serverIp);
	// 只删除默认路由（0.0.0.0/0），保留服务器 bypass 路由——断线重连时调用，
	// 撤销"全流量进 TUN"的黑洞，让物理网卡正常上网，同时握手包仍走 bypass。
	void remove_default_route() noexcept;
	void clear_routes() noexcept;
private:
	bool create_route(const MIB_IPFORWARD_ROW2& route);
private:
	NET_LUID m_tunnelLuid{};
	std::vector<MIB_IPFORWARD_ROW2> m_createdRoutes;
};

