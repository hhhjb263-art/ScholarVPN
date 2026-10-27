#pragma once

#include "itun_device.h"       // tun_id_t
#include "platform/cfgstr.h"
#include "platform/cidr.h"     // 分流用的 CIDR 列表

#include <cstdint>
#include <cstddef>
#include <set>
#include <string>
#include <vector>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")   // htonl / InetPtonW（分流注入时用）
#endif

// 一条 IPv4 路由的参数（Windows 走 IP Helper；Linux 拼 ip route 命令）
struct Ipv4RouteParam {
	cfgstr destination;
	uint8_t prefixLength = 0;
	cfgstr nexthop;
	tun_id_t interfaceId{};
	uint32_t metric = 0;
};

// ============================================================================
// 路由管理
//
// 两端策略一致：
//   1. 先加"到服务器的 /32 bypass 路由"——握手包必须走物理网卡，
//      否则隧道还没建立、默认路由已指向 TUN，握手全进黑洞。
//   2. 连接成功后才加默认路由（Linux 用 0.0.0.0/1 + 128.0.0.0/1 拆分，
//      不覆盖系统原有 default，断开时只需删自己加的两条）。
//   3. 断线/停止时只删自己加过的，绝不碰系统原有路由。
// ============================================================================
class RouteManager final
{
public:
	explicit RouteManager(tun_id_t tunnelId);
	~RouteManager();

	bool add_ipv4_route(const Ipv4RouteParam& param);
	bool add_tunnel_route(
		const cfgstr& destination,
		uint8_t prefixLength,
		uint32_t metric);

	bool add_default_route(uint32_t metric);
	// IPv6 kill-switch：把 ::/0 指向 TUN（本隧道只承载 IPv4），阻止 IPv6 流量
	// 绕过隧道泄漏真实出口 IP。
	// ⚠️ 当前**不在连接流程中调用**：2026-09-25 实测，加上这条之后客户端只会本地
	// 静默丢弃 IPv6 包，V6 优先的应用要等 10~20s 连接超时才回落 IPv4，表现为
	// "连上了但很多应用打不开/很慢"（Android 端同因已回滚该路由）。
	// 要重新启用，必须先实现对 IPv6 包的 fail-fast 回应（ICMPv6 Destination
	// Unreachable / TCP RST），否则宁可让它走物理网卡。
	bool add_ipv6_default_route(uint32_t metric);
	bool add_server_bypass_route(const cfgstr& serverIp);

	// ---- 流量分流（Mode=split）----
	// 把一批 CIDR 指向"通往 probeIp 的物理出口"（下一跳 = 物理网关）。
	// 这些前缀比隧道的 0.0.0.0/1 更长，因此会优先命中 → 国内流量直连。
	// 返回成功注入的条数；失败条目不记录（调用方据此判断是否整体回滚）。
	int add_bypass_routes(const std::vector<cidr::Cidr>& cidrs, const cfgstr& probeIp);

	// 只撤销分流路由，保留默认路由与服务器 bypass（切换 split→full 时用）
	void remove_split_routes() noexcept;

	// 当前生效的分流路由条数（用于日志与"是否已注入"判断）
	std::size_t split_route_count() const noexcept;

	// 自校验：从系统路由表统计这批分流条目**真正存在**的条数。
	// 用途：CreateIpForwardEntry2 返回成功不代表写进去了（权限/接口/参数问题都可能静默失败），
	// 只有读回来才算数。返回 -1 表示当前平台未实现该校验。
	int count_active_split_routes() const;
	// 只删除默认路由，保留服务器 bypass 路由——断线重连时调用，
	// 撤销"全流量进 TUN"的黑洞，让物理网卡正常上网，同时握手包仍走 bypass。
	void remove_default_route() noexcept;
	void clear_routes() noexcept;

private:
#if defined(_WIN32)
	bool create_route(const MIB_IPFORWARD_ROW2& route);
#endif
private:
	tun_id_t m_tunnelId{};
	// 已注入的分流 CIDR（key = addr<<8 | prefix）。用于幂等：
	// 重复调用 add_bypass_routes 时跳过已存在的条目，避免 m_splitRoutes 膨胀
	// （断线重连/模式切换都可能重复走到这里）。
	std::set<uint64_t> m_splitKeys;
#if defined(_WIN32)
	std::vector<MIB_IPFORWARD_ROW2> m_createdRoutes;
	// 分流路由单独存一份：切换模式时只撤销这一批，不碰默认路由与服务器 bypass
	std::vector<MIB_IPFORWARD_ROW2> m_splitRoutes;
#else
	// Linux：记录"删除命令"，清理时原样执行（只删自己加过的）
	std::vector<std::string> m_addedRoutes;
	std::vector<std::string> m_splitRoutes;
#endif
};
