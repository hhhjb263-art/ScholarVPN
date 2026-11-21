#pragma once

#include "itun_device.h"
#include "platform/cfgstr.h"
#include "platform/cidr.h"

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
#pragma comment(lib, "ws2_32.lib")
#endif

struct Ipv4RouteParam {
	cfgstr destination;
	uint8_t prefixLength = 0;
	cfgstr nexthop;
	tun_id_t interfaceId{};
	uint32_t metric = 0;
};

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
	bool add_ipv6_default_route(uint32_t metric);
	bool add_server_bypass_route(const cfgstr& serverIp);

	int add_bypass_routes(const std::vector<cidr::Cidr>& cidrs, const cfgstr& probeIp);

	void remove_split_routes() noexcept;

	std::size_t split_route_count() const noexcept;

	int count_active_split_routes() const;
	void remove_default_route() noexcept;
	void clear_routes() noexcept;

private:
#if defined(_WIN32)
	bool create_route(const MIB_IPFORWARD_ROW2& route);
#endif
private:
	tun_id_t m_tunnelId{};
	std::set<uint64_t> m_splitKeys;
#if defined(_WIN32)
	std::vector<MIB_IPFORWARD_ROW2> m_createdRoutes;
	std::vector<MIB_IPFORWARD_ROW2> m_splitRoutes;
#else
	std::vector<std::string> m_addedRoutes;
	std::vector<std::string> m_splitRoutes;
#endif
};
