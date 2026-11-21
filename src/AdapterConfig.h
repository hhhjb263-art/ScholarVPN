#pragma once

#include "itun_device.h"
#include "platform/cfgstr.h"
#include "tun_macro.h"

#if defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <iphlpapi.h>
#endif

#include <string>

class AdapterConfig {
public:
	explicit AdapterConfig(tun_id_t interfaceId);
	AdapterConfig& operator=(const AdapterConfig&) = delete;
	AdapterConfig(const AdapterConfig&) = delete;

	bool set_IPv4_address(const cfgstr& ipAddress, uint8_t prefixLenth);
	bool remove_IPv4_address(const cfgstr& ipAddress, uint8_t prefixLenth);

	int clear_IPv4_addresses(const cfgstr& keepIpv4);

	bool set_MTU(uint32_t mtu);
	bool set_metric(uint8_t metric);
	bool set_DNS_IPv4(const cfgstr& dnsServer);

private:
	tun_id_t m_id;
};
