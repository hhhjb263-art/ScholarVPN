#pragma once

#include "itun_device.h"          // tun_id_t（Win: LUID / Linux: 接口名）
#include "platform/cfgstr.h"
#include "tun_macro.h"

#if defined(_WIN32)
// 顺序要求：windows.h 必须先于 iphlpapi.h。
// iphlpapi.h 会引入 netioapi.h，而 netioapi.h 里的 NETIO_STATUS 就是 NTSTATUS
// （定义在 winnt.h）——iphlpapi 在前会让整份 netioapi.h 全部报"缺少类型说明符"。
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <iphlpapi.h>
#endif

#include <string>

// ============================================================================
// 虚拟网卡的网络参数配置：IPv4 地址 / MTU / metric / DNS
//
// 两端语义差异：
//   Windows：IP Helper（LUID 定位）+ netsh 设 MTU/metric + DNS API
//   Linux  ：`ip addr` / `ip link` + `resolvectl`（per-interface DNS）
//            Linux 的 tun 默认是 down 的，构造时负责 `ip link set up`
// ============================================================================
class AdapterConfig {
public:
	explicit AdapterConfig(tun_id_t interfaceId);
	AdapterConfig& operator=(const AdapterConfig&) = delete;
	AdapterConfig(const AdapterConfig&) = delete;

	bool set_IPv4_address(const cfgstr& ipAddress, uint8_t prefixLenth);
	bool remove_IPv4_address(const cfgstr& ipAddress, uint8_t prefixLenth);

	// 清掉本网卡上【除 keepIpv4 之外】的全部 IPv4 地址，返回删除成功的个数
	// （keepIpv4 为空 = 全清）。
	//
	// 为什么必须有这个：重连时服务端会分配【新】虚拟 IP，旧地址残留在网卡上，
	// 系统选源地址可能挑到旧的那个，而服务端按"源地址必须等于本会话虚拟 IP"
	// 做防伪校验 → 上行包被全部丢弃。
	// 现象：认证成功、隧道建立、显示已连接，但一个包都上不去。
	//
	// Windows 的 Wintun 是持久设备（跨进程保留地址），所以这条是硬需求；
	// Linux 的 tun 虽随 fd 关闭消失，但**同一进程内重连**仍会积累旧地址，
	// 同样必须清。
	int clear_IPv4_addresses(const cfgstr& keepIpv4);

	bool set_MTU(uint32_t mtu);
	bool set_metric(uint8_t metric);
	bool set_DNS_IPv4(const cfgstr& dnsServer);

private:
	tun_id_t m_id;
};
