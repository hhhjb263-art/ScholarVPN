#pragma once
#include<iphlpapi.h>
#include<Windows.h>
#include<string>
#include "tun_macro.h"


// Wintun网卡IP/网络参数配置类，用来给虚拟网卡设置地址、MTU、DNS、跃点等
class AdapterConfig{
public:
	explicit AdapterConfig(NET_LUID interfaceLuid);
	AdapterConfig& operator=(const AdapterConfig&) = delete;
	AdapterConfig(const AdapterConfig&) = delete;

	bool set_IPv4_address(const std::wstring &ipAddress, uint8_t prefixLenth);
	bool remove_IPv4_address(const std::wstring &ipAddress, uint8_t prefixLenth);
	// 清掉本网卡上【除 keepIpv4 之外】的全部 IPv4 地址，返回删除成功的个数
	// （keepIpv4 为空 = 全清）。
	//
	// 为什么必须有这个：Wintun 适配器是【持久设备】，它的地址不随进程退出而消失，
	// 而 remove_IPv4_address 只能删"LUID+前缀+地址完全匹配"的那一条。历次运行若被
	// 分配到不同的虚拟 IP，网卡上就会残留多个地址，Windows 选源地址时可能挑到旧的那个，
	// 而服务端按"源地址必须等于本会话分配的虚拟 IP"做防伪校验 → 上行包被全部丢弃。
	// 现象：认证成功、隧道建立、显示已连接，但一个包都上不去。
	//
	// 传 keepIpv4 = 本次要用的地址：若它已在网卡上则不做任何删除（不退掉再重加，
	// 避免"删了加不回来"的窗口），只清掉其它残留地址。
	int clear_IPv4_addresses(const std::wstring& keepIpv4);
	bool set_MTU(uint32_t mtu); //1420
	bool set_metric(uint8_t metric);
	bool set_DNS_IPv4(const std::wstring &dnsServer);

private:
	NET_LUID m_interfaceLuid{};
};

