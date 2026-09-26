#define NTDDI_VERSION NTDDI_WIN10
#define _WIN32_WINNT _WIN32_WINNT_WIN10

#include <winsock2.h>
#include <ws2tcpip.h>
#include "AdapterConfig.h"
#include <icmpapi.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib") 

namespace {
	bool parse(const std::wstring& text, IN_ADDR* output) {
		*output = {};
		 const int  result = ::InetPtonW(AF_INET,text.c_str(),output);
		 // 1 = 转换成功
		 // 0 = 格式错误
		 // <0 = 系统错误
		 return result == 1;
	}
}
AdapterConfig::AdapterConfig(NET_LUID interfaceLuid): m_interfaceLuid(interfaceLuid) {

}
/*
 * @brief       为Wintun虚拟网卡配置静态IPv4单播地址
 * @param ipAddress    宽字符串IPv4地址（如 L"10.0.10.2"）
 * @param prefixLength  IPv4子网前缀长度（0~32，常用24=255.255.255.0）
 * @return      true=配置IP成功，false=参数非法/解析失败/系统配置失败
 *
 * 1. 基于网卡唯一LUID精准定位目标虚拟网卡，避免修改到物理网卡
 * 2. 将字符串IP转为系统内核识别的二进制网络序IP
 * 3. 填充网卡IP配置结构体，调用系统API写入静态IPv4地址
 */

bool AdapterConfig::set_IPv4_address(const std::wstring& ipAddress, uint8_t prefixLength)
{	
	if (m_interfaceLuid.Value == 0 || ipAddress.empty() || prefixLength > 32) {
		LOG_ERROR("set_IPv4_address failed");
		return false;
	}
    // https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_unicastipaddress_row
    MIB_UNICASTIPADDRESS_ROW row{};
    // Initialize to safe defaults if available
    ::InitializeUnicastIpAddressEntry(&row);

    // Fill required fields for IPv4
    row.InterfaceLuid = m_interfaceLuid;
    row.OnLinkPrefixLength = prefixLength;

    // Populate IPv4 socket address part
    row.Address.Ipv4.sin_family = AF_INET;;
    if (!parse(ipAddress, &(row.Address.Ipv4.sin_addr))) {
        LOG_ERROR("set_IPv4_address: parse ip failed %ls", ipAddress.c_str());
        return false;
    }
    //手动配置ip
    row.PrefixOrigin = IpPrefixOriginManual;
    row.SuffixOrigin = IpSuffixOriginManual;

    const NETIO_STATUS  status = CreateUnicastIpAddressEntry(&row); //指定网卡创建/写入静态IPv4单播地址
    if (status == NO_ERROR) {
        LOG_INFO("CreateUnicastIpAddressEntry success err=%lu", status);
        return true;
    }
    /*
        成功返回true
        存在也返回true
    */
    if (status == ERROR_OBJECT_ALREADY_EXISTS) {
        return true;
    }
    LOG_ERROR("CreateUnicastIpAddressEntry failed status=%lu", status);
    return false;
}
bool AdapterConfig::remove_IPv4_address(const std::wstring &ipAdress, uint8_t prefixLenth) {
    DWORD err = GetLastError();
    if (m_interfaceLuid.Value == 0 || ipAdress.empty() || prefixLenth > 32) {
        LOG_ERROR("remove_IPv4_address failed , err = %lu",err);
        return false;
    }
    MIB_UNICASTIPADDRESS_ROW row{};
    ::InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = m_interfaceLuid;
    row.OnLinkPrefixLength = prefixLenth;
    row.Address.Ipv4.sin_family = AF_INET;

    if (!parse(ipAdress, &row.Address.Ipv4.sin_addr)) {
        err = GetLastError();
        LOG_ERROR("remove_IPv4_address: parse ip failed , err = %lu", err);
        return false;
    }
    const NETIO_STATUS  status = ::DeleteUnicastIpAddressEntry(&row);
    if (status == NO_ERROR || status == ERROR_NOT_FOUND) {
        // 注意函数名：这里删地址，历史上错打成 "CreateUnicastIpAddressEntry success"，
        // 日志里"多出一条创建成功"是假象（曾据此误判网卡上有两个地址）
        LOG_INFO("DeleteUnicastIpAddressEntry success err=%lu", status);
        return true;
    }
    /*
        成功返回true
    */
    if (status == ERROR_OBJECT_ALREADY_EXISTS) {
        return true;
    }

    ::SetLastError(status);
    return false;
}

/*
 * @brief 清掉本网卡上【除 keepIpv4 之外】的全部 IPv4 地址，返回删除成功的个数
 *
 * Wintun 适配器是持久设备，地址跨进程保留：历次运行被分配到不同虚拟 IP 时网卡上会
 * 残留多个地址，Windows 选源地址可能挑到旧的那个，被服务端的源地址防伪校验全部丢弃
 * ——表现为"能连上但一个包都上不去"。因此采用服务端新分配的虚拟 IP 之前，先把本网卡
 * 的其它地址清掉。
 *
 * keepIpv4 = 本次要用的地址：已在网卡上就不删（不退掉再重加，避免"删了加不回来"的
 * 窗口）；只清其它残留。传空串 = 全清。
 * 实现：GetUnicastIpAddressTable 枚举本机全部 IPv4 单播地址，按 InterfaceLuid
 * 过滤出本网卡的，逐个 DeleteUnicastIpAddressEntry（绝不碰物理网卡）。
 */
int AdapterConfig::clear_IPv4_addresses(const std::wstring& keepIpv4)
{
    if (m_interfaceLuid.Value == 0) {
        LOG_ERROR("clear_IPv4_addresses: invalid interface LUID");
        return 0;
    }
    IN_ADDR keep{};
    const bool has_keep = !keepIpv4.empty() && parse(keepIpv4, &keep);
    PMIB_UNICASTIPADDRESS_TABLE table = nullptr;
    const NETIO_STATUS gst = ::GetUnicastIpAddressTable(AF_INET, &table);
    if (gst != NO_ERROR || table == nullptr) {
        LOG_ERROR("clear_IPv4_addresses: GetUnicastIpAddressTable failed, err = %lu", gst);
        return 0;
    }
    int removed = 0;
    for (ULONG i = 0; i < table->NumEntries; ++i) {
        MIB_UNICASTIPADDRESS_ROW& row = table->Table[i];
        if (row.InterfaceLuid.Value != m_interfaceLuid.Value)
            continue;   // 只动本虚拟网卡
        if (has_keep && row.Address.Ipv4.sin_addr.S_un.S_addr == keep.S_un.S_addr)
            continue;   // 本次要用的地址：保留
        const NETIO_STATUS dst = ::DeleteUnicastIpAddressEntry(&row);
        if (dst == NO_ERROR || dst == ERROR_NOT_FOUND) {
            ++removed;
        } else {
            LOG_ERROR("clear_IPv4_addresses: delete entry failed, err = %lu", dst);
        }
    }
    ::FreeMibTable(table);
    if (removed > 0) {
        LOG_INFO("clear_IPv4_addresses: removed %d stale address(es)", removed);
    }
    return removed;
}

bool AdapterConfig::set_MTU(uint32_t mtu)
{
    if (m_interfaceLuid.Value == 0 || mtu < 576 || mtu > 1500)
    {
        LOG_ERROR("set_MTU invalid mtu=%u", mtu);
        return false;
    }
    ULONG ifIndex = 0;
    NETIO_STATUS status =
        ConvertInterfaceLuidToIndex(&m_interfaceLuid, &ifIndex);
    if (status != NO_ERROR)
    {
        LOG_ERROR("ConvertInterfaceLuidToIndex failed %lu", status);
        return false;
    }
    wchar_t cmd[256]{};
    swprintf_s(
        cmd,
        L"netsh interface ipv4 set subinterface %lu mtu=%u store=persistent",
        ifIndex,
        mtu
    );
    int ret = _wsystem(cmd);
    if (ret != 0)
    {
        LOG_ERROR("netsh set mtu failed ret=%d", ret);
        return false;
    }
    LOG_INFO("Set MTU success ifIndex=%lu mtu=%u", ifIndex, mtu);
    return true;
}
bool AdapterConfig::set_metric(uint8_t metric)
{
    if (m_interfaceLuid.Value == 0)
    {
        LOG_ERROR("set_metric invalid LUID");
        return false;
    }
    ULONG ifIndex = 0;
    NETIO_STATUS status =
        ConvertInterfaceLuidToIndex(
            &m_interfaceLuid,
            &ifIndex
        );
    if (status != NO_ERROR)
    {
        LOG_ERROR(
            "ConvertInterfaceLuidToIndex failed %lu",
            status
        );
        return false;
    }
    wchar_t cmd[256]{};
    swprintf_s(
        cmd,
        L"netsh interface ipv4 set interface %lu metric=%u",
        ifIndex,
        metric
    );
    int ret = _wsystem(cmd);
    if (ret != 0)
    {
        LOG_ERROR(
            "set metric failed ret=%d",
            ret
        );
        return false;
    }
    LOG_INFO(
        "Set interface metric success ifIndex=%lu metric=%u",
        ifIndex,
        metric
    );
    return true;
}
bool AdapterConfig::set_DNS_IPv4(const std::wstring& dnsServers)
{
    if (m_interfaceLuid.Value == 0) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        LOG_ERROR("set_DNS_IPv4 : m_interfaceLuid not found  -> ERROR_INVALID_PARAMETER");
        return false;
    }
    GUID interfaceGuid{};
    NETIO_STATUS status = ::ConvertInterfaceLuidToGuid(&m_interfaceLuid,&interfaceGuid);
    if (status != NO_ERROR) {
        ::SetLastError(status);
        return false;
    }
    DNS_INTERFACE_SETTINGS settings{};
    settings.Version = DNS_INTERFACE_SETTINGS_VERSION1;
    settings.Flags = DNS_SETTING_NAMESERVER;

    settings.NameServer = const_cast<PWSTR> (dnsServers.c_str());
    /*
    * dnsServers.c_str() 返回 const wchar_t*
    * 结构体NameServer字段类型是 PWSTR (wchar_t*)，非const
    * 但官方文档说明：SetInterfaceDnsSettings 只会读取字符串，不会修改、不释放内存
    * 因此 const_cast 剥离const限定是安全合法操作，无内存越界风险
    */
    status = ::SetInterfaceDnsSettings(interfaceGuid, &settings);
    if (status != NO_ERROR) {
        ::SetLastError(status);
        return false;
    }
    return true;
}
