#if defined(_WIN32)

#define NTDDI_VERSION NTDDI_WIN10
#define _WIN32_WINNT _WIN32_WINNT_WIN10

#include <winsock2.h>
#include <ws2tcpip.h>
#include "AdapterConfig.h"
#include <icmpapi.h>
#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Iphlpapi.lib")

namespace {
	bool parse(const cfgstr& text, IN_ADDR* output) {
		*output = {};
		 const int  result = ::InetPtonW(AF_INET,text.c_str(),output);
		 // 1 = 转换成功
		 // 0 = 格式错误
		 // <0 = 系统错误
		 return result == 1;
	}
}

AdapterConfig::AdapterConfig(tun_id_t interfaceId) : m_id(interfaceId) {

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
bool AdapterConfig::set_IPv4_address(const cfgstr& ipAddress, uint8_t prefixLength)
{
	if (m_id.Value == 0 || ipAddress.empty() || prefixLength > 32) {
		LOG_ERROR("set_IPv4_address failed");
		return false;
	}
    // https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_unicastipaddress_row
    MIB_UNICASTIPADDRESS_ROW row{};
    ::InitializeUnicastIpAddressEntry(&row);

    row.InterfaceLuid = m_id;
    row.OnLinkPrefixLength = prefixLength;

    row.Address.Ipv4.sin_family = AF_INET;;
    if (!parse(ipAddress, &(row.Address.Ipv4.sin_addr))) {
        LOG_ERROR("set_IPv4_address: parse ip failed %s", cfg_to_utf8(ipAddress).c_str());
        return false;
    }
    //手动配置ip
    row.PrefixOrigin = IpPrefixOriginManual;
    row.SuffixOrigin = IpSuffixOriginManual;

    const NETIO_STATUS  status = CreateUnicastIpAddressEntry(&row);
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

bool AdapterConfig::remove_IPv4_address(const cfgstr& ipAdress, uint8_t prefixLenth) {
    DWORD err = GetLastError();
    if (m_id.Value == 0 || ipAdress.empty() || prefixLenth > 32) {
        LOG_ERROR("remove_IPv4_address failed , err = %lu",err);
        return false;
    }
    MIB_UNICASTIPADDRESS_ROW row{};
    ::InitializeUnicastIpAddressEntry(&row);
    row.InterfaceLuid = m_id;
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
 */
int AdapterConfig::clear_IPv4_addresses(const cfgstr& keepIpv4)
{
    if (m_id.Value == 0) {
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
        if (row.InterfaceLuid.Value != m_id.Value)
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
    if (m_id.Value == 0 || mtu < 576 || mtu > 1500)
    {
        LOG_ERROR("set_MTU invalid mtu=%u", mtu);
        return false;
    }
    ULONG ifIndex = 0;
    NETIO_STATUS status =
        ConvertInterfaceLuidToIndex(&m_id, &ifIndex);
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
    if (m_id.Value == 0)
    {
        LOG_ERROR("set_metric invalid LUID");
        return false;
    }
    ULONG ifIndex = 0;
    NETIO_STATUS status =
        ConvertInterfaceLuidToIndex(
            &m_id,
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

bool AdapterConfig::set_DNS_IPv4(const cfgstr& dnsServers)
{
    if (m_id.Value == 0) {
        ::SetLastError(ERROR_INVALID_PARAMETER);
        LOG_ERROR("set_DNS_IPv4 : m_id not found  -> ERROR_INVALID_PARAMETER");
        return false;
    }
    GUID interfaceGuid{};
    NETIO_STATUS status = ::ConvertInterfaceLuidToGuid(&m_id,&interfaceGuid);
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

#else // ---------------------------- Linux ----------------------------

#include "AdapterConfig.h"
#include "platform/exec.h"

#include <arpa/inet.h>
#include <cctype>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/if.h>

namespace {

bool valid_ipv4(const std::string& ip)
{
    struct in_addr a{};
    return ::inet_pton(AF_INET, ip.c_str(), &a) == 1;
}

// 接口名只允许 [A-Za-z0-9._-]：这些字符串会被拼进 shell 命令，
// 不校验就等于把 config.ini 的写权限升级成 root 命令执行
bool safe_ifname(const std::string& name)
{
    if (name.empty() || name.size() >= IFNAMSIZ)
    {
        return false;
    }
    for (char c : name)
    {
        const unsigned char u = static_cast<unsigned char>(c);
        if (!(std::isalnum(u) || c == '.' || c == '_' || c == '-'))
        {
            return false;
        }
    }
    return true;
}

std::string q(const std::string& s)
{
    return "'" + s + "'";   // 单引号包裹（配合上面的白名单，双保险）
}

// 网卡上是否已有该地址
bool addr_exists(const std::string& ifname, const std::string& ip)
{
    const std::string out = [] (const std::string& cmd) {
        std::string o;
        run_cmd(cmd, &o);
        return o;
    }("ip -4 -o addr show dev " + q(ifname));
    return out.find(" " + ip + "/") != std::string::npos;
}

} // namespace

AdapterConfig::AdapterConfig(tun_id_t interfaceId) : m_id(std::move(interfaceId))
{
    if (!safe_ifname(m_id))
    {
        LOG_ERROR("AdapterConfig: 非法接口名（拒绝拼命令）");
        return;
    }
    // Linux 的 tun 设备创建后默认是 down：必须先 up，之后设地址/路由才生效。
    // 放在构造函数里，是因为 ClientApp 的初始化顺序固定为"建 tun -> 建 AdapterConfig"。
    const std::string cmd = "ip link set dev " + q(m_id) + " up";
    if (run_cmd(cmd) != 0)
    {
        LOG_WARN("AdapterConfig: `%s` 失败（缺 CAP_NET_ADMIN？）", cmd.c_str());
    }
}

bool AdapterConfig::set_IPv4_address(const cfgstr& ipAddress, uint8_t prefixLength)
{
    if (!safe_ifname(m_id) || ipAddress.empty() || prefixLength > 32 || !valid_ipv4(ipAddress))
    {
        LOG_ERROR("set_IPv4_address: 参数非法 ip=%s prefix=%u",
                  ipAddress.c_str(), static_cast<unsigned>(prefixLength));
        return false;
    }
    const std::string cidr = ipAddress + "/" + std::to_string(static_cast<unsigned>(prefixLength));
    const std::string cmd = "ip addr add " + q(cidr) + " dev " + q(m_id);
    if (run_cmd(cmd) == 0)
    {
        LOG_INFO("set_IPv4_address: %s ok", cidr.c_str());
        return true;
    }
    // 已存在时 ip 返回非 0（RTNETLINK answers: File exists）。
    // 幂等：地址已经在网卡上就算成功，不要因此判定整次连接失败。
    if (addr_exists(m_id, ipAddress))
    {
        LOG_INFO("set_IPv4_address: %s 已存在（幂等）", cidr.c_str());
        return true;
    }
    LOG_ERROR("set_IPv4_address: `%s` 失败", cmd.c_str());
    return false;
}

bool AdapterConfig::remove_IPv4_address(const cfgstr& ipAddress, uint8_t prefixLength)
{
    if (!safe_ifname(m_id) || ipAddress.empty() || prefixLength > 32 || !valid_ipv4(ipAddress))
    {
        return false;
    }
    const std::string cidr = ipAddress + "/" + std::to_string(static_cast<unsigned>(prefixLength));
    return run_cmd("ip addr del " + q(cidr) + " dev " + q(m_id)) == 0;
}

int AdapterConfig::clear_IPv4_addresses(const cfgstr& keepIpv4)
{
    if (!safe_ifname(m_id))
    {
        LOG_ERROR("clear_IPv4_addresses: 非法接口名");
        return 0;
    }
    // `ip -4 -o addr show dev vpn0` 输出形如：
    //   2: vpn0    inet 10.8.0.7/24 brd 10.8.0.255 scope global vpn0
    const std::vector<std::string> lines =
        run_cmd_lines("ip -4 -o addr show dev " + q(m_id));

    int removed = 0;
    for (const auto& line : lines)
    {
        const std::string marker = " inet ";
        const std::size_t pos = line.find(marker);
        if (pos == std::string::npos)
        {
            continue;
        }
        const std::size_t begin = pos + marker.size();
        const std::size_t end = line.find_first_of(" \t", begin);
        const std::string cidr = line.substr(begin, end == std::string::npos ? std::string::npos : end - begin);
        const std::size_t slash = cidr.find('/');
        const std::string ip = (slash == std::string::npos) ? cidr : cidr.substr(0, slash);
        if (!keepIpv4.empty() && ip == keepIpv4)
        {
            continue;   // 本次要用的地址：保留
        }
        if (run_cmd("ip addr del " + q(cidr) + " dev " + q(m_id)) == 0)
        {
            ++removed;
        }
        else
        {
            LOG_ERROR("clear_IPv4_addresses: 删除 %s 失败", cidr.c_str());
        }
    }
    if (removed > 0)
    {
        LOG_INFO("clear_IPv4_addresses: 清理了 %d 个残留地址", removed);
    }
    return removed;
}

bool AdapterConfig::set_MTU(uint32_t mtu)
{
    if (!safe_ifname(m_id) || mtu < 576 || mtu > 1500)
    {
        LOG_ERROR("set_MTU invalid mtu=%u", mtu);
        return false;
    }
    const std::string cmd = "ip link set dev " + q(m_id) + " mtu " + std::to_string(mtu);
    if (run_cmd(cmd) != 0)
    {
        LOG_ERROR("set_MTU: `%s` 失败", cmd.c_str());
        return false;
    }
    LOG_INFO("Set MTU success dev=%s mtu=%u", m_id.c_str(), mtu);
    return true;
}

bool AdapterConfig::set_metric(uint8_t metric)
{
    // Linux 没有"网卡跃点"这个概念：metric 是路由属性，
    // 由 RouteManager 在添加 0.0.0.0/1、128.0.0.0/1 时通过 `ip route ... metric N` 指定。
    // 这里保持接口一致（ClientApp 不必 ifdef），仅记录一条调试日志。
    LOG_DEBUG("set_metric(%u): Linux 下由路由 metric 承担，跳过", static_cast<unsigned>(metric));
    return true;
}

bool AdapterConfig::set_DNS_IPv4(const cfgstr& dnsServer)
{
    if (!safe_ifname(m_id) || dnsServer.empty())
    {
        return false;
    }
    // "8.8.8.8,1.1.1.1" -> "8.8.8.8 1.1.1.1"，并逐个校验是合法 IPv4
    std::string servers = dnsServer;
    for (char& c : servers)
    {
        if (c == ',') c = ' ';
    }
    std::size_t i = 0;
    while (i < servers.size())
    {
        while (i < servers.size() && servers[i] == ' ') ++i;
        const std::size_t j = servers.find(' ', i);
        const std::string one = servers.substr(i, j == std::string::npos ? std::string::npos : j - i);
        if (!one.empty() && !valid_ipv4(one))
        {
            LOG_ERROR("set_DNS_IPv4: 非法 DNS 地址 %s", one.c_str());
            return false;
        }
        if (j == std::string::npos) break;
        i = j;
    }

    // per-interface DNS 只有 systemd-resolved 提供（resolvectl）。
    // 没有它也不致命：DnsLeakGuard 会在连接成功时按自己的策略处理（改写 resolv.conf）。
    const std::string cmd = "resolvectl dns " + q(m_id) + " " + servers;
    if (run_cmd(cmd) != 0)
    {
        LOG_WARN("set_DNS_IPv4: resolvectl 不可用（未启用 systemd-resolved），"
                 "DNS 交由 DnsLeakGuard 处理");
        return false;
    }
    return true;
}

#endif // _WIN32
