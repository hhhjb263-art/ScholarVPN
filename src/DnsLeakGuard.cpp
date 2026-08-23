#include "DnsLeakGuard.h"

#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "advapi32.lib")

// dnsapi.dll 导出（无头文件，自行声明）
extern "C" BOOL WINAPI DnsFlushResolverCache(void);

namespace {

// DNS Client 服务名
const wchar_t* kDnsClientService = L"dnscache";

// 禁用"智能多宿主名称解析"的注册表键（组策略路径，键不存在时需创建）
const wchar_t* kPolicyKey = L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient";
const wchar_t* kPolicyValue = L"DisableSmartNameResolution";

// 黑洞 DNS 地址：设置为静态 DNS 后查询会快速失败，且不会被 DHCP 回填覆盖
const wchar_t* kBlackHoleDns = L"0.0.0.0";

// 刷新 DNS 解析缓存（等价 ipconfig /flushdns）
void flush_dns_cache()
{
    DnsFlushResolverCache();
}

// 重启 DNS Client 服务，让接口/注册表 DNS 配置立即生效
void restart_dns_client_service()
{
    SC_HANDLE scm = ::OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm)
        return;
    SC_HANDLE svc = ::OpenServiceW(scm, kDnsClientService,
                                   SERVICE_STOP | SERVICE_START | SERVICE_QUERY_STATUS);
    if (svc)
    {
        SERVICE_STATUS status{};
        ::ControlService(svc, SERVICE_CONTROL_STOP, &status);
        // 最多等 5 秒让服务停下来
        for (int i = 0; i < 50; ++i)
        {
            ::QueryServiceStatus(svc, &status);
            if (status.dwCurrentState == SERVICE_STOPPED)
                break;
            ::Sleep(100);
        }
        if (status.dwCurrentState == SERVICE_STOPPED)
            ::StartServiceW(svc, 0, nullptr);
        ::CloseServiceHandle(svc);
    }
    ::CloseServiceHandle(scm);
}

} // namespace

// 备份并清空非 TUN 接口的 DNS + 禁用多宿主解析（防回退到运营商/本地 DNS）
bool DnsLeakGuard::protect(NET_LUID keepLuid)
{
    restore();   // 清理上一次的状态（防重复调用）

    // 1) 禁用"智能多宿主名称解析"：
    //    Windows 默认会同时向所有网卡配置的 DNS 服务器发查询（多宿主解析），
    //    即使 TUN 网卡设置了 8.8.8.8，物理网卡残留的运营商 DNS 仍会被查询 → 泄漏。
    //    写入组策略键 DisableSmartNameResolution=1，断开时恢复。
    //    注意：该键在未配置过组策略的系统上不存在，必须用 RegCreateKeyExW 创建，
    //    RegOpenKeyExW 打开不存在的键会失败，导致静默写不进去。
    HKEY key = nullptr;
    DWORD disp = 0;
    if (::RegCreateKeyExW(HKEY_LOCAL_MACHINE, kPolicyKey, 0, nullptr, 0,
                          KEY_READ | KEY_SET_VALUE, nullptr, &key, &disp) == ERROR_SUCCESS)
    {
        DWORD type = 0, size = sizeof(DWORD);
        m_policyKeyExisted =
            (::RegQueryValueExW(key, kPolicyValue, nullptr, &type,
                                reinterpret_cast<BYTE*>(&m_policyOldValue), &size) == ERROR_SUCCESS);
        DWORD v = 1;
        ::RegSetValueExW(key, kPolicyValue, 0, REG_DWORD, reinterpret_cast<const BYTE*>(&v), sizeof(v));
        ::RegCloseKey(key);
    }

    // 2) 清空物理网卡 DNS：
    //    注意：物理网卡往往是 DHCP（DNS 由 DHCP/路由器下发），
    //    GetInterfaceDnsSettings 对这种网卡返回的 NameServer 可能为空，
    //    因此不能"读不到就跳过"——统一设置为黑洞地址 0.0.0.0（静态覆盖 DHCP），
    //    查询会快速失败而不是泄漏。
    ULONG size = 0;
    GetAdaptersAddresses(AF_UNSPEC,
                         GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                         nullptr, nullptr, &size);
    if (size == 0)
        return false;
    std::vector<BYTE> buf(size);
    auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
    if (GetAdaptersAddresses(AF_UNSPEC,
                             GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                             nullptr, adapters, &size) != NO_ERROR)
        return false;

    for (auto* a = adapters; a; a = a->Next)
    {
        if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
            continue;
        if (a->OperStatus != IfOperStatusUp)
            continue;
        if (a->Luid.Value == keepLuid.Value)
            continue;   // 跳过 TUN 网卡（它的 DNS 由 set_DNS_IPv4 管理）

        GUID g{};
        if (ConvertInterfaceLuidToGuid(&a->Luid, &g) != NO_ERROR)
            continue;

        // 读取该接口当前 DNS（SDK 10.0.26100+：传 GUID 值 + 调用方提供的结构体，先设 Version）
        DNS_INTERFACE_SETTINGS cur{};
        cur.Version = DNS_INTERFACE_SETTINGS_VERSION1;
        std::wstring dns;
        if (GetInterfaceDnsSettings(g, &cur) == NO_ERROR)
        {
            if (cur.NameServer)
                dns = cur.NameServer;
            FreeInterfaceDnsSettings(&cur);
        }

        // 有原值才需要备份（断开时恢复）；无原值（如 DHCP 自动）断开时清空即可回 DHCP
        if (!dns.empty())
        {
            Backup bk;
            bk.guid = g;
            bk.ipv4Dns = dns;
            m_backup.push_back(std::move(bk));
        }

        // 强制设置黑洞地址（静态覆盖 DHCP，防泄漏且防回填）
        DNS_INTERFACE_SETTINGS bh{};
        bh.Version = DNS_INTERFACE_SETTINGS_VERSION1;
        bh.Flags = DNS_SETTING_NAMESERVER;
        bh.NameServer = const_cast<PWSTR>(kBlackHoleDns);
        SetInterfaceDnsSettings(g, &bh);
    }

    // 3) 让配置立即生效
    restart_dns_client_service();
    flush_dns_cache();

    return true;
}

// 恢复全部备份的 DNS + 恢复多宿主解析设置
void DnsLeakGuard::restore()
{
    for (const auto& bk : m_backup)
    {
        DNS_INTERFACE_SETTINGS s{};
        s.Version = DNS_INTERFACE_SETTINGS_VERSION1;
        s.Flags = DNS_SETTING_NAMESERVER;
        s.NameServer = const_cast<PWSTR>(bk.ipv4Dns.c_str());
        SetInterfaceDnsSettings(bk.guid, &s);
    }
    m_backup.clear();

    // 恢复多宿主解析策略
    if (m_policyKeyExisted)
    {
        HKEY key = nullptr;
        if (::RegOpenKeyExW(HKEY_LOCAL_MACHINE, kPolicyKey, 0, KEY_SET_VALUE, &key) == ERROR_SUCCESS)
        {
            ::RegSetValueExW(key, kPolicyValue, 0, REG_DWORD,
                             reinterpret_cast<const BYTE*>(&m_policyOldValue), sizeof(m_policyOldValue));
            ::RegCloseKey(key);
        }
    }
    else
    {
        ::RegDeleteKeyValueW(HKEY_LOCAL_MACHINE, kPolicyKey, kPolicyValue);
    }
    m_policyKeyExisted = false;

    restart_dns_client_service();
    flush_dns_cache();
}
