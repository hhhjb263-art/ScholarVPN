#include "DnsLeakGuard.h"

#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "advapi32.lib")

namespace {

// 禁用"智能多宿主名称解析"的注册表键（组策略路径，键不存在时需创建）
const wchar_t* kPolicyKey = L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient";
const wchar_t* kPolicyValue = L"DisableSmartNameResolution";

// 黑洞 DNS 地址：设置为静态 DNS 后查询会快速失败，且不会被 DHCP 回填覆盖
const wchar_t* kBlackHoleDns = L"0.0.0.0";

// 刷新 DNS 解析缓存（等价 ipconfig /flushdns）
// 注意：dnsapi.dll 的 DnsFlushResolverCache 是非公开导出，不能保证所有 Windows 都有，
// 不能用 extern 声明 + 静态链接（旧系统加载 dnsapi 缺导出会崩）；
// 改为 LoadLibrary/GetProcAddress 动态获取，拿不到就静默跳过。
// 另外：SetInterfaceDnsSettings 本身会通知 DNS Client 立即生效，
// 不需要重启 dnscache 系统服务（重启会让全系统 DNS 闪断，属高风险操作）。
void flush_dns_cache()
{
    typedef BOOL(WINAPI* DnsFlushResolverCacheFn)(void);
    static DnsFlushResolverCacheFn fn = []() -> DnsFlushResolverCacheFn {
        HMODULE h = ::LoadLibraryW(L"dnsapi.dll");
        if (!h)
            return nullptr;
        return reinterpret_cast<DnsFlushResolverCacheFn>(
            reinterpret_cast<void*>(::GetProcAddress(h, "DnsFlushResolverCache")));
    }();
    if (fn)
        fn();
}

} // namespace

// 备份并清空非 TUN 接口的 DNS + 禁用多宿主解析（防回退到运营商/本地 DNS）
bool DnsLeakGuard::protect(NET_LUID keepLuid)
{
    restore();   // 清理上一次的状态（防重复调用 / 崩溃残留）

    bool ok = true;

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
        if (::RegSetValueExW(key, kPolicyValue, 0, REG_DWORD,
                             reinterpret_cast<const BYTE*>(&v), sizeof(v)) != ERROR_SUCCESS)
            ok = false;
        ::RegCloseKey(key);
    }
    else
    {
        ok = false;   // 没权限写入组策略键（多半没以管理员运行）
    }

    //    注意：物理网卡往往是 DHCP（DNS 由 DHCP/路由器下发），
    //    GetInterfaceDnsSettings 对这种网卡返回的 NameServer 可能为空，
    //    因此不能"读不到就跳过"——统一设置为黑洞地址 0.0.0.0（静态覆盖 DHCP），
    //    查询会快速失败而不是泄漏。
    //     同时：无论读到没读到原 DNS，**每个接口都要进备份列表**——
    //    - 读到原值：restore 时写回；
    //    - 读不到（DHCP 自动）：wasDhcp=true，restore 时以 Flags=0（不设 NAMESERVER）
    //      切回 DHCP 自动获取。否则黑洞 0.0.0.0 会把网卡永久切成静态模式，
    //      断开后 DNS 永远恢复不了（电脑断网）——这是高危缺陷。
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
        bool gotSettings = false;
        if (GetInterfaceDnsSettings(g, &cur) == NO_ERROR)
        {
            gotSettings = true;
            if (cur.NameServer)
                dns = cur.NameServer;
            FreeInterfaceDnsSettings(&cur);
        }

        Backup bk;
        bk.guid = g;
        bk.ipv4Dns = dns;
        if (gotSettings)
        {
            // 读取成功：NameServer 为空 = 原本 DHCP 自动获取（wasDhcp=true，恢复时切回自动）；
            // 非空 = 原本静态 DNS（恢复时写回原串）。
            bk.wasDhcp = dns.empty();
        }
        else
        {
            // 读取失败：不知道真实配置，保守按"静态 DNS"处理（wasDhcp=false），
            // 恢复时把当前值原样写回（此刻 ipv4Dns 为空 → 恢复为空 = 不变更），
            // 绝不能误判成 DHCP——否则会把用户原本手配的静态 DNS 清成自动。
            bk.wasDhcp = false;
        }
        m_backup.push_back(std::move(bk));

        // 强制设置黑洞地址
        DNS_INTERFACE_SETTINGS bh{};
        bh.Version = DNS_INTERFACE_SETTINGS_VERSION1;
        bh.Flags = DNS_SETTING_NAMESERVER;
        bh.NameServer = const_cast<PWSTR>(kBlackHoleDns);
        if (SetInterfaceDnsSettings(g, &bh) != NO_ERROR)
            ok = false;   // 设置失败（权限/网卡被占用），上层需记日志
    }

    // 刷新 DNS 解析缓存让配置立即生效
    flush_dns_cache();

    return ok;
}

// 恢复全部备份的 DNS + 恢复多宿主解析设置 + 清理崩溃残留的黑洞
void DnsLeakGuard::restore()
{
    {
        ULONG size = 0;
        GetAdaptersAddresses(AF_UNSPEC,
                             GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                             nullptr, nullptr, &size);
        if (size != 0)
        {
            std::vector<BYTE> buf(size);
            auto* adapters = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());
            if (GetAdaptersAddresses(AF_UNSPEC,
                                     GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                                     nullptr, adapters, &size) == NO_ERROR)
            {
                for (auto* a = adapters; a; a = a->Next)
                {
                    if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK)
                        continue;
                    if (a->OperStatus != IfOperStatusUp)
                        continue;
                    GUID g{};
                    if (ConvertInterfaceLuidToGuid(&a->Luid, &g) != NO_ERROR)
                        continue;
                    DNS_INTERFACE_SETTINGS cur{};
                    cur.Version = DNS_INTERFACE_SETTINGS_VERSION1;
                    if (GetInterfaceDnsSettings(g, &cur) != NO_ERROR)
                        continue;
                    bool isBlackHole = cur.NameServer &&
                                       wcscmp(cur.NameServer, kBlackHoleDns) == 0;
                    FreeInterfaceDnsSettings(&cur);
                    if (!isBlackHole)
                        continue;
                    // 黑洞 -> 清除静态 DNS，切回 DHCP 自动获取。
                    //   关键：必须 Flags=DNS_SETTING_NAMESERVER + NameServer=L""（空串=清除）。
                    //    若写 Flags=0 + NameServer=nullptr，语义是"本次不修改任何设置"，
                    //    黑洞会原样保留，DHCP 网卡永久失真（断线后 DNS 不恢复）——高危缺陷。
                    DNS_INTERFACE_SETTINGS reset{};
                    reset.Version = DNS_INTERFACE_SETTINGS_VERSION1;
                    reset.Flags = DNS_SETTING_NAMESERVER;      // 声明要修改 NAMESERVER 字段
                    reset.NameServer = const_cast<PWSTR>(L""); // 空串 = 清除静态 DNS → 回退 DHCP 自动
                    SetInterfaceDnsSettings(g, &reset);
                }
            }
        }
    }

    for (const auto& bk : m_backup)
    {
        DNS_INTERFACE_SETTINGS s{};
        s.Version = DNS_INTERFACE_SETTINGS_VERSION1;
        if (bk.wasDhcp)
        {

            s.Flags = DNS_SETTING_NAMESERVER;
            s.NameServer = const_cast<PWSTR>(L"");
        }
        else
        {
            s.Flags = DNS_SETTING_NAMESERVER;
            s.NameServer = const_cast<PWSTR>(bk.ipv4Dns.c_str());
        }
        SetInterfaceDnsSettings(bk.guid, &s);
    }
    m_backup.clear();

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

    flush_dns_cache();
}