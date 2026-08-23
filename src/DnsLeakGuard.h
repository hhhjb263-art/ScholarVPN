#pragma once

#include <winsock2.h>
#include <windows.h>
#include <netioapi.h>

#include <string>
#include <vector>

// ============================================================================
// 防 DNS 泄漏：
//   连接时：
//     1. 禁用 Windows"智能多宿主名称解析"（默认会并行查询所有网卡的 DNS，
//        即使 TUN 网卡配了 8.8.8.8，物理网卡的运营商 DNS 也会被查询 → 泄漏），
//        写注册表 HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient
//        DisableSmartNameResolution=1（备份原值，断开时恢复）；
//     2. 备份并清空"非 TUN 网卡"（物理网卡等）的 IPv4/IPv6 DNS，
//        防止解析器回退到运营商/本地 DNS（查询明文走局域网，被审查/记录）；
//     3. 重启 DNS Client 服务 + 刷新解析缓存，让配置立即生效。
//   断开时恢复全部备份，保证断线后网络正常。
// ============================================================================
class DnsLeakGuard
{
public:
    // 备份除 keepLuid（TUN 网卡）之外所有活跃接口的 DNS 并清空，同时禁用多宿主解析
    bool protect(NET_LUID keepLuid);
    // 恢复全部备份的 DNS + 恢复多宿主解析设置（断开连接时调用）
    void restore();

private:
    struct Backup
    {
        GUID guid{};           // 接口 GUID
        std::wstring ipv4Dns;  // 备份的 DNS 服务器串（空格分隔，含 IPv4/IPv6）
    };
    std::vector<Backup> m_backup;

    // 注册表备份：DisableSmartNameResolution 键是否存在及原值
    bool m_policyKeyExisted = false;
    DWORD m_policyOldValue = 0;
};
