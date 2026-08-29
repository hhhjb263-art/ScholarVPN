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
//     2. 备份并清空"非 TUN 网卡"（物理网卡等）的 DNS：
//        - 原静态 DNS：备份原串，断开时写回；
//        - 原 DHCP 自动（读出的 NameServer 为空）：也要入备份并标记 wasDhcp=true，
//          断开时用 Flags=0（不设 NAMESERVER）切回 DHCP 自动获取——否则黑洞
//          0.0.0.0 会把网卡切成静态模式，断开后永远恢复不了，电脑断 DNS（高危）；
//     3. 刷新解析缓存（动态加载 dnsapi，找不到导出也不崩溃），让配置立即生效；
//        **绝不重启 dnscache 系统服务**（全系统 DNS 闪断，属高风险）。
//   断开时：
//     恢复全部备份（DHCP 网卡切回自动、静态网卡写回原串），并额外清理
//     残留黑洞（NameServer 仍为 0.0.0.0 的接口）——覆盖程序崩溃/被杀后的残留。
// ============================================================================
class DnsLeakGuard
{
public:
    // 备份除 keepLuid（TUN 网卡）之外所有活跃接口的 DNS 并清空，同时禁用多宿主解析；
    // 成功后派生"崩溃看门狗"进程：本进程退出（含崩溃）时自动复位所有被改的网卡 DNS
    // 返回 false 表示至少一个关键步骤失败（注册表写不进去等），上层需记日志
    bool protect(NET_LUID keepLuid);
    // 恢复全部备份的 DNS + 恢复多宿主解析设置 + 清理残留黑洞（断开连接时调用）
    void restore();

private:
    // 派生分离的 PowerShell 看门狗：Wait-Process 盯住本进程，进程死后复位备份网卡的 DNS。
    // 覆盖崩溃/被任务管理器杀掉等 restore() 来不及执行的异常退出。
    void spawn_crash_watchdog();

    struct Backup
    {
        GUID guid{};           // 接口 GUID
        ULONG ifIndex = 0;     // 接口索引（看门狗 netsh/PowerShell 复位用，无编码问题）
        std::wstring ipv4Dns;  // 原 DNS 服务器串（wasDhcp=true 时为空）
        bool wasDhcp = false;  // true=原为 DHCP 自动获取 DNS，恢复时切回自动
    };
    std::vector<Backup> m_backup;

    // 注册表备份：DisableSmartNameResolution 键是否存在及原值
    bool m_policyKeyExisted = false;
    DWORD m_policyOldValue = 0;
};