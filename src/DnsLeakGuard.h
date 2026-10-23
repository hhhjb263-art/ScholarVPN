#pragma once

#include "itun_device.h"        // tun_id_t
#include "platform/cfgstr.h"

#include <string>
#include <vector>

#if defined(_WIN32)
#include <winsock2.h>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// 不要在这里 include <netioapi.h>：
// 它由 DnsLeakGuard.cpp 的 <iphlpapi.h> 引入（那一步已经在 windows.h 之后），
// 本头文件只用 GUID/ULONG/DWORD，不直接依赖 NETIO_STATUS。
#else
#include <sys/types.h>
#endif

// ============================================================================
// 防 DNS 泄漏
//
// Windows：
//   连接时：禁用"智能多宿主名称解析"（注册表）+ 把非 TUN 网卡的 DNS 清成
//   黑洞 0.0.0.0（备份原值）+ 刷新解析缓存；断线恢复全部备份，并额外清理
//   崩溃残留的黑洞；派生 PowerShell 看门狗兜底。
//
// Linux：
//   连接时：优先 `resolvectl domain <if> '~.'`（把默认域绑到隧道网卡，
//   不碰 /etc/resolv.conf，也不与 NetworkManager 打架）；
//   没有 systemd-resolved 才回退"备份并改写 /etc/resolv.conf"，
//   并且要处理"resolv.conf 是符号链接"的情况（直接写会穿透到 stub 文件）。
//   断线恢复；看门狗用"pipe EOF"：父进程崩溃/被杀 → 子进程读到 EOF →
//   执行恢复命令（fork 前把命令拼好，子进程只 exec，避免多线程 fork 后
//   调用非 async-signal-safe 函数）。
// ============================================================================
class DnsLeakGuard
{
public:
    // dnsServers：Linux 用来配 per-link DNS（"8.8.8.8,1.1.1.1"）；
    // Windows 忽略（它的 DNS 由 AdapterConfig 设在 TUN 网卡上）
    bool protect(tun_id_t keepId, const cfgstr& dnsServers = cfgstr());
    // 恢复全部备份 + 清理崩溃残留（断开连接时调用，可重复调用）
    void restore();

private:
#if defined(_WIN32)
    // 派生分离的 PowerShell 看门狗：Wait-Process 盯住本进程，进程死后复位备份网卡的 DNS。
    // 覆盖崩溃/被任务管理器杀掉等 restore() 来不及执行的异常退出。
    void spawn_crash_watchdog();

    struct Backup
    {
        GUID guid{};           // 接口 GUID
        ULONG ifIndex = 0;     // 接口索引（看门狗 netsh/PowerShell 复位用，无编码问题）
        cfgstr ipv4Dns;        // 原 DNS 服务器串（wasDhcp=true 时为空）
        bool wasDhcp = false;  // true=原为 DHCP 自动获取 DNS，恢复时切回自动
    };
    std::vector<Backup> m_backup;

    // 注册表备份：DisableSmartNameResolution 键是否存在及原值
    bool m_policyKeyExisted = false;
    DWORD m_policyOldValue = 0;
#else
    void spawn_pipe_watchdog();          // 父进程死亡后由子进程执行恢复
    std::string build_restore_command() const;

    std::string m_ifname;
    bool m_active = false;
    bool m_useResolvectl = false;        // true = resolvectl 模式，false = resolv.conf 模式
    bool m_resolvWasSymlink = false;     // 原 /etc/resolv.conf 是否为符号链接
    std::string m_resolvTarget;          // 原符号链接目标
    bool m_hadResolvConf = false;        // 原本是否存在该文件
    std::string m_origResolvConf;        // 原文件内容
    pid_t m_watchdogPid = -1;
    int m_pipeWriteFd = -1;              // 父进程持有的管道写端（关闭 = 通知子进程）
#endif
};
