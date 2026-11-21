#pragma once

#include "itun_device.h"
#include "platform/cfgstr.h"

#include <string>
#include <vector>

#if defined(_WIN32)
#include <winsock2.h>
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <sys/types.h>
#endif

class DnsLeakGuard
{
public:
    bool protect(tun_id_t keepId, const cfgstr& dnsServers = cfgstr());
    void restore();

private:
#if defined(_WIN32)
    void spawn_crash_watchdog();

    struct Backup
    {
        GUID guid{};
        ULONG ifIndex = 0;
        cfgstr ipv4Dns;
        bool wasDhcp = false;
    };
    std::vector<Backup> m_backup;

    bool m_policyKeyExisted = false;
    DWORD m_policyOldValue = 0;
#else
    void spawn_pipe_watchdog();
    std::string build_restore_command() const;

    std::string m_ifname;
    bool m_active = false;
    bool m_useResolvectl = false;
    bool m_resolvWasSymlink = false;
    std::string m_resolvTarget;
    bool m_hadResolvConf = false;
    std::string m_origResolvConf;
    pid_t m_watchdogPid = -1;
    int m_pipeWriteFd = -1;
#endif
};
