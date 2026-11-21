#include "DnsLeakGuard.h"

#if defined(_WIN32)

#include <iphlpapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "advapi32.lib")

namespace {

const wchar_t* kPolicyKey = L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient";
const wchar_t* kPolicyValue = L"DisableSmartNameResolution";

const wchar_t* kBlackHoleDns = L"0.0.0.0";

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

}

// 隧道建立后锁定各网卡 DNS，防止查询绕过隧道泄漏真实出口
bool DnsLeakGuard::protect(tun_id_t keepId, const cfgstr&)
{
    restore();

    bool ok = true;

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
        ok = false;
    }

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
        if (a->Luid.Value == keepId.Value)
            continue;

        GUID g{};
        if (ConvertInterfaceLuidToGuid(&a->Luid, &g) != NO_ERROR)
            continue;

        DNS_INTERFACE_SETTINGS cur{};
        cur.Version = DNS_INTERFACE_SETTINGS_VERSION1;
        cfgstr dns;
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
        bk.ifIndex = a->IfIndex;
        bk.ipv4Dns = dns;
        if (gotSettings)
        {
            bk.wasDhcp = dns.empty();
        }
        else
        {
            bk.wasDhcp = false;
        }
        m_backup.push_back(std::move(bk));

        DNS_INTERFACE_SETTINGS bh{};
        bh.Version = DNS_INTERFACE_SETTINGS_VERSION1;
        bh.Flags = DNS_SETTING_NAMESERVER;
        bh.NameServer = const_cast<PWSTR>(kBlackHoleDns);
        if (SetInterfaceDnsSettings(g, &bh) != NO_ERROR)
            ok = false;
    }

    flush_dns_cache();

    spawn_crash_watchdog();

    return ok;
}

void DnsLeakGuard::spawn_crash_watchdog()
{
    if (m_backup.empty())
        return;

    auto trim = [](const cfgstr& s) {
        const size_t b = s.find_first_not_of(L" \t");
        if (b == cfgstr::npos)
            return cfgstr();
        const size_t e = s.find_last_not_of(L" \t");
        return s.substr(b, e - b + 1);
    };

    cfgstr cmd =
        L"powershell.exe -NoProfile -WindowStyle Hidden -Command \""
        L"Wait-Process -Id " + std::to_wstring(::GetCurrentProcessId()) +
        L" -ErrorAction SilentlyContinue;";

    for (const auto& bk : m_backup)
    {
        if (bk.wasDhcp)
        {
            cmd += L" Set-DnsClientServerAddress -InterfaceIndex "
                 + std::to_wstring(bk.ifIndex) + L" -ResetServerAddresses;";
        }
        else if (!bk.ipv4Dns.empty())
        {
            cmd += L" Set-DnsClientServerAddress -InterfaceIndex "
                 + std::to_wstring(bk.ifIndex) + L" -ServerAddresses";
            const cfgstr dns = bk.ipv4Dns;
            size_t pos = 0;
            bool first = true;
            while (pos < dns.size())
            {
                size_t comma = dns.find(L',', pos);
                if (comma == cfgstr::npos)
                    comma = dns.size();
                const cfgstr item = trim(dns.substr(pos, comma - pos));
                pos = comma + 1;
                if (item.empty())
                    continue;
                cmd += (first ? L" '" : L",'") + item + L"'";
                first = false;
            }
            cmd += L";";
        }
    }
    cmd += L"\"";

    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (::CreateProcessW(nullptr, cmd.data(), nullptr, nullptr, FALSE,
                         CREATE_NO_WINDOW | DETACHED_PROCESS, nullptr, nullptr, &si, &pi))
    {
        ::CloseHandle(pi.hThread);
        ::CloseHandle(pi.hProcess);
    }
}

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
                    DNS_INTERFACE_SETTINGS reset{};
                    reset.Version = DNS_INTERFACE_SETTINGS_VERSION1;
                    reset.Flags = DNS_SETTING_NAMESERVER;
                    reset.NameServer = const_cast<PWSTR>(L"");
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

#else

#include "platform/exec.h"

#include <cctype>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace {

const char* kResolvConf = "/etc/resolv.conf";

bool safe_ifname(const std::string& name)
{
    if (name.empty() || name.size() >= 16)
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

std::string read_file(const char* path, bool* ok)
{
    std::string out;
    FILE* f = std::fopen(path, "rb");
    if (f == nullptr)
    {
        if (ok) *ok = false;
        return out;
    }
    char buf[1024];
    std::size_t n = 0;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0)
    {
        out.append(buf, n);
    }
    std::fclose(f);
    if (ok) *ok = true;
    return out;
}

bool write_file_atomic(const char* path, const std::string& data)
{
    const std::string tmp = std::string(path) + ".scholarvpn.tmp";
    FILE* f = std::fopen(tmp.c_str(), "wb");
    if (f == nullptr)
    {
        return false;
    }
    const bool ok = std::fwrite(data.data(), 1, data.size(), f) == data.size();
    std::fclose(f);
    if (!ok)
    {
        std::remove(tmp.c_str());
        return false;
    }
    return std::rename(tmp.c_str(), path) == 0;
}

bool has_resolvectl()
{
    return run_cmd("command -v resolvectl >/dev/null 2>&1") == 0;
}

std::string dns_list(const std::string& csv)
{
    std::string out;
    std::string cur;
    auto flush = [&]() {
        const std::size_t b = cur.find_first_not_of(" \t");
        const std::size_t e = cur.find_last_not_of(" \t");
        if (b != std::string::npos)
        {
            if (!out.empty()) out += ' ';
            out += cur.substr(b, e - b + 1);
        }
        cur.clear();
    };
    for (char c : csv)
    {
        if (c == ',') flush();
        else cur.push_back(c);
    }
    flush();
    return out;
}

std::string sh_quote(const std::string& s)
{
    std::string out = "'";
    for (char c : s)
    {
        if (c == '\'') out += "'\\''";
        else out.push_back(c);
    }
    out += "'";
    return out;
}

}

std::string DnsLeakGuard::build_restore_command() const
{
    if (m_useResolvectl)
    {
        return "resolvectl revert " + sh_quote(m_ifname) + " 2>/dev/null; "
               "resolvectl flush-caches 2>/dev/null; true";
    }
    if (m_resolvWasSymlink)
    {
        return "ln -sfn " + sh_quote(m_resolvTarget) + " " + kResolvConf;
    }
    if (m_hadResolvConf)
    {
        return "printf '%s' " + sh_quote(m_origResolvConf) + " > " + kResolvConf;
    }
    return "rm -f " + std::string(kResolvConf);
}

bool DnsLeakGuard::protect(tun_id_t keepId, const cfgstr& dnsServers)
{
    restore();

    if (!safe_ifname(keepId))
    {
        LOG_ERROR("DnsLeakGuard: 非法接口名");
        return false;
    }
    m_ifname = keepId;
    const std::string servers = dns_list(dnsServers);

    if (has_resolvectl())
    {
        if (!servers.empty())
        {
            run_cmd("resolvectl dns " + sh_quote(m_ifname) + " " + servers);
        }
        const int rc = run_cmd("resolvectl domain " + sh_quote(m_ifname) + " '~.'");
        run_cmd("resolvectl flush-caches");
        if (rc == 0)
        {
            m_useResolvectl = true;
            m_active = true;
            spawn_pipe_watchdog();
            LOG_INFO("DNS 防泄漏: 默认域已绑定到 %s（systemd-resolved）", m_ifname.c_str());
            return true;
        }
        LOG_WARN("DnsLeakGuard: resolvectl domain 失败，回退到改写 resolv.conf");
    }

    if (servers.empty())
    {
        LOG_ERROR("DnsLeakGuard: 未配置 DNS，拒绝改写 resolv.conf（会把系统 DNS 弄空）");
        return false;
    }
    struct stat st{};
    if (::lstat(kResolvConf, &st) == 0 && S_ISLNK(st.st_mode))
    {
        m_resolvWasSymlink = true;
        char buf[4096]{};
        const ssize_t n = ::readlink(kResolvConf, buf, sizeof(buf) - 1);
        if (n > 0)
        {
            m_resolvTarget.assign(buf, static_cast<std::size_t>(n));
        }
    }
    bool existed = false;
    m_origResolvConf = read_file(kResolvConf, &existed);
    m_hadResolvConf = existed;

    std::string content;
    {
        std::string cur;
        for (char c : servers + " ")
        {
            if (c == ' ')
            {
                if (!cur.empty())
                {
                    content += "nameserver " + cur + "\n";
                    cur.clear();
                }
            }
            else
            {
                cur.push_back(c);
            }
        }
    }
    content += "# generated by ScholarVPN while connected; restored on disconnect\n";

    if (m_resolvWasSymlink && ::unlink(kResolvConf) != 0)
    {
        LOG_ERROR("DnsLeakGuard: 删除 resolv.conf 符号链接失败: %s", std::strerror(errno));
        return false;
    }
    if (!write_file_atomic(kResolvConf, content))
    {
        LOG_ERROR("DnsLeakGuard: 写入 resolv.conf 失败（需要 root）");
        return false;
    }
    m_useResolvectl = false;
    m_active = true;
    spawn_pipe_watchdog();
    LOG_INFO("DNS 防泄漏: resolv.conf 已指向 %s", servers.c_str());
    return true;
}

void DnsLeakGuard::restore()
{
    if (!m_active)
    {
        return;
    }
    if (m_useResolvectl)
    {
        run_cmd("resolvectl revert " + sh_quote(m_ifname));
        run_cmd("resolvectl flush-caches");
    }
    else if (m_resolvWasSymlink)
    {
        ::unlink(kResolvConf);
        if (!m_resolvTarget.empty())
        {
            ::symlink(m_resolvTarget.c_str(), kResolvConf);
        }
    }
    else if (m_hadResolvConf)
    {
        write_file_atomic(kResolvConf, m_origResolvConf);
    }
    m_active = false;

    if (m_pipeWriteFd >= 0)
    {
        ::close(m_pipeWriteFd);
        m_pipeWriteFd = -1;
    }
    if (m_watchdogPid > 0)
    {
        int status = 0;
        ::waitpid(m_watchdogPid, &status, WNOHANG);
        m_watchdogPid = -1;
    }
}

void DnsLeakGuard::spawn_pipe_watchdog()
{
    const std::string cmd = build_restore_command();

    int fds[2];
    if (::pipe(fds) != 0)
    {
        LOG_WARN("DnsLeakGuard: 创建看门狗管道失败: %s", std::strerror(errno));
        return;
    }
    const pid_t pid = ::fork();
    if (pid < 0)
    {
        ::close(fds[0]);
        ::close(fds[1]);
        LOG_WARN("DnsLeakGuard: fork 看门狗失败: %s", std::strerror(errno));
        return;
    }
    if (pid == 0)
    {
        ::close(fds[1]);
        char c = 0;
        while (::read(fds[0], &c, 1) > 0) {}
        ::close(fds[0]);
        ::execl("/bin/sh", "sh", "-c", cmd.c_str(), static_cast<char*>(nullptr));
        ::_exit(127);
    }
    ::close(fds[0]);
    m_watchdogPid = pid;
    m_pipeWriteFd = fds[1];
}

#endif
