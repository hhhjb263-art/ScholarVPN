#include "DnsLeakGuard.h"

#if defined(_WIN32)

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
bool DnsLeakGuard::protect(tun_id_t keepId, const cfgstr& /*dnsServers*/)
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
        if (a->Luid.Value == keepId.Value)
            continue;   // 跳过 TUN 网卡（它的 DNS 由 set_DNS_IPv4 管理）

        GUID g{};
        if (ConvertInterfaceLuidToGuid(&a->Luid, &g) != NO_ERROR)
            continue;

        // 读取该接口当前 DNS（SDK 10.0.26100+：传 GUID 值 + 调用方提供的结构体，先设 Version）
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

    // 派生崩溃看门狗：本进程退出（含崩溃/被杀）后自动复位这些网卡的 DNS，
    // 覆盖 restore() 来不及执行的异常退出。正常退出时 restore() 先行，看门狗幂等无害。
    spawn_crash_watchdog();

    return ok;
}

// 派生分离的 PowerShell 看门狗：
//   Wait-Process 等本进程退出 → 逐网卡复位（DHCP→自动 / 静态→写回原值）。
//   用 InterfaceIndex 而非网卡名，避免中文网卡名的编码问题。
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
            // 原 DHCP 自动获取：复位为自动（等价"恢复为默认"）
            cmd += L" Set-DnsClientServerAddress -InterfaceIndex "
                 + std::to_wstring(bk.ifIndex) + L" -ResetServerAddresses;";
        }
        else if (!bk.ipv4Dns.empty())
        {
            // 原静态 DNS：写回原串（可能是 "1.1.1.1,8.8.8.8" 逗号分隔，拆开逐个加引号）
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
    // 派生失败静默忽略：还有正常 restore() 和下次启动的残留清理两层兜底
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
                    // 注意：不过滤 OperStatus！崩溃发生时某网卡可能恰好断开（如 Wi-Fi 掉线），
                    // 黑洞残留在其配置里，重新连接后才会暴露——宕着的网卡也必须扫描清理。
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

#else // ---------------------------- Linux ----------------------------

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
    if (name.empty() || name.size() >= 16)   // IFNAMSIZ
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

// "8.8.8.8,1.1.1.1" -> "8.8.8.8 1.1.1.1"
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

// 单引号转义（拼进 sh -c 时防止命令注入/断行）
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

} // namespace

// 看门狗要执行的恢复命令（fork 之前拼好，子进程只 execl）
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
    restore();   // 清掉上一次的状态（防重复调用 / 上次崩溃残留）

    if (!safe_ifname(keepId))
    {
        LOG_ERROR("DnsLeakGuard: 非法接口名");
        return false;
    }
    m_ifname = keepId;
    const std::string servers = dns_list(dnsServers);

    // ---- 方案 A：systemd-resolved（首选）----
    // `resolvectl domain <if> '~.'` 把"所有域名"的解析都路由到该 link，
    // 物理网卡上的 DNS 自然不再被使用；不碰 /etc/resolv.conf，
    // 也不与 NetworkManager 抢文件，断开 revert 即可。
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

    // ---- 方案 B：直接改写 /etc/resolv.conf ----
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

    // 符号链接必须先删：直接写会穿透到 systemd 的 stub 文件，重启后失效
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

    // 关闭写端：看门狗读到 EOF 后会执行一次恢复（幂等）然后退出
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
    // fork 之后子进程只能调 async-signal-safe 函数：多线程程序里 malloc 可能
    // 被其他线程持锁，子进程再 popen/拼接字符串会死锁。
    // 所以恢复命令在这里就拼好，子进程只做 read + execl。
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
        // 父进程活着时永远阻塞；父死/被 kill -9 → EOF
        while (::read(fds[0], &c, 1) > 0) {}
        ::close(fds[0]);
        ::execl("/bin/sh", "sh", "-c", cmd.c_str(), static_cast<char*>(nullptr));
        ::_exit(127);
    }
    ::close(fds[0]);
    m_watchdogPid = pid;
    m_pipeWriteFd = fds[1];
}

#endif // _WIN32
