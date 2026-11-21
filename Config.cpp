#include "Config.h"
#include "src/logger.h"

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <utility>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#include "src/platform/ini_doc.h"
#endif

namespace scholini
{

    cfgstr TrimStr(const cfgstr& s)
    {
        const cfgstr::size_type b = s.find_first_not_of(CS(" \t\r\n"));
        if (b == cfgstr::npos)
        {
            return cfgstr();
        }
        const cfgstr::size_type e = s.find_last_not_of(CS(" \t\r\n"));
        return s.substr(b, e - b + 1);
    }

    cfgstr LowerAscii(const cfgstr& s)
    {
        cfgstr out = s;
        for (auto& c : out)
        {
            if (c >= CS('A') && c <= CS('Z'))
            {
                c = static_cast<cfgstr::value_type>(c - CS('A') + CS('a'));
            }
        }
        return out;
    }

    int CfgToInt(const cfgstr& s, int def)
    {
        try
        {
            const std::size_t used = s.find_first_not_of(CS(" \t"));
            if (used == cfgstr::npos)
            {
                return def;
            }
            return static_cast<int>(std::stoll(s.substr(used)));
        }
        catch (const std::exception&)
        {
            return def;
        }
    }

    cfgstr StripQuotes(cfgstr s)
    {
        if (s.size() >= 2 && s.front() == CS('"') && s.back() == CS('"'))
        {
            s = s.substr(1, s.size() - 2);
        }
        return s;
    }

#if defined(_WIN32)

    cfgstr IniGetStr(const cfgstr& path, const cfgstr& sec, const cfgstr& key, const cfgstr& def)
    {
        wchar_t buffer[4096] = { 0 };
        const DWORD n = ::GetPrivateProfileStringW(sec.c_str(), key.c_str(), def.c_str(),
                                                   buffer, 4096, path.c_str());
        return StripQuotes(TrimStr(cfgstr(buffer, n)));
    }

    int IniGetInt(const cfgstr& path, const cfgstr& sec, const cfgstr& key, int def)
    {
        return static_cast<int>(::GetPrivateProfileIntW(sec.c_str(), key.c_str(), def, path.c_str()));
    }

    bool IniSetStr(const cfgstr& path, const cfgstr& sec, const cfgstr& key, const cfgstr& val)
    {
        return ::WritePrivateProfileStringW(sec.c_str(), key.c_str(), val.c_str(), path.c_str()) != 0;
    }

    bool IniSetInt(const cfgstr& path, const cfgstr& sec, const cfgstr& key, int val)
    {
        return IniSetStr(path, sec, key, cfg_num(val));
    }

    void IniDelKey(const cfgstr& path, const cfgstr& sec, const cfgstr& key)
    {
        ::WritePrivateProfileStringW(sec.c_str(), key.c_str(), nullptr, path.c_str());
    }

    void IniDelSection(const cfgstr& path, const cfgstr& sec)
    {
        ::WritePrivateProfileStringW(sec.c_str(), nullptr, nullptr, path.c_str());
    }

    std::vector<cfgstr> IniSections(const cfgstr& path)
    {
        std::vector<cfgstr> out;
        std::vector<wchar_t> names(16384, L'\0');
        const UINT n = ::GetPrivateProfileSectionNamesW(names.data(),
                                                        static_cast<DWORD>(names.size()),
                                                        path.c_str());
        if (n == 0)
        {
            return out;
        }
        for (const wchar_t* p = names.data(); *p; p += wcslen(p) + 1)
        {
            out.emplace_back(p);
        }
        return out;
    }

#else

    using PosixIni = scholinux::IniDoc;

    cfgstr IniGetStr(const cfgstr& path, const cfgstr& sec, const cfgstr& key, const cfgstr& def)
    {
        PosixIni ini;
        ini.load(path);
        return StripQuotes(TrimStr(ini.get(sec, key, def)));
    }

    int IniGetInt(const cfgstr& path, const cfgstr& sec, const cfgstr& key, int def)
    {
        PosixIni ini;
        ini.load(path);
        return CfgToInt(ini.get(sec, key, cfg_num(def)), def);
    }

    bool IniSetStr(const cfgstr& path, const cfgstr& sec, const cfgstr& key, const cfgstr& val)
    {
        PosixIni ini;
        ini.load(path);
        ini.set(sec, key, val);
        return ini.save(path);
    }

    bool IniSetInt(const cfgstr& path, const cfgstr& sec, const cfgstr& key, int val)
    {
        return IniSetStr(path, sec, key, cfg_num(val));
    }

    void IniDelKey(const cfgstr& path, const cfgstr& sec, const cfgstr& key)
    {
        PosixIni ini;
        ini.load(path);
        ini.del_key(sec, key);
        ini.save(path);
    }

    void IniDelSection(const cfgstr& path, const cfgstr& sec)
    {
        PosixIni ini;
        ini.load(path);
        ini.del_section(sec);
        ini.save(path);
    }

    std::vector<cfgstr> IniSections(const cfgstr& path)
    {
        PosixIni ini;
        ini.load(path);
        return ini.sections();
    }

#endif

}

using namespace scholini;

Config::Config(cfgstr path, cfgstr dirPath)
    : ini_path(std::move(path)), dir_path(std::move(dirPath))
{
}

Config::~Config() = default;

cfgstr Config::GetAppDataRoaming()
{
    return cfg_config_root();
}

bool Config::CreateDir(const cfgstr& dirPath)
{
    if (dirPath.empty())
    {
        return false;
    }
#if defined(_WIN32)
    return ::CreateDirectoryW(dirPath.c_str(), nullptr) != 0 ||
           ::GetLastError() == ERROR_ALREADY_EXISTS;
#else
    struct stat st{};
    if (::stat(dirPath.c_str(), &st) == 0)
    {
        return S_ISDIR(st.st_mode);
    }
    for (cfgstr::size_type pos = 1; pos != cfgstr::npos;)
    {
        pos = dirPath.find('/', pos);
        const cfgstr part = (pos == cfgstr::npos) ? dirPath : dirPath.substr(0, pos);
        if (!part.empty() && ::mkdir(part.c_str(), 0755) != 0 && errno != EEXIST)
        {
            return false;
        }
        if (pos == cfgstr::npos)
        {
            break;
        }
        ++pos;
    }
    return ::stat(dirPath.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

bool Config::FileExists(const cfgstr& filePath)
{
#if defined(_WIN32)
    const DWORD attr = ::GetFileAttributesW(filePath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES)
    {
        return false;
    }
    return (attr & FILE_ATTRIBUTE_DIRECTORY) == 0;
#else
    struct stat st{};
    return ::stat(filePath.c_str(), &st) == 0 && S_ISREG(st.st_mode);
#endif
}

bool Config::DirExists(const cfgstr& dirPath)
{
#if defined(_WIN32)
    const DWORD attr = ::GetFileAttributesW(dirPath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES)
    {
        return false;
    }
    return (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
#else
    struct stat st{};
    return ::stat(dirPath.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

std::string Config::ReadTextFile(const cfgstr& filePath)
{
    std::ifstream in(std::filesystem::path(filePath), std::ios::binary);
    if (!in)
    {
        return std::string();
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

bool Config::WriteTextFile(const cfgstr& filePath, const std::string& content)
{
    std::ofstream out(std::filesystem::path(filePath), std::ios::binary | std::ios::trunc);
    if (!out)
    {
        return false;
    }
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    return out.good();
}

bool Config::LoadClientConfig(ClientConfig& outCfg)
{
    if (ini_path.empty())
    {
        return false;
    }
    if (!FileExists(ini_path))
    {
        return SaveClientConfig(outCfg);
    }

    outCfg.ServerIP = IniGetStr(ini_path, CS("Server"), CS("ServerIP"), outCfg.ServerIP);
    outCfg.DebugServerIP = IniGetStr(ini_path, CS("Server"), CS("DebugServerIP"), outCfg.DebugServerIP);
    outCfg.ServerPort = IniGetInt(ini_path, CS("Server"), CS("ServerPort"), outCfg.ServerPort);

    outCfg.servers.clear();
    std::vector<std::pair<int, ServerEntry>> found;

    const std::vector<cfgstr> sections = IniSections(ini_path);

    for (const auto& sec : sections)
    {
        if (sec.compare(0, 6, CS("Server")) != 0)
            continue;
        const cfgstr num = sec.substr(6);
        if (num.empty() || num.find_first_not_of(CS("0123456789")) != cfgstr::npos)
            continue;
        const int idx = CfgToInt(num, 0);
        if (idx <= 0)
            continue;

        ServerEntry e;
        e.Name = StripQuotes(IniGetStr(ini_path, sec, CS("Name"), CS("")));
        e.ServerIP = IniGetStr(ini_path, sec, CS("ServerIP"), CS(""));
        e.ServerPort = IniGetInt(ini_path, sec, CS("ServerPort"), 51820);
        e.ClientID = IniGetStr(ini_path, sec, CS("ClientID"), outCfg.ClientID);
        e.RegisterToken = IniGetStr(ini_path, sec, CS("RegisterToken"), outCfg.RegisterToken);
        e.ServerPubKey = StripQuotes(IniGetStr(ini_path, sec, CS("ServerPubKey"), CS("")));
        e.managed = IniGetInt(ini_path, sec, CS("Managed"), 0) != 0;

        {
            const cfgstr tv = LowerAscii(IniGetStr(ini_path, sec, CS("Transport"), CS("")));
            if (tv.empty() || tv == CS("0") || tv == CS("udp") || tv == CS("false") || tv == CS("no"))
            {
                e.transport = 0;
            }
            else if (tv == CS("1") || tv == CS("tcp") || tv == CS("true") || tv == CS("yes"))
            {
                e.transport = 1;
            }
            else
            {
                e.transport = 0;
                LOG_ERR("[Config] [%s] Transport=%s 无法识别（应为 udp/tcp 或 0/1），按 UDP 处理",
                        cfg_to_utf8(sec).c_str(), cfg_to_utf8(tv).c_str());
            }
        }
        if (!e.ServerIP.empty())
            found.emplace_back(idx, std::move(e));
    }

    std::sort(found.begin(), found.end(),
              [](const std::pair<int, ServerEntry>& a, const std::pair<int, ServerEntry>& b)
              { return a.first < b.first; });

    bool needRebuild = false;
    const int count = IniGetInt(ini_path, CS("Server"), CS("Count"), 0);
    if (static_cast<int>(found.size()) != count)
    {
        needRebuild = true;
    }
    else
    {
        for (std::size_t i = 0; i < found.size(); ++i)
        {
            if (found[i].first != static_cast<int>(i + 1))
            {
                needRebuild = true;
                break;
            }
        }
    }

    if (needRebuild)
    {
        for (const auto& sec : sections)
        {
            if (sec.compare(0, 6, CS("Server")) != 0)
                continue;
            const cfgstr num = sec.substr(6);
            if (num.empty() || num.find_first_not_of(CS("0123456789")) != cfgstr::npos)
                continue;
            IniDelSection(ini_path, sec);
        }
        for (std::size_t i = 0; i < found.size(); ++i)
        {
            const cfgstr sec = CS("Server") + cfg_num(static_cast<long long>(i + 1));
            const ServerEntry& e = found[i].second;
            IniSetStr(ini_path, sec, CS("Name"), e.Name);
            IniSetStr(ini_path, sec, CS("ServerIP"), e.ServerIP);
            IniSetInt(ini_path, sec, CS("ServerPort"), e.ServerPort);
            IniSetInt(ini_path, sec, CS("Transport"), e.transport);
            IniSetStr(ini_path, sec, CS("ClientID"), e.ClientID);
            IniSetStr(ini_path, sec, CS("RegisterToken"), e.RegisterToken);
            IniSetStr(ini_path, sec, CS("ServerPubKey"), e.ServerPubKey);
            IniSetInt(ini_path, sec, CS("Managed"), e.managed ? 1 : 0);
        }
        IniSetInt(ini_path, CS("Server"), CS("Count"), static_cast<int>(found.size()));
    }

    for (auto& f : found)
        outCfg.servers.push_back(std::move(f.second));
    if (outCfg.servers.empty() && !outCfg.ServerIP.empty())
    {
        ServerEntry e;
        e.Name = CS("computer") + cfg_num(0);
        e.ServerIP = outCfg.ServerIP;
        e.ServerPort = outCfg.ServerPort;
        e.ClientID = outCfg.ClientID;
        e.RegisterToken = outCfg.RegisterToken;
        outCfg.servers.push_back(std::move(e));
    }
    if (!outCfg.servers.empty())
    {
        outCfg.ServerIP = outCfg.servers[0].ServerIP;
        outCfg.ServerPort = outCfg.servers[0].ServerPort;
        outCfg.ClientID = outCfg.servers[0].ClientID;
        outCfg.RegisterToken = outCfg.servers[0].RegisterToken;
        outCfg.ServerPubKey = outCfg.servers[0].ServerPubKey;
    }

    outCfg.VirtualIP = IniGetStr(ini_path, CS("Network"), CS("VirtualIP"), outCfg.VirtualIP);
    outCfg.VirtualPrefix = IniGetInt(ini_path, CS("Network"), CS("VirtualPrefix"), outCfg.VirtualPrefix);
    outCfg.DNS = IniGetStr(ini_path, CS("Network"), CS("DNS"), outCfg.DNS);
    outCfg.MTU = static_cast<uint32_t>(
        IniGetInt(ini_path, CS("Network"), CS("MTU"), static_cast<int>(outCfg.MTU)));
    outCfg.Metric = static_cast<uint8_t>(
        IniGetInt(ini_path, CS("Network"), CS("Metric"), outCfg.Metric));

    outCfg.RoutingMode = IniGetStr(ini_path, CS("Routing"), CS("Mode"), outCfg.RoutingMode);
    outCfg.ChinaIPList = IniGetStr(ini_path, CS("Routing"), CS("ChinaIPList"), outCfg.ChinaIPList);
    outCfg.BypassSubnets = IniGetStr(ini_path, CS("Routing"), CS("BypassSubnets"), outCfg.BypassSubnets);
    outCfg.IntranetSubnets = IniGetStr(ini_path, CS("Routing"), CS("IntranetSubnets"), outCfg.IntranetSubnets);
    outCfg.ProbeIP = IniGetStr(ini_path, CS("Routing"), CS("ProbeIP"), outCfg.ProbeIP);

    outCfg.UpdatePolicyURL = IniGetStr(ini_path, CS("Update"), CS("PolicyURL"), outCfg.UpdatePolicyURL);
    outCfg.UpdateSigURL = IniGetStr(ini_path, CS("Update"), CS("SigURL"), outCfg.UpdateSigURL);
    outCfg.ReleasePubKey = IniGetStr(ini_path, CS("Update"), CS("PublicKey"), outCfg.ReleasePubKey);

    outCfg.ServiceMode = IniGetStr(ini_path, CS("Service"), CS("Mode"), outCfg.ServiceMode);
    outCfg.ServiceURL = IniGetStr(ini_path, CS("Service"), CS("ServiceURL"), outCfg.ServiceURL);
    outCfg.ServicePubKey = IniGetStr(ini_path, CS("Service"), CS("PublicKey"), outCfg.ServicePubKey);
    outCfg.ServiceFp = IniGetStr(ini_path, CS("Service"), CS("Fp"), outCfg.ServiceFp);
    outCfg.ServiceClientId = IniGetStr(ini_path, CS("Service"), CS("ClientID"), outCfg.ServiceClientId);
    outCfg.ServiceToken = IniGetStr(ini_path, CS("Service"), CS("Token"), outCfg.ServiceToken);
    outCfg.ServiceStatus = IniGetStr(ini_path, CS("Service"), CS("Status"), outCfg.ServiceStatus);
    outCfg.ServiceExpireAt = IniGetStr(ini_path, CS("Service"), CS("ExpireAt"), outCfg.ServiceExpireAt);
    outCfg.ServiceQuotaBytes = IniGetStr(ini_path, CS("Service"), CS("QuotaBytes"), outCfg.ServiceQuotaBytes);
    outCfg.ServiceUsedBytes = IniGetStr(ini_path, CS("Service"), CS("UsedBytes"), outCfg.ServiceUsedBytes);
    outCfg.ServiceManagedServers = IniGetStr(ini_path, CS("Service"), CS("ManagedServers"), outCfg.ServiceManagedServers);

    outCfg.ClientID = IniGetStr(ini_path, CS("Identity"), CS("ClientID"), outCfg.ClientID);
    outCfg.RegisterToken = IniGetStr(ini_path, CS("Identity"), CS("RegisterToken"), outCfg.RegisterToken);

    return true;
}

bool Config::SaveClientConfig(const ClientConfig& cfg)
{
    if (ini_path.empty())
    {
        return false;
    }
    if (!dir_path.empty())
    {
        CreateDir(dir_path);
    }

    bool ok = true;

    ok &= IniSetInt(ini_path, CS("Server"), CS("Count"), static_cast<int>(cfg.servers.size()));
    for (std::size_t i = 0; i < cfg.servers.size(); ++i)
    {
        const cfgstr sec = CS("Server") + cfg_num(static_cast<long long>(i + 1));
        const ServerEntry& e = cfg.servers[i];
        ok &= IniSetStr(ini_path, sec, CS("Name"), e.Name);
        ok &= IniSetStr(ini_path, sec, CS("ServerIP"), e.ServerIP);
        ok &= IniSetInt(ini_path, sec, CS("ServerPort"), e.ServerPort);
        ok &= IniSetInt(ini_path, sec, CS("Transport"), e.transport);
        ok &= IniSetStr(ini_path, sec, CS("ClientID"), e.ClientID);
        ok &= IniSetStr(ini_path, sec, CS("RegisterToken"), e.RegisterToken);
        ok &= IniSetStr(ini_path, sec, CS("ServerPubKey"), e.ServerPubKey);
    }

    ok &= IniSetStr(ini_path, CS("Network"), CS("VirtualIP"), cfg.VirtualIP);
    ok &= IniSetInt(ini_path, CS("Network"), CS("VirtualPrefix"), cfg.VirtualPrefix);
    ok &= IniSetStr(ini_path, CS("Network"), CS("DNS"), cfg.DNS);
    ok &= IniSetInt(ini_path, CS("Network"), CS("MTU"), static_cast<int>(cfg.MTU));
    ok &= IniSetInt(ini_path, CS("Network"), CS("Metric"), cfg.Metric);

    ok &= IniSetStr(ini_path, CS("Routing"), CS("Mode"), cfg.RoutingMode);
    ok &= IniSetStr(ini_path, CS("Routing"), CS("ChinaIPList"), cfg.ChinaIPList);
    ok &= IniSetStr(ini_path, CS("Routing"), CS("BypassSubnets"), cfg.BypassSubnets);
    ok &= IniSetStr(ini_path, CS("Routing"), CS("IntranetSubnets"), cfg.IntranetSubnets);
    ok &= IniSetStr(ini_path, CS("Routing"), CS("ProbeIP"), cfg.ProbeIP);

    ok &= IniSetStr(ini_path, CS("Update"), CS("PolicyURL"), cfg.UpdatePolicyURL);
    ok &= IniSetStr(ini_path, CS("Update"), CS("SigURL"), cfg.UpdateSigURL);
    ok &= IniSetStr(ini_path, CS("Update"), CS("PublicKey"), cfg.ReleasePubKey);

    ok &= IniSetStr(ini_path, CS("Service"), CS("Mode"), cfg.ServiceMode);
    ok &= IniSetStr(ini_path, CS("Service"), CS("ServiceURL"), cfg.ServiceURL);
    ok &= IniSetStr(ini_path, CS("Service"), CS("PublicKey"), cfg.ServicePubKey);
    ok &= IniSetStr(ini_path, CS("Service"), CS("Fp"), cfg.ServiceFp);
    ok &= IniSetStr(ini_path, CS("Service"), CS("ClientID"), cfg.ServiceClientId);
    ok &= IniSetStr(ini_path, CS("Service"), CS("Token"), cfg.ServiceToken);
    ok &= IniSetStr(ini_path, CS("Service"), CS("Status"), cfg.ServiceStatus);
    ok &= IniSetStr(ini_path, CS("Service"), CS("ExpireAt"), cfg.ServiceExpireAt);
    ok &= IniSetStr(ini_path, CS("Service"), CS("QuotaBytes"), cfg.ServiceQuotaBytes);
    ok &= IniSetStr(ini_path, CS("Service"), CS("UsedBytes"), cfg.ServiceUsedBytes);
    ok &= IniSetStr(ini_path, CS("Service"), CS("ManagedServers"), cfg.ServiceManagedServers);

    IniDelKey(ini_path, CS("Server"), CS("ServerIP"));
    IniDelKey(ini_path, CS("Server"), CS("DebugServerIP"));
    IniDelKey(ini_path, CS("Server"), CS("ServerPort"));
    IniDelKey(ini_path, CS("Identity"), CS("ClientID"));
    IniDelKey(ini_path, CS("Identity"), CS("RegisterToken"));

    {
        const std::vector<cfgstr> sections = IniSections(ini_path);
        const std::size_t maxOk = cfg.servers.size();
        for (const auto& sec : sections)
        {
            if (sec.compare(0, 6, CS("Server")) != 0)
                continue;
            const cfgstr num = sec.substr(6);
            if (num.empty() || num.find_first_not_of(CS("0123456789")) != cfgstr::npos)
                continue;
            const int idx = CfgToInt(num, 0);
            if (idx <= 0 || static_cast<std::size_t>(idx) <= maxOk)
                continue;
            IniDelSection(ini_path, sec);
        }
    }
    return ok;
}
