#include "Config.h"
#include "src/logger.h"   // LOG_ERR（Transport 等配置项解析异常要能看见）

#include <algorithm>   // std::sort（多服务器节按编号排序）
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <sstream>
#include <utility>     // std::pair

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

// ============================================================================
// 平台无关的 INI 原语。上层 LoadClientConfig / SaveClientConfig 只用这几个函数，
// 不再直接调 Win32 API，也不用关心编码：
//   Windows：GetPrivateProfileStringW 等（行为与改造前逐字节一致）
//   Linux  ：自实现解析（保留注释/未知键，原子写回，UTF-8）
// ============================================================================

namespace
{
    // ---- 字符串小工具（cfgstr 两种底层类型都要能编） ----

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

    // ASCII 小写化：只用于 udp/tcp 这类关键字判断，不引入 locale
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

    // 剥掉 QSettings 写入时加的成对双引号（引号混进 PEM 正文会污染公钥）
    cfgstr StripQuotes(cfgstr s)
    {
        if (s.size() >= 2 && s.front() == CS('"') && s.back() == CS('"'))
        {
            s = s.substr(1, s.size() - 2);
        }
        return s;
    }

#if defined(_WIN32)

    // ---------------- Windows：直接用 Win32 INI API ----------------

    cfgstr IniGetStr(const cfgstr& path, const cfgstr& sec, const cfgstr& key, const cfgstr& def)
    {
        wchar_t buffer[4096] = { 0 };
        const DWORD n = ::GetPrivateProfileStringW(sec.c_str(), key.c_str(), def.c_str(),
                                                   buffer, 4096, path.c_str());
        // 统一剥掉 QSettings 写入时加的成对引号：值里含逗号/空格/非 ASCII 时 Qt 会加引号，
        // 引号混进 PEM 正文或 DNS 列表会让上层解析失败
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
        // 值为 nullptr = 删除该键
        ::WritePrivateProfileStringW(sec.c_str(), key.c_str(), nullptr, path.c_str());
    }

    void IniDelSection(const cfgstr& path, const cfgstr& sec)
    {
        // 节 + 键均为 nullptr = 删除整节
        ::WritePrivateProfileStringW(sec.c_str(), nullptr, nullptr, path.c_str());
    }

    std::vector<cfgstr> IniSections(const cfgstr& path)
    {
        std::vector<cfgstr> out;
        std::vector<wchar_t> names(16384, L'\0');   // 双 NULL 结尾
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

#else // ---------------- Linux：自实现解析 ----------------

    // INI 文档实现已抽到 src/platform/ini_doc.h（纯标准库，可单测）
    using PosixIni = scholinux::IniDoc;


    // 每次 set/delete 都 load + save：配置不到 4KB、调用次数 <40，代价可忽略，
    // 换来的是"任何一步失败都不会留下半截文件"
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

} // namespace

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
    // 递归创建（~/.config 一般存在，但 XDG_CONFIG_HOME 可能是多级路径）
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
    // A directory is not a regular file.
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
    // 用 std::filesystem::path 而不是直接传 cfgstr：
    // std::ifstream 的 wstring 重载是 MSVC 私有扩展，libstdc++（MinGW/Linux）不认，
    // 而 filesystem::path 是 C++17 标准，三个编译器都走同一条路
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
        // First run: create the INI file with the built-in defaults.
        return SaveClientConfig(outCfg);
    }

    outCfg.ServerIP = IniGetStr(ini_path, CS("Server"), CS("ServerIP"), outCfg.ServerIP);
    outCfg.DebugServerIP = IniGetStr(ini_path, CS("Server"), CS("DebugServerIP"), outCfg.DebugServerIP);
    outCfg.ServerPort = IniGetInt(ini_path, CS("Server"), CS("ServerPort"), outCfg.ServerPort);

    // [Server] Count=N + [ServerN] Name/IP/Port/ClientID/RegisterToken
    // 读取方式：扫描 INI 全部节名，把所有 [ServerN] 节按编号收集
    // 支持手动编辑造成的影响：删掉中间一节、或编号有空洞（如 Server1+Server3 缺 Server2）
    // 时，都能正确读到；然后检测到"数量/编号与 Count 不符"就自动重排为连续编号
    // Server1..M 并回写 Count
    outCfg.servers.clear();
    std::vector<std::pair<int, ServerEntry>> found;   // (节编号, 内容)，按编号排序

    const std::vector<cfgstr> sections = IniSections(ini_path);

    for (const auto& sec : sections)
    {
        if (sec.compare(0, 6, CS("Server")) != 0)
            continue;                       // 只要 [ServerN]
        const cfgstr num = sec.substr(6);
        if (num.empty() || num.find_first_not_of(CS("0123456789")) != cfgstr::npos)
            continue;                       // 跳过 [Server] 主节等
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

        // 传输方式：0=UDP（默认）1=TCP。
        // 必须按字符串容错解析：手工把 ini 写成 "Transport=TCP" 时不能被静默当成 0，
        // 否则用户以为切了 TCP、实际一直走 UDP，日志里连一句提示都没有。
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

    // 按节编号升序排列（保持 config.ini 里的原始顺序）
    std::sort(found.begin(), found.end(),
              [](const std::pair<int, ServerEntry>& a, const std::pair<int, ServerEntry>& b)
              { return a.first < b.first; });

    // 检测是否需要"连续重排"
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
            if (found[i].first != static_cast<int>(i + 1))   // 期望 Server1..N 连续
            {
                needRebuild = true;
                break;
            }
        }
    }

    // 需要重排：把有效 [ServerN] 连续重写为 Server1..M，并删除多余旧节
    if (needRebuild)
    {
        // 先删掉所有现有 [ServerN] 节，避免旧节编号冲突
        for (const auto& sec : sections)
        {
            if (sec.compare(0, 6, CS("Server")) != 0)
                continue;
            const cfgstr num = sec.substr(6);
            if (num.empty() || num.find_first_not_of(CS("0123456789")) != cfgstr::npos)
                continue;
            IniDelSection(ini_path, sec);
        }
        // 连续写回 Server1..M
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
        }
        IniSetInt(ini_path, CS("Server"), CS("Count"), static_cast<int>(found.size()));
    }

    for (auto& f : found)
        outCfg.servers.push_back(std::move(f.second));
    // 向后兼容：没有 [ServerN] 节、但 [Server] 有真实主 IP 时，把它作为默认服务器
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
    // 主字段与 servers[0] 同步（默认/活动服务器）。
    // 身份字段（ClientID/RegisterToken/ServerPubKey）一并同步：
    // 否则直接 start()（未走 set_server()，如 AppBridge::start()）会
    // "连对地址、用错身份"——ClientID/RegisterToken 仍是 [Identity] 默认值。
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

    //多服务器列表：[Server] Count + [ServerN] 节（每台含各自身份）
    ok &= IniSetInt(ini_path, CS("Server"), CS("Count"), static_cast<int>(cfg.servers.size()));
    for (std::size_t i = 0; i < cfg.servers.size(); ++i)
    {
        const cfgstr sec = CS("Server") + cfg_num(static_cast<long long>(i + 1));
        const ServerEntry& e = cfg.servers[i];
        ok &= IniSetStr(ini_path, sec, CS("Name"), e.Name);
        ok &= IniSetStr(ini_path, sec, CS("ServerIP"), e.ServerIP);
        ok &= IniSetInt(ini_path, sec, CS("ServerPort"), e.ServerPort);
        ok &= IniSetInt(ini_path, sec, CS("Transport"), e.transport);
        // 每台服务器各自的认证身份 + 服务器公钥
        ok &= IniSetStr(ini_path, sec, CS("ClientID"), e.ClientID);
        ok &= IniSetStr(ini_path, sec, CS("RegisterToken"), e.RegisterToken);
        ok &= IniSetStr(ini_path, sec, CS("ServerPubKey"), e.ServerPubKey);
    }

    //[Network]
    ok &= IniSetStr(ini_path, CS("Network"), CS("VirtualIP"), cfg.VirtualIP);
    ok &= IniSetInt(ini_path, CS("Network"), CS("VirtualPrefix"), cfg.VirtualPrefix);
    ok &= IniSetStr(ini_path, CS("Network"), CS("DNS"), cfg.DNS);
    ok &= IniSetInt(ini_path, CS("Network"), CS("MTU"), static_cast<int>(cfg.MTU));
    ok &= IniSetInt(ini_path, CS("Network"), CS("Metric"), cfg.Metric);

    // 多服务器模式下信息已由 [ServerN] 承载，主节/身份节的旧键清掉
    IniDelKey(ini_path, CS("Server"), CS("ServerIP"));
    IniDelKey(ini_path, CS("Server"), CS("DebugServerIP"));
    IniDelKey(ini_path, CS("Server"), CS("ServerPort"));
    IniDelKey(ini_path, CS("Identity"), CS("ClientID"));
    IniDelKey(ini_path, CS("Identity"), CS("RegisterToken"));

    // 删除服务器后清理残留的旧 [ServerN] 节：
    // 例如从 3 台删到 2 台，[Server3] 仍留在 ini 里，下次 Count 会拿到脏数据。
    {
        const std::vector<cfgstr> sections = IniSections(ini_path);
        const std::size_t maxOk = cfg.servers.size();
        for (const auto& sec : sections)
        {
            if (sec.compare(0, 6, CS("Server")) != 0)
                continue;
            // 仅处理形如 Server<数字> 的节；跳过 Server 主节本身
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
