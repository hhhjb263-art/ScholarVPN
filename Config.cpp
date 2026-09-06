#include "Config.h"

#include <algorithm>   // std::sort（多服务器节按编号排序）
#include <cstdlib>     // _wtoi
#include <cwchar>      // wcslen
#include <fstream>
#include <sstream>
#include <utility>     // std::pair

#pragma comment(lib, "shell32.lib")   // SHGetFolderPathW（Config::GetAppDataRoaming）

Config::Config(std::wstring path, std::wstring dirPath)
    : ini_path(std::move(path)), dir_path(std::move(dirPath))
{
}

Config::~Config() = default;

std::wstring Config::GetAppDataRoaming()
{
    wchar_t path[MAX_PATH] = { 0 };
    if (SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, path) != S_OK)
    {
        GetCurrentDirectoryW(MAX_PATH, path);
    }
    return std::wstring(path);
}

bool Config::CreateDir(const std::wstring& dirPath)
{
    return CreateDirectoryW(dirPath.c_str(), nullptr) != 0 ||
           GetLastError() == ERROR_ALREADY_EXISTS;
}

bool Config::FileExists(const std::wstring& filePath)
{
    const DWORD attr = GetFileAttributesW(filePath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES)
    {
        return false;
    }
    // A directory is not a regular file.
    return (attr & FILE_ATTRIBUTE_DIRECTORY) == 0;
}

bool Config::DirExists(const std::wstring& dirPath)
{
    const DWORD attr = GetFileAttributesW(dirPath.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES)
    {
        return false;
    }
    return (attr & FILE_ATTRIBUTE_DIRECTORY) != 0;
}

std::string Config::ReadTextFile(const std::wstring& filePath)
{
    std::ifstream in(filePath, std::ios::binary);
    if (!in)
    {
        return std::string();
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

bool Config::WriteTextFile(const std::wstring& filePath, const std::string& content)
{
    std::ofstream out(filePath, std::ios::binary | std::ios::trunc);
    if (!out)
    {
        return false;
    }
    out.write(content.data(), static_cast<std::streamsize>(content.size()));
    return out.good();
}

std::wstring Config::ExpandEnvStr(const std::wstring& src)
{
    const DWORD len = ExpandEnvironmentStringsW(src.c_str(), nullptr, 0);
    if (len == 0)
    {
        return src;
    }
    std::wstring out(len, L'\0');
    const DWORD written = ExpandEnvironmentStringsW(src.c_str(), &out[0], len);
    if (written > 0)
    {
        out.resize(written - 1); // strip the trailing null
    }
    return out;
}

namespace
{
    // Trim leading/trailing whitespace (e.g. "ServerIP=1.2.3.4 " would otherwise fail validation)
    std::wstring TrimW(const std::wstring& s)
    {
        const std::size_t b = s.find_first_not_of(L" \t\r\n");
        if (b == std::wstring::npos)
            return std::wstring();
        const std::size_t e = s.find_last_not_of(L" \t\r\n");
        return s.substr(b, e - b + 1);
    }

    std::wstring ReadIniString(const std::wstring& section, const std::wstring& key,
                               const std::wstring& defaultValue, const std::wstring& iniPath)
    {
        wchar_t buffer[4096] = { 0 };
        const DWORD n = GetPrivateProfileStringW(section.c_str(), key.c_str(),
                                                 defaultValue.c_str(), buffer, 4096, iniPath.c_str());
        return TrimW(std::wstring(buffer, n));
    }

    bool WriteIniInt(const wchar_t* section, const wchar_t* key, int value, const std::wstring& iniPath)
    {
        return WritePrivateProfileStringW(section, key, std::to_wstring(value).c_str(), iniPath.c_str()) != 0;
    }
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

    outCfg.ServerIP = ReadIniString(L"Server", L"ServerIP", outCfg.ServerIP, ini_path);
    outCfg.DebugServerIP = ReadIniString(L"Server", L"DebugServerIP", outCfg.DebugServerIP, ini_path);
    outCfg.ServerPort = static_cast<int>(
        GetPrivateProfileIntW(L"Server", L"ServerPort", outCfg.ServerPort, ini_path.c_str()));

    // [Server] Count=N + [ServerN] Name/IP/Port/ClientID/RegisterToken
    // 读取方式：扫描 INI 全部节名，把所有 [ServerN] 节按编号收集
    // 支持手动编辑造成的影响：删掉中间一节、或编号有空洞（如 Server1+Server3 缺 Server2）
    // 时，都能正确读到；然后检测到"数量/编号与 Count 不符"就自动重排为连续编号
    // Server1..M 并回写 Count
    outCfg.servers.clear();
    std::vector<std::pair<int, ServerEntry>> found;   // (节编号, 内容)，按编号排序

    wchar_t names[16384] = { 0 };   // 全部节名（双 NULL 结尾）
    const UINT namesLen = GetPrivateProfileSectionNamesW(names, _countof(names), ini_path.c_str());

    {
        if (namesLen > 0)
        {
            for (wchar_t* p = names; *p; p += wcslen(p) + 1)
            {
                const std::wstring sec(p);
                if (sec.rfind(L"Server", 0) != 0)
                    continue;                       // 只要 [ServerN]
                const std::wstring num = sec.substr(6);
                if (num.empty() || num.find_first_not_of(L"0123456789") != std::wstring::npos)
                    continue;                       // 跳过 [Server] 主节等
                const int idx = _wtoi(num.c_str());
                if (idx <= 0)
                    continue;

                ServerEntry e;
                e.Name = ReadIniString(sec.c_str(), L"Name", L"", ini_path);
                if (e.Name.size() >= 2 && e.Name.front() == L'"' && e.Name.back() == L'"')
                    e.Name = e.Name.substr(1, e.Name.size() - 2);   // QSettings 引号剥离
                e.ServerIP = ReadIniString(sec.c_str(), L"ServerIP", L"", ini_path);
                e.ServerPort = static_cast<int>(
                    GetPrivateProfileIntW(sec.c_str(), L"ServerPort", 51820, ini_path.c_str()));
                e.ClientID = ReadIniString(sec.c_str(), L"ClientID", outCfg.ClientID, ini_path);
                e.RegisterToken = ReadIniString(sec.c_str(), L"RegisterToken", outCfg.RegisterToken, ini_path);
                e.ServerPubKey = ReadIniString(sec.c_str(), L"ServerPubKey", L"", ini_path);
                // QSettings 写入的值会带双引号（Win32 API 读取时不剥）：
                // 引号混进 PEM 正文会污染公钥，剥掉首尾引号
                if (e.ServerPubKey.size() >= 2 &&
                    e.ServerPubKey.front() == L'"' && e.ServerPubKey.back() == L'"')
                    e.ServerPubKey = e.ServerPubKey.substr(1, e.ServerPubKey.size() - 2);
                e.transport = static_cast<uint8_t>(
                    GetPrivateProfileIntW(sec.c_str(), L"Transport", 0, ini_path.c_str()));
                if (!e.ServerIP.empty())
                    found.emplace_back(idx, std::move(e));
            }
        }
    }

    // 按节编号升序排列（保持 config.ini 里的原始顺序）
    std::sort(found.begin(), found.end(),
              [](const std::pair<int, ServerEntry>& a, const std::pair<int, ServerEntry>& b)
              { return a.first < b.first; });

    // 检测是否需要"连续重排"
    bool needRebuild = false;
    const int count = static_cast<int>(
        GetPrivateProfileIntW(L"Server", L"Count", 0, ini_path.c_str()));
    if (static_cast<int>(found.size()) != count)
    {
        needRebuild = true;
    }
    else
    {
        for (size_t i = 0; i < found.size(); ++i)
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
        if (namesLen > 0)
        {
            for (wchar_t* p = names; *p; p += wcslen(p) + 1)
            {
                const std::wstring sec(p);
                if (sec.rfind(L"Server", 0) != 0)
                    continue;
                const std::wstring num = sec.substr(6);
                if (num.empty() || num.find_first_not_of(L"0123456789") != std::wstring::npos)
                    continue;
                WritePrivateProfileStringW(sec.c_str(), nullptr, nullptr, ini_path.c_str());  // 删整节
            }
        }
        // 连续写回 Server1..M
        for (size_t i = 0; i < found.size(); ++i)
        {
            const std::wstring sec = L"Server" + std::to_wstring(i + 1);
            WritePrivateProfileStringW(sec.c_str(), L"Name", found[i].second.Name.c_str(), ini_path.c_str());
            WritePrivateProfileStringW(sec.c_str(), L"ServerIP", found[i].second.ServerIP.c_str(), ini_path.c_str());
            WriteIniInt(sec.c_str(), L"ServerPort", found[i].second.ServerPort, ini_path);
            WriteIniInt(sec.c_str(), L"Transport", found[i].second.transport, ini_path);
            WritePrivateProfileStringW(sec.c_str(), L"ClientID", found[i].second.ClientID.c_str(), ini_path.c_str());
            WritePrivateProfileStringW(sec.c_str(), L"RegisterToken", found[i].second.RegisterToken.c_str(), ini_path.c_str());
            WritePrivateProfileStringW(sec.c_str(), L"ServerPubKey", found[i].second.ServerPubKey.c_str(), ini_path.c_str());
        }
        WriteIniInt(L"Server", L"Count", static_cast<int>(found.size()), ini_path);
    }

    for (auto& f : found)
        outCfg.servers.push_back(std::move(f.second));
    // 向后兼容：没有 [ServerN] 节、但 [Server] 有真实主 IP 时，把它作为默认服务器
    if (outCfg.servers.empty() && !outCfg.ServerIP.empty())
    {
        ServerEntry e;
        int idx = 0;
        e.Name = L"computer" + std::to_wstring(idx++);
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

    outCfg.VirtualIP = ReadIniString(L"Network", L"VirtualIP", outCfg.VirtualIP, ini_path);
    outCfg.VirtualPrefix = static_cast<int>(
        GetPrivateProfileIntW(L"Network", L"VirtualPrefix", outCfg.VirtualPrefix, ini_path.c_str()));
    outCfg.DNS = ReadIniString(L"Network", L"DNS", outCfg.DNS, ini_path);
    outCfg.MTU = static_cast<uint32_t>(
        GetPrivateProfileIntW(L"Network", L"MTU", static_cast<int>(outCfg.MTU), ini_path.c_str()));
    outCfg.Metric = static_cast<uint8_t>(
        GetPrivateProfileIntW(L"Network", L"Metric", outCfg.Metric, ini_path.c_str()));

    outCfg.ClientID = ReadIniString(L"Identity", L"ClientID", outCfg.ClientID, ini_path);
    outCfg.RegisterToken = ReadIniString(L"Identity", L"RegisterToken", outCfg.RegisterToken, ini_path);

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
    ok &= WriteIniInt(L"Server", L"Count", static_cast<int>(cfg.servers.size()), ini_path);
    for (size_t i = 0; i < cfg.servers.size(); ++i)
    {
        const std::wstring sec = L"Server" + std::to_wstring(i + 1);
        ok &= WritePrivateProfileStringW(sec.c_str(), L"Name", cfg.servers[i].Name.c_str(), ini_path.c_str()) != 0;
        ok &= WritePrivateProfileStringW(sec.c_str(), L"ServerIP", cfg.servers[i].ServerIP.c_str(), ini_path.c_str()) != 0;
        ok &= WriteIniInt(sec.c_str(), L"ServerPort", cfg.servers[i].ServerPort, ini_path);
        ok &= WriteIniInt(sec.c_str(), L"Transport", cfg.servers[i].transport, ini_path);
        // 每台服务器各自的认证身份 + 服务器公钥
        ok &= WritePrivateProfileStringW(sec.c_str(), L"ClientID", cfg.servers[i].ClientID.c_str(), ini_path.c_str()) != 0;
        ok &= WritePrivateProfileStringW(sec.c_str(), L"RegisterToken", cfg.servers[i].RegisterToken.c_str(), ini_path.c_str()) != 0;
        ok &= WritePrivateProfileStringW(sec.c_str(), L"ServerPubKey", cfg.servers[i].ServerPubKey.c_str(), ini_path.c_str()) != 0;
    }

    //[Network]
    ok &= WritePrivateProfileStringW(L"Network", L"VirtualIP", cfg.VirtualIP.c_str(), ini_path.c_str()) != 0;
    ok &= WriteIniInt(L"Network", L"VirtualPrefix", cfg.VirtualPrefix, ini_path);
    ok &= WritePrivateProfileStringW(L"Network", L"DNS", cfg.DNS.c_str(), ini_path.c_str()) != 0;
    ok &= WriteIniInt(L"Network", L"MTU", static_cast<int>(cfg.MTU), ini_path);
    ok &= WriteIniInt(L"Network", L"Metric", cfg.Metric, ini_path);

    //多服务器模式下信息已由 [ServerN] 承载）
    // WritePrivateProfileStringW 传 nullptr 值 = 删除该键
    WritePrivateProfileStringW(L"Server", L"ServerIP", nullptr, ini_path.c_str());
    WritePrivateProfileStringW(L"Server", L"DebugServerIP", nullptr, ini_path.c_str());
    WritePrivateProfileStringW(L"Server", L"ServerPort", nullptr, ini_path.c_str());
    WritePrivateProfileStringW(L"Identity", L"ClientID", nullptr, ini_path.c_str());
    WritePrivateProfileStringW(L"Identity", L"RegisterToken", nullptr, ini_path.c_str());

    // 删除服务器后清理残留的旧 [ServerN] 节：
    // 例如从 3 台删到 2 台，[Server3] 仍留在 ini 里，下次 Count 会拿到脏数据。
    // 这里枚举全部节名，把编号大于 servers.size() 的 [ServerN] 整体删除。
    {
        wchar_t names[16384] = { 0 };   // 所有节名（双 NULL 结尾）
        const UINT namesLen = GetPrivateProfileSectionNamesW(names, _countof(names), ini_path.c_str());
        if (namesLen > 0)
        {
            const size_t maxOk = cfg.servers.size();
            for (wchar_t* p = names; *p; p += wcslen(p) + 1)
            {
                const std::wstring sec(p);
                if (sec.rfind(L"Server", 0) != 0)
                    continue;
                // 仅处理形如 Server<数字> 的节；跳过 Server 主节本身
                const std::wstring num = sec.substr(6);
                if (num.empty() || num.find_first_not_of(L"0123456789") != std::wstring::npos)
                    continue;
                const int idx = _wtoi(num.c_str());
                if (idx <= 0 || static_cast<size_t>(idx) <= maxOk)
                    continue;
                // 删除多余节（key 传 nullptr = 删整个节）
                WritePrivateProfileStringW(sec.c_str(), nullptr, nullptr, ini_path.c_str());
            }
        }
    }
    return ok;
}
