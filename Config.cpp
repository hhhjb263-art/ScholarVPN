#include "Config.h"

#include <fstream>
#include <sstream>

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

    // ---- 多服务器列表：[Server] Count=N + [Server1..N] Name/IP/Port/ClientID/RegisterToken ----
    outCfg.servers.clear();
    const int count = static_cast<int>(
        GetPrivateProfileIntW(L"Server", L"Count", 0, ini_path.c_str()));
    for (int i = 1; i <= count; ++i)
    {
        const std::wstring sec = L"Server" + std::to_wstring(i);
        ServerEntry e;
        e.Name = ReadIniString(sec.c_str(), L"Name", L"", ini_path);
        e.ServerIP = ReadIniString(sec.c_str(), L"ServerIP", L"", ini_path);
        e.ServerPort = static_cast<int>(
            GetPrivateProfileIntW(sec.c_str(), L"ServerPort", 51820, ini_path.c_str()));
        // 每台服务器的身份；未配置时回退全局 [Identity]（兼容旧配置）
        e.ClientID = ReadIniString(sec.c_str(), L"ClientID", outCfg.ClientID, ini_path);
        e.RegisterToken = ReadIniString(sec.c_str(), L"RegisterToken", outCfg.RegisterToken, ini_path);
        // 该服务器身份公钥（base64 单行；空=用内置硬编码）
        e.ServerPubKey = ReadIniString(sec.c_str(), L"ServerPubKey", L"", ini_path);
        if (!e.ServerIP.empty())
        {
            outCfg.servers.push_back(std::move(e));
        }
    }
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
    // 主字段与 servers[0] 同步（默认/活动服务器）
    if (!outCfg.servers.empty())
    {
        outCfg.ServerIP = outCfg.servers[0].ServerIP;
        outCfg.ServerPort = outCfg.servers[0].ServerPort;
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

    // ---- 多服务器列表：[Server] Count + [ServerN] 节（每台含各自身份）----
    ok &= WriteIniInt(L"Server", L"Count", static_cast<int>(cfg.servers.size()), ini_path);
    for (size_t i = 0; i < cfg.servers.size(); ++i)
    {
        const std::wstring sec = L"Server" + std::to_wstring(i + 1);
        ok &= WritePrivateProfileStringW(sec.c_str(), L"Name", cfg.servers[i].Name.c_str(), ini_path.c_str()) != 0;
        ok &= WritePrivateProfileStringW(sec.c_str(), L"ServerIP", cfg.servers[i].ServerIP.c_str(), ini_path.c_str()) != 0;
        ok &= WriteIniInt(sec.c_str(), L"ServerPort", cfg.servers[i].ServerPort, ini_path);
        // 每台服务器各自的认证身份 + 服务器公钥
        ok &= WritePrivateProfileStringW(sec.c_str(), L"ClientID", cfg.servers[i].ClientID.c_str(), ini_path.c_str()) != 0;
        ok &= WritePrivateProfileStringW(sec.c_str(), L"RegisterToken", cfg.servers[i].RegisterToken.c_str(), ini_path.c_str()) != 0;
        ok &= WritePrivateProfileStringW(sec.c_str(), L"ServerPubKey", cfg.servers[i].ServerPubKey.c_str(), ini_path.c_str()) != 0;
    }

    // ---- [Network] 全局网络设置 ----
    ok &= WritePrivateProfileStringW(L"Network", L"VirtualIP", cfg.VirtualIP.c_str(), ini_path.c_str()) != 0;
    ok &= WriteIniInt(L"Network", L"VirtualPrefix", cfg.VirtualPrefix, ini_path);
    ok &= WritePrivateProfileStringW(L"Network", L"DNS", cfg.DNS.c_str(), ini_path.c_str()) != 0;
    ok &= WriteIniInt(L"Network", L"MTU", static_cast<int>(cfg.MTU), ini_path);
    ok &= WriteIniInt(L"Network", L"Metric", cfg.Metric, ini_path);

    // ---- 删除旧版单服务器冗余键（多服务器模式下信息已由 [ServerN] 承载）----
    // WritePrivateProfileStringW 传 nullptr 值 = 删除该键
    WritePrivateProfileStringW(L"Server", L"ServerIP", nullptr, ini_path.c_str());
    WritePrivateProfileStringW(L"Server", L"DebugServerIP", nullptr, ini_path.c_str());
    WritePrivateProfileStringW(L"Server", L"ServerPort", nullptr, ini_path.c_str());
    WritePrivateProfileStringW(L"Identity", L"ClientID", nullptr, ini_path.c_str());
    WritePrivateProfileStringW(L"Identity", L"RegisterToken", nullptr, ini_path.c_str());

    return ok;
}
