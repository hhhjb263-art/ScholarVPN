#include "Config.h"

#include <fstream>
#include <sstream>

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

    outCfg.Timeout = static_cast<int>(
        GetPrivateProfileIntW(L"General", L"Timeout", outCfg.Timeout, ini_path.c_str()));
    outCfg.KeyFile = ReadIniString(L"General", L"KeyFile", outCfg.KeyFile, ini_path);

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
    ok &= WritePrivateProfileStringW(L"Server", L"ServerIP", cfg.ServerIP.c_str(), ini_path.c_str()) != 0;
    ok &= WritePrivateProfileStringW(L"Server", L"DebugServerIP", cfg.DebugServerIP.c_str(), ini_path.c_str()) != 0;
    ok &= WriteIniInt(L"Server", L"ServerPort", cfg.ServerPort, ini_path);

    ok &= WriteIniInt(L"General", L"Timeout", cfg.Timeout, ini_path);
    ok &= WritePrivateProfileStringW(L"General", L"KeyFile", cfg.KeyFile.c_str(), ini_path.c_str()) != 0;

    ok &= WritePrivateProfileStringW(L"Network", L"VirtualIP", cfg.VirtualIP.c_str(), ini_path.c_str()) != 0;
    ok &= WriteIniInt(L"Network", L"VirtualPrefix", cfg.VirtualPrefix, ini_path);
    ok &= WritePrivateProfileStringW(L"Network", L"DNS", cfg.DNS.c_str(), ini_path.c_str()) != 0;
    ok &= WriteIniInt(L"Network", L"MTU", static_cast<int>(cfg.MTU), ini_path);
    ok &= WriteIniInt(L"Network", L"Metric", cfg.Metric, ini_path);

    ok &= WritePrivateProfileStringW(L"Identity", L"ClientID", cfg.ClientID.c_str(), ini_path.c_str()) != 0;
    ok &= WritePrivateProfileStringW(L"Identity", L"RegisterToken", cfg.RegisterToken.c_str(), ini_path.c_str()) != 0;

    return ok;
}
