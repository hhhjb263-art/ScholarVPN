#pragma once
#include <windows.h>
#include <shlobj.h>
#include <cstdint>
#include <string>

// Client runtime settings, loaded from / saved to an INI file.
struct ClientConfig
{
#ifdef _DEBUG
    std::wstring ServerIP = L"192.168.1.12";
#else
    // Release builds: no hardcoded server; the user fills it in the generated config.ini
    std::wstring ServerIP = L"\u8BF7\u81EA\u884C\u586B\u5199"; // "please fill in"
#endif
    // Debug-only server override: DEBUG builds prefer this key, RELEASE builds ignore it.
    // Debug default = local test server; Release default = empty (never used).
#ifdef _DEBUG
    std::wstring DebugServerIP = L"192.168.1.12";
#else
    std::wstring DebugServerIP = L"";
#endif
    int ServerPort = 51820;
    int Timeout = 5000;
    std::wstring KeyFile = L"client.key";

    // Virtual adapter (TUN) settings
    std::wstring VirtualIP = L"10.8.0.2";
    int VirtualPrefix = 24;
    std::wstring DNS = L"8.8.8.8,1.1.1.1";
    uint32_t MTU = 1400;
    uint8_t Metric = 5;

    // Identity (three-phase auth)
    std::wstring ClientID = L"user";        // client identifier
    std::wstring RegisterToken = L"";       // one-time register token (empty = login mode)
};

class Config
{
public:
    std::wstring ini_path;
    std::wstring dir_path;

    Config(std::wstring path, std::wstring dirPath);
    ~Config();

    static std::wstring GetAppDataRoaming();

    // Directory / file helpers
    static bool CreateDir(const std::wstring& dirPath);
    static bool FileExists(const std::wstring& filePath);
    static bool DirExists(const std::wstring& dirPath);
    static std::string ReadTextFile(const std::wstring& filePath);
    static bool WriteTextFile(const std::wstring& filePath, const std::string& content);
    static std::wstring ExpandEnvStr(const std::wstring& src);

    // Load settings from the INI file; creates it with defaults when missing.
    bool LoadClientConfig(ClientConfig& outCfg);
    bool SaveClientConfig(const ClientConfig& cfg);
};
