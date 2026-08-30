#pragma once
#include <windows.h>
#include <shlobj.h>
#include <cstdint>
#include <string>
#include <vector>

// 一台服务器的配置（多服务器支持）
struct ServerEntry
{
    std::wstring Name;          // 显示名，如 "服务器A"
    std::wstring ServerIP;      // 服务器 IP
    int ServerPort = 51820;
    // 每台服务器各自的认证身份（各服务器独立注册）
    std::wstring ClientID;      // 该服务器的客户端标识
    std::wstring RegisterToken; // 该服务器的一次性注册令牌（空=登录模式）
    // 该服务器的身份公钥（Ed25519 SPKI PEM 的 base64 正文，60 字符单行，不带头尾行）。
    // 每台服务器密钥独立，客户端用它验证该服务器签名（防中间人）；留空=用内置硬编码公钥。
    std::wstring ServerPubKey;
};

// Client runtime settings, loaded from / saved to an INI file.
struct ClientConfig
{
#ifdef _DEBUG
    std::wstring ServerIP = L"192.168.1.12";
#else
    // Release builds: no hardcoded server; user fills it in config.ini (empty default avoids mojibake)
    std::wstring ServerIP = L"";
#endif
    // Debug-only server override: DEBUG builds prefer this key, RELEASE builds ignore it.
    // Debug default = local test server; Release default = empty (never used).
#ifdef _DEBUG
    std::wstring DebugServerIP = L"192.168.1.12";
#else
    std::wstring DebugServerIP = L"";
#endif
    int ServerPort = 51820;

    // 多服务器列表（INI 格式：[Server] Count=N + [ServerN] Name/IP/Port）。
    // servers[0] 即默认/活动服务器，读写时与上面的 ServerIP/ServerPort 保持同步。
    std::vector<ServerEntry> servers;

    // Virtual adapter (TUN) settings
    // VirtualIP: optional. Empty = adopt the server-assigned virtual IP after
    // authentication (multi-user servers always assign one); non-empty = fallback
    // for old servers that do not advertise an address.
    std::wstring VirtualIP = L"";
    int VirtualPrefix = 24;
    std::wstring DNS = L"8.8.8.8,1.1.1.1";
    uint32_t MTU = 1400;
    uint8_t Metric = 5;

    // Identity (three-phase auth)
    std::wstring ClientID = L"user";        // client identifier
    std::wstring RegisterToken = L"";       // one-time register token (empty = login mode)
    // 默认/活动服务器的身份公钥（与 servers[0].ServerPubKey 同步，base64 正文单行，空=用内置公钥）
    std::wstring ServerPubKey;
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
