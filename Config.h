#pragma once

#include "src/platform/cfgstr.h"

#include <cstdint>
#include <string>
#include <vector>

// ============================================================================
// 配置层（跨平台）
//
// 字符串类型统一用 cfgstr：
//   Windows = std::wstring（Win32 INI API / 宽字符路径，行为与改造前完全一致）
//   Linux   = std::string UTF-8
// 业务代码一律不要写 std::wstring 或 L"..."，用 cfgstr + CS("...")
// ============================================================================

// 一台服务器的配置
struct ServerEntry
{
    cfgstr Name;            // 显示名，如 "服务器A"
    cfgstr ServerIP;        // 服务器 IP
    int ServerPort = 51820;
    // 传输方式：0 = UDP（默认），1 = TCP（应对运营商丢 UDP，可配合 443 端口）
    uint8_t transport = 0;
    // 每台服务器各自的认证身份（各服务器独立注册）
    cfgstr ClientID;        // 该服务器的客户端标识
    cfgstr RegisterToken;   // 该服务器的一次性注册令牌（空=登录模式）
    // 该服务器的身份公钥（Ed25519 SPKI PEM 的 base64 正文，单行，不带头尾行）。
    // 每台服务器密钥独立，客户端用它验证该服务器签名（防中间人）；留空=用内置硬编码公钥。
    cfgstr ServerPubKey;
};

// Client runtime settings, loaded from / saved to an INI file.
struct ClientConfig
{
#ifdef _DEBUG
    cfgstr ServerIP = CS("192.168.1.12");
#else
    // Release builds: no hardcoded server; user fills it in config.ini (empty default avoids mojibake)
    cfgstr ServerIP = CS("");
#endif
    // Debug-only server override: DEBUG builds prefer this key, RELEASE builds ignore it.
#ifdef _DEBUG
    cfgstr DebugServerIP = CS("192.168.1.12");
#else
    cfgstr DebugServerIP = CS("");
#endif
    int ServerPort = 51820;

    // 多服务器列表（INI 格式：[Server] Count=N + [ServerN] Name/IP/Port）。
    // servers[0] 即默认/活动服务器，读写时与上面的 ServerIP/ServerPort 保持同步。
    std::vector<ServerEntry> servers;

    // Virtual adapter (TUN) settings
    // VirtualIP: optional. Empty = adopt the server-assigned virtual IP after
    // authentication (multi-user servers always assign one); non-empty = fallback
    // for old servers that do not advertise an address.
    cfgstr VirtualIP = CS("");
    int VirtualPrefix = 24;
    cfgstr DNS = CS("8.8.8.8,1.1.1.1");
    uint32_t MTU = 1400;
    uint8_t Metric = 5;

    // Identity (three-phase auth)
    cfgstr ClientID = CS("user");        // client identifier
    cfgstr RegisterToken = CS("");       // one-time register token (empty = login mode)
    // 默认/活动服务器的身份公钥（与 servers[0].ServerPubKey 同步，空=用内置公钥）
    cfgstr ServerPubKey;

    // ---- 流量分流（[Routing]）----
    // Mode: full = 全流量走隧道（默认，保持旧行为）；split = 国内 IP 直连
    cfgstr RoutingMode = CS("full");
    // 国内列表来源：builtin = 程序目录的 chnroute.txt；也可填 http(s) URL（P2）
    cfgstr ChinaIPList = CS("builtin");
    // 额外直连网段（逗号分隔），用于"连上后仍要访问本地局域网"的场景
    cfgstr BypassSubnets = CS("");
    // 查物理出口用的探测地址，空 = 8.8.8.8
    cfgstr ProbeIP = CS("");

    // ---- 客户端更新（[Update]）----
    // 全部留空 = 不启用更新检查（默认值，升级后老用户行为不变）。
    // 一旦 PolicyURL 与 ReleasePubKey 都有值，启动时就会校验；验签失败即拒绝使用。
    cfgstr UpdatePolicyURL = CS("");   // 策略文件地址
    cfgstr UpdateSigURL = CS("");      // 签名地址；留空 = PolicyURL + ".sig"
    cfgstr ReleasePubKey = CS("");     // 发布公钥 PEM；留空 = 内置（无内置则视为未启用）
};

class Config
{
public:
    cfgstr ini_path;
    cfgstr dir_path;

    Config(cfgstr path, cfgstr dirPath);
    ~Config();

    // 配置根目录：Windows=%APPDATA%；Linux=$XDG_CONFIG_HOME 或 ~/.config
    // （保留原函数名与语义，Windows 端行为不变；程序数据目录用 cfg_app_dir()）
    static cfgstr GetAppDataRoaming();

    // Directory / file helpers
    static bool CreateDir(const cfgstr& dirPath);
    static bool FileExists(const cfgstr& filePath);
    static bool DirExists(const cfgstr& dirPath);
    static std::string ReadTextFile(const cfgstr& filePath);
    static bool WriteTextFile(const cfgstr& filePath, const std::string& content);

    // Load settings from the INI file; creates it with defaults when missing.
    bool LoadClientConfig(ClientConfig& outCfg);
    bool SaveClientConfig(const ClientConfig& cfg);
};
