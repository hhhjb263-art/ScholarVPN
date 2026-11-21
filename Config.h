#pragma once

#include "src/platform/cfgstr.h"

#include <cstdint>
#include <string>
#include <vector>

struct ServerEntry
{
    cfgstr Name;
    cfgstr ServerIP;
    int ServerPort = 51820;
    uint8_t transport = 0;
    cfgstr ClientID;
    cfgstr RegisterToken;
    cfgstr ServerPubKey;
    bool managed = false;
};

struct ClientConfig
{
#ifdef _DEBUG
    cfgstr ServerIP = CS("192.168.1.12");
#else
    cfgstr ServerIP = CS("");
#endif
#ifdef _DEBUG
    cfgstr DebugServerIP = CS("192.168.1.12");
#else
    cfgstr DebugServerIP = CS("");
#endif
    int ServerPort = 51820;

    std::vector<ServerEntry> servers;

    cfgstr VirtualIP = CS("");
    int VirtualPrefix = 24;
    cfgstr DNS = CS("8.8.8.8,1.1.1.1");
    uint32_t MTU = 1400;
    uint8_t Metric = 5;

    cfgstr ClientID = CS("user");
    cfgstr RegisterToken = CS("");
    cfgstr ServerPubKey;

    cfgstr RoutingMode = CS("full");
    cfgstr ChinaIPList = CS("builtin");
    cfgstr BypassSubnets = CS("");
    cfgstr IntranetSubnets = CS("");
    cfgstr ProbeIP = CS("");

    cfgstr UpdatePolicyURL = CS("");
    cfgstr UpdateSigURL = CS("");
    cfgstr ReleasePubKey = CS("MCowBQYDK2VwAyEAc0EJCcbif2w8vPpeutGT+o7bqTFTdOoRSdrDuOJ4xj4=");

    cfgstr ServiceMode = CS("off");
    cfgstr ServiceURL = CS("");
    cfgstr ServicePubKey = CS("");
    cfgstr ServiceFp = CS("");
    cfgstr ServiceClientId = CS("");
    cfgstr ServiceToken = CS("");
    cfgstr ServiceStatus = CS("");
    cfgstr ServiceExpireAt = CS("0");
    cfgstr ServiceQuotaBytes = CS("0");
    cfgstr ServiceUsedBytes = CS("0");
    cfgstr ServiceManagedServers = CS("");
};

namespace scholini {
cfgstr IniGetStr(const cfgstr& path, const cfgstr& sec, const cfgstr& key, const cfgstr& def);
int IniGetInt(const cfgstr& path, const cfgstr& sec, const cfgstr& key, int def);
bool IniSetStr(const cfgstr& path, const cfgstr& sec, const cfgstr& key, const cfgstr& val);
bool IniSetInt(const cfgstr& path, const cfgstr& sec, const cfgstr& key, int val);
void IniDelKey(const cfgstr& path, const cfgstr& sec, const cfgstr& key);
void IniDelSection(const cfgstr& path, const cfgstr& sec);
std::vector<cfgstr> IniSections(const cfgstr& path);
}

class Config
{
public:
    cfgstr ini_path;
    cfgstr dir_path;

    Config(cfgstr path, cfgstr dirPath);
    ~Config();

    static cfgstr GetAppDataRoaming();

    static bool CreateDir(const cfgstr& dirPath);
    static bool FileExists(const cfgstr& filePath);
    static bool DirExists(const cfgstr& dirPath);
    static std::string ReadTextFile(const cfgstr& filePath);
    static bool WriteTextFile(const cfgstr& filePath, const std::string& content);

    bool LoadClientConfig(ClientConfig& outCfg);
    bool SaveClientConfig(const ClientConfig& cfg);
};
