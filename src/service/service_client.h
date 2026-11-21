#pragma once

#include "../service/machine_id.h"

#include <cstdint>
#include <string>
#include <vector>

namespace service {

struct Credentials {
    std::string fp;
    std::string client_id;
    std::string token;
    std::string status;
    std::uint64_t expire_at = 0;
    std::uint64_t quota_bytes = 0;
    std::uint64_t used_bytes = 0;
    std::string limit_kind;
    std::uint64_t remaining = 0;
    bool valid = false;
    std::string error;
};

struct Verdict {
    bool blocked = false;
    std::string reason;
};

Credentials parse_credentials(const std::string& iniText);

Verdict evaluate(const Credentials& c, std::uint64_t nowUnix);

bool verify_signature(const std::string& body, const std::string& sigBase64,
                      const std::string& pubKeyBase64);

Credentials register_trial(const std::string& url, const std::string& pubKeyBase64,
                           const MachineInfo& info, int timeoutMs = 5000);

Credentials fetch_status(const std::string& url, const std::string& pubKeyBase64,
                         int timeoutMs = 5000);

struct ManagedServer {
    std::string addr;
    std::string pubkey_b64;
    std::string remark;
};
std::vector<ManagedServer> fetch_server_list(const std::string& listUrl,
                                             const std::string& sigUrl,
                                             const std::string& pubKeyBase64,
                                             std::string& error,
                                             int timeoutMs = 5000);

bool split_addr(const std::string& addr, std::string& ip, int& port);

}
