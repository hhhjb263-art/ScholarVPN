#pragma once

#include <chrono>
#include <map>
#include <mutex>
#include <set>
#include <string>

struct sqlite3;

namespace service {

struct TrialInfo {
    bool found = false;
    std::string status;
    long long expire_at = 0;
    long long quota_bytes = 0;
    long long used_bytes = 0;
};

bool extract_domain(const unsigned char* pkt, size_t len, std::string& out);

class ServiceDB {
public:
    bool open(const std::string& path);
    void close();
    ~ServiceDB();

    bool available() const { return m_db != nullptr; }

    TrialInfo get_trial(const std::string& client_id);

    void add_used(const std::string& client_id, long long delta);
    void audit_hit(const std::string& client_id, const std::string& domain);
    void flush();

    bool domain_blocked(const std::string& domain);
    bool ip_blocked(std::uint32_t dst_host_order);
    bool machine_blocked(const std::string& client_id);

private:
    void load_blacklist_locked();

    sqlite3* m_db = nullptr;
    std::mutex m_mu;
    std::map<std::string, long long> m_pendingUsed;
    std::map<std::string, long long> m_pendingAudit;
    std::set<std::string> m_blacklist;
    std::set<std::string> m_blIps;
    std::set<std::string> m_blMachines;
    std::chrono::steady_clock::time_point m_blacklistAt{};
};

}
