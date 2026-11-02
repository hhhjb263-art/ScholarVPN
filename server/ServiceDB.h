// ============================================================================
// server/ServiceDB.h —— 受管服务数据库（sqlite）服务端侧访问层
//
// SQL 唯一所在（对应客户端工具链的 tools/broker/db.py，见
// docs/受管服务与试用授权方案.md 8.2）。职责：
//   · 登录校验：读 trials 的状态/到期/配额（client_id 不在表里 = 手工注册的
//     老用户，不受任何约束）
//   · 数据面：会话流量增量内存聚合，flush() 批量写回 used_bytes
//   · 审计：域名命中内存聚合（day+client_id+domain），flush() 批量 upsert
//   · 黑名单：内存缓存（60s 重读），后缀匹配
// 库打不开（路径不存在/权限）时所有能力自动停用——不得影响普通用户上线。
// ============================================================================
#pragma once

#include <chrono>
#include <map>
#include <mutex>
#include <set>
#include <string>

struct sqlite3;

namespace service {

struct TrialInfo {
    bool found = false;          // client_id 是否在 trials 里
    std::string status;          // trial | approved | rejected
    long long expire_at = 0;     // unix 秒；0 = 不限（正式）
    long long quota_bytes = 0;   // 0 = 不限（正式）
    long long used_bytes = 0;
};

// 从隧道内 IPv4 包提取访问域名：
//   UDP dst:53 → DNS 查询的 QNAME；TCP 且载荷以 TLS ClientHello 开头 → SNI。
// 分片/短包/非明文（QUIC、ESNI 等）一律返回 false，静默跳过——审计是尽力而为，
// 绝不能因为解析拖慢或阻断转发路径。
bool extract_domain(const unsigned char* pkt, size_t len, std::string& out);

class ServiceDB {
public:
    bool open(const std::string& path);   // 失败 = 能力停用（available()==false）
    void close();
    ~ServiceDB();

    bool available() const { return m_db != nullptr; }

    TrialInfo get_trial(const std::string& client_id);

    // 数据面字节增量（线程安全；内存聚合，flush() 批量落库）。
    // 只对 trials 里存在的 client_id 有效（避免为任意冒填名字插行）。
    void add_used(const std::string& client_id, long long delta);
    // 域名审计命中（内存聚合，flush() 批量 upsert audit_domains）
    void audit_hit(const std::string& client_id, const std::string& domain);
    // 把内存聚合写入 DB（心跳线程周期调用；close/进程退出前也调）
    void flush();

    // 黑名单（type: domain=域名（支持 * 通配，后缀匹配）/ ip=目的 IPv4（精确）/
    // machine=整机（client_id 精确））
    bool domain_blocked(const std::string& domain);
    bool ip_blocked(std::uint32_t dst_host_order);
    bool machine_blocked(const std::string& client_id);

private:
    void load_blacklist_locked();   // 调用方须持有 m_mu

    sqlite3* m_db = nullptr;
    std::mutex m_mu;
    std::map<std::string, long long> m_pendingUsed;
    std::map<std::string, long long> m_pendingAudit;   // key = day \x1f client_id \x1f domain
    std::set<std::string> m_blacklist;                 // 域名（小写，*前缀已剥除）
    std::set<std::string> m_blIps;                     // 点分十进制字符串
    std::set<std::string> m_blMachines;                // client_id
    std::chrono::steady_clock::time_point m_blacklistAt{};
};

} // namespace service
