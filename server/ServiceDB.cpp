// ============================================================================
// server/ServiceDB.cpp —— 受管服务数据库访问（SQL 全部在本文件）
// ============================================================================
#include "ServiceDB.h"

#include <sqlite3.h>

#include <cctype>
#include <cstdio>
#include <ctime>

namespace service {

bool ServiceDB::open(const std::string& path)
{
    close();
    if (sqlite3_open(path.c_str(), &m_db) != SQLITE_OK) {
        close();
        return false;
    }
    sqlite3_busy_timeout(m_db, 3000);   // broker/webadmin 同库并发写
    char* err = nullptr;
    sqlite3_exec(m_db, "PRAGMA journal_mode=WAL;", nullptr, nullptr, &err);
    sqlite3_free(err);
    return true;
}

void ServiceDB::close()
{
    if (m_db != nullptr) {
        flush();
        sqlite3_close(m_db);
        m_db = nullptr;
    }
}

ServiceDB::~ServiceDB()
{
    close();
}

TrialInfo ServiceDB::get_trial(const std::string& client_id)
{
    TrialInfo t;
    if (m_db == nullptr || client_id.empty())
        return t;
    sqlite3_stmt* st = nullptr;
    if (sqlite3_prepare_v2(m_db,
                           "SELECT status, expire_at, quota_bytes, used_bytes"
                           " FROM trials WHERE client_id = ?",
                           -1, &st, nullptr) != SQLITE_OK) {
        return t;
    }
    sqlite3_bind_text(st, 1, client_id.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st) == SQLITE_ROW) {
        const char* status = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
        t.found = true;
        t.status = (status != nullptr) ? status : "";
        t.expire_at = sqlite3_column_int64(st, 1);
        t.quota_bytes = sqlite3_column_int64(st, 2);
        t.used_bytes = sqlite3_column_int64(st, 3);
    }
    sqlite3_finalize(st);
    return t;
}

void ServiceDB::add_used(const std::string& client_id, long long delta)
{
    if (m_db == nullptr || client_id.empty() || delta <= 0)
        return;
    std::lock_guard<std::mutex> lk(m_mu);
    m_pendingUsed[client_id] += delta;
}

void ServiceDB::audit_hit(const std::string& client_id, const std::string& domain)
{
    if (m_db == nullptr || client_id.empty() || domain.empty())
        return;
    std::lock_guard<std::mutex> lk(m_mu);
    char day[16] = { 0 };
    const std::time_t now = std::time(nullptr);
    std::tm tmv{};
    localtime_r(&now, &tmv);
    std::snprintf(day, sizeof(day), "%04d-%02d-%02d",
                  tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday);
    std::string key = day;
    key += '\x1f';
    key += client_id;
    key += '\x1f';
    key += domain;
    m_pendingAudit[key] += 1;
}

void ServiceDB::flush()
{
    if (m_db == nullptr)
        return;
    std::map<std::string, long long> used;
    std::map<std::string, long long> audit;
    {
        std::lock_guard<std::mutex> lk(m_mu);
        used.swap(m_pendingUsed);
        audit.swap(m_pendingAudit);
    }
    for (const auto& kv : used) {
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(m_db,
                               "UPDATE trials SET used_bytes = used_bytes + ?"
                               " WHERE client_id = ?",
                               -1, &st, nullptr) == SQLITE_OK) {
            sqlite3_bind_int64(st, 1, kv.second);
            sqlite3_bind_text(st, 2, kv.first.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_step(st);
            sqlite3_finalize(st);
        }
    }
    for (const auto& kv : audit) {
        // key = day \x1f client_id \x1f domain
        const size_t p1 = kv.first.find('\x1f');
        const size_t p2 = (p1 == std::string::npos) ? std::string::npos
                                                    : kv.first.find('\x1f', p1 + 1);
        if (p1 == std::string::npos || p2 == std::string::npos)
            continue;
        const std::string day = kv.first.substr(0, p1);
        const std::string cid = kv.first.substr(p1 + 1, p2 - p1 - 1);
        const std::string dom = kv.first.substr(p2 + 1);
        sqlite3_stmt* st = nullptr;
        if (sqlite3_prepare_v2(m_db,
                               "INSERT INTO audit_domains(day, client_id, domain, hits)"
                               " VALUES(?,?,?,?)"
                               " ON CONFLICT(day, client_id, domain)"
                               " DO UPDATE SET hits = hits + ?",
                               -1, &st, nullptr) == SQLITE_OK) {
            sqlite3_bind_text(st, 1, day.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 2, cid.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_text(st, 3, dom.c_str(), -1, SQLITE_TRANSIENT);
            sqlite3_bind_int64(st, 4, kv.second);
            sqlite3_bind_int64(st, 5, kv.second);
            sqlite3_step(st);
            sqlite3_finalize(st);
        }
    }
}

void ServiceDB::load_blacklist_locked()
{
    const auto now = std::chrono::steady_clock::now();
    if (std::chrono::duration_cast<std::chrono::seconds>(now - m_blacklistAt).count() < 60)
        return;   // 60s 内用缓存
    m_blacklistAt = now;
    m_blacklist.clear();
    m_blIps.clear();
    m_blMachines.clear();
    sqlite3_stmt* st = nullptr;
    // type 列是后加的（迁移默认 domain）——列不存在时按全域名处理
    if (sqlite3_prepare_v2(m_db,
                           "SELECT domain, type FROM blacklist"
                           " ORDER BY rowid LIMIT 100000",
                           -1, &st, nullptr) != SQLITE_OK) {
        return;
    }
    while (sqlite3_step(st) == SQLITE_ROW) {
        const char* d = reinterpret_cast<const char*>(sqlite3_column_text(st, 0));
        if (d == nullptr)
            continue;
        const char* ty = reinterpret_cast<const char*>(sqlite3_column_text(st, 1));
        const std::string type = (ty != nullptr) ? ty : "domain";
        if (type == "ip") {
            m_blIps.insert(d);
        } else if (type == "machine") {
            m_blMachines.insert(d);
        } else {
            std::string dom = d;
            if (dom.rfind("*.", 0) == 0)
                dom = dom.substr(2);
            if (!dom.empty())
                m_blacklist.insert(dom);
        }
    }
    sqlite3_finalize(st);
}

bool ServiceDB::domain_blocked(const std::string& domain)
{
    if (m_db == nullptr || domain.empty())
        return false;
    std::lock_guard<std::mutex> lk(m_mu);
    load_blacklist_locked();
    if (m_blacklist.empty())
        return false;
    // 空列表守卫只看域名类型；ip/machine 各自在自己入口判断
    if (m_blacklist.count(domain) != 0)
        return true;
    // 子域后缀匹配：a.example.com 命中 example.com（通配与裸域语义一致）
    for (const auto& e : m_blacklist) {
        if (domain.size() > e.size() + 1 &&
            domain.compare(domain.size() - e.size(), e.size(), e) == 0 &&
            domain[domain.size() - e.size() - 1] == '.') {
            return true;
        }
    }
    return false;
}

bool ServiceDB::ip_blocked(std::uint32_t dst_host_order)
{
    if (m_db == nullptr)
        return false;
    char ip[16] = { 0 };
    std::snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
                  (dst_host_order >> 24) & 0xFF, (dst_host_order >> 16) & 0xFF,
                  (dst_host_order >> 8) & 0xFF, dst_host_order & 0xFF);
    std::lock_guard<std::mutex> lk(m_mu);
    load_blacklist_locked();
    return !m_blIps.empty() && m_blIps.count(ip) != 0;
}

bool ServiceDB::machine_blocked(const std::string& client_id)
{
    if (m_db == nullptr || client_id.empty())
        return false;
    std::lock_guard<std::mutex> lk(m_mu);
    load_blacklist_locked();
    return !m_blMachines.empty() && m_blMachines.count(client_id) != 0;
}

// ---------------------------------------------------------------------------
// 域名提取：DNS QNAME / TLS SNI（全部带边界检查，畸形即放弃）
// ---------------------------------------------------------------------------

// DNS QNAME：IHL → UDP 头（8）→ dst port 53 → 头 12 字节 → QDCOUNT>=1 → 标签序列
static bool extract_dns_name(const unsigned char* pkt, size_t len,
                             size_t l4, std::string& out)
{
    if (len < l4 + 8)
        return false;
    const uint16_t dport = static_cast<uint16_t>((pkt[l4 + 2] << 8) | pkt[l4 + 3]);
    if (dport != 53)
        return false;
    const size_t dns = l4 + 8;
    if (len < dns + 12)
        return false;
    const uint16_t qd = static_cast<uint16_t>((pkt[dns + 4] << 8) | pkt[dns + 5]);
    if (qd < 1)
        return false;
    size_t p = dns + 12;
    std::string name;
    for (int guard = 0; guard < 16; ++guard) {   // 标签数上限，防畸形包打满循环
        if (p >= len)
            return false;
        const uint8_t l = pkt[p];
        p += 1;
        if (l == 0)
            break;
        if (p + l > len)
            return false;
        if (!name.empty())
            name += '.';
        for (uint8_t k = 0; k < l; ++k)
            name += static_cast<char>(std::tolower(pkt[p + k]));
        p += l;
    }
    if (name.empty() || name.size() > 253)
        return false;
    out = name;
    return true;
}

// TLS SNI：TCP 载荷必须以 TLS 握手记录（0x16 0x03）开头且内层是 ClientHello(0x01)。
// 应用数据记录（0x17）直接跳过——SNI 只出现在每条流的第一包。
static bool extract_sni(const unsigned char* pkt, size_t len,
                        size_t l4, std::string& out)
{
    if (len < l4 + 20)
        return false;
    const size_t doff = static_cast<size_t>(pkt[l4 + 12] >> 4) * 4;
    if (doff < 20 || len < l4 + doff + 1)
        return false;
    const unsigned char* t = pkt + l4 + doff;
    const size_t tlen = len - (l4 + doff);
    if (tlen < 5 || t[0] != 0x16 || t[1] != 0x03)
        return false;
    size_t hs = 5;   // TLS 记录头
    if (hs + 4 > tlen || t[hs] != 0x01)
        return false;   // 非 ClientHello
    // ClientHello：handshake_len(3) 后 = version(2) random(32) session_id...
    size_t p = hs + 4 + 2 + 32;
    if (p + 1 > tlen)
        return false;
    const uint8_t sid = t[p];
    p += 1 + sid;
    if (p + 2 > tlen)
        return false;
    const uint16_t cs = static_cast<uint16_t>((t[p] << 8) | t[p + 1]);
    p += 2 + cs;
    if (p + 1 > tlen)
        return false;
    const uint8_t comp = t[p];
    p += 1 + comp;
    if (p + 2 > tlen)
        return false;
    const uint16_t extTotal = static_cast<uint16_t>((t[p] << 8) | t[p + 1]);
    p += 2;
    const size_t extEnd = (p + extTotal > tlen) ? tlen : p + extTotal;
    while (p + 4 <= extEnd) {
        const uint16_t et = static_cast<uint16_t>((t[p] << 8) | t[p + 1]);
        const uint16_t el = static_cast<uint16_t>((t[p + 2] << 8) | t[p + 3]);
        p += 4;
        if (el > extEnd - p)
            break;
        if (et == 0x0000 && el >= 5) {   // server_name 扩展
            // server_name_list: list_len(2) name_type(1)=0 host_len(2) host
            if (t[p + 2] == 0) {
                const uint16_t hl = static_cast<uint16_t>((t[p + 3] << 8) | t[p + 4]);
                if (hl > 0 && el >= 5u + hl && p + 5 + hl <= extEnd) {
                    std::string host;
                    for (uint16_t k = 0; k < hl; ++k)
                        host += static_cast<char>(std::tolower(t[p + 5 + k]));
                    if (!host.empty()) {
                        out = host;
                        return true;
                    }
                }
            }
            break;
        }
        p += el;
    }
    return false;
}

bool extract_domain(const unsigned char* pkt, size_t len, std::string& out)
{
    out.clear();
    if (pkt == nullptr || len < 20 || (pkt[0] >> 4) != 4)
        return false;
    const size_t ihl = static_cast<size_t>(pkt[0] & 0x0F) * 4;
    if (ihl < 20 || len < ihl)
        return false;
    const uint8_t proto = pkt[9];
    if (proto == 17)
        return extract_dns_name(pkt, len, ihl, out);
    if (proto == 6)
        return extract_sni(pkt, len, ihl, out);
    return false;
}

} // namespace service
