#pragma once

// ============================================================================
// src/service/service_client.h —— 受管服务客户端（试用申请 / 状态同步 / 列表下发）
//
// 对应 docs/受管服务与试用授权方案.md 2.3/2.4。设计要点：
//   - 可信性由 service.key 的 Ed25519 签名保证：个人凭据在响应头
//     X-Service-Signature（对响应原始字节的签名，base64），服务器列表用分离的
//     .sig 文件。验签不通过的内容一律拒绝，与更新系统同一铁律。
//   - 纯逻辑（parse/evaluate/verify）与网络（fetch）拆开：前者可单测。
//   - 不含 Qt；AppBridge 负责线程与 UI 转接。
// ============================================================================

#include "../service/machine_id.h"

#include <cstdint>
#include <string>
#include <vector>

namespace service {

// 个人凭据（broker 响应 INI 的解析结果）
struct Credentials {
    std::string fp;              // 64hex 机器指纹
    std::string client_id;       // trial-xxxxxxxx
    std::string token;           // 一次性注册令牌（仅注册响应携带）
    std::string status;          // trial | approved | rejected
    std::uint64_t expire_at = 0;    // unix 秒；0 = 不限（正式）
    std::uint64_t quota_bytes = 0;  // 0 = 不限
    std::uint64_t used_bytes = 0;
    std::string limit_kind;         // 服务器选定的限制维度：days | bytes | none
    std::uint64_t remaining = 0;    // 该维度剩余量（天/字节）；0 = 已超限
    bool valid = false;
    std::string error;           // 解析/验签失败原因
};

// 闸门判定结果
struct Verdict {
    bool blocked = false;        // true = 禁止连接（与强制更新同一处理路径）
    std::string reason;          // 界面展示用
};

// ---- 纯逻辑（可单测）----

// 解析凭据 INI（key = value，# 注释；字段缺失不致命，valid 以 client_id 判）
Credentials parse_credentials(const std::string& iniText);

// 闸门判定：rejected / 试用到期 / 配额耗尽 → blocked
// nowUnix = 当前 unix 秒（测试可注入）
Verdict evaluate(const Credentials& c, std::uint64_t nowUnix);

// 验签：body 原始字节 + base64 签名 + 服务公钥（SPKI DER 的 base64 单行，
// 与 config.ini ServerPubKey 同格式；内部包成 PEM 交给 OpenSSL）
bool verify_signature(const std::string& body, const std::string& sigBase64,
                      const std::string& pubKeyBase64);

// ---- 网络 ----

// 申请/换发试用。url = broker 的 /trial/register 完整地址（由 AppBridge 拼）。
// 成功时 Credentials.valid=true 且签名已验证；失败时 error 指明原因。
Credentials register_trial(const std::string& url, const std::string& pubKeyBase64,
                           const MachineInfo& info, int timeoutMs = 5000);

// 状态同步（每次启动/手动刷新）。url = /trial/status?fp=... 完整地址。
Credentials fetch_status(const std::string& url, const std::string& pubKeyBase64,
                         int timeoutMs = 5000);

// 服务器列表（静态 server-list.ini + .sig）
struct ManagedServer {
    std::string addr;        // ip:port
    std::string pubkey_b64;  // 该服务器签名公钥（SPKI DER base64）
    std::string remark;      // 展示名
};
// 验签通过才返回内容；失败返回空 vector（error 输出原因）
std::vector<ManagedServer> fetch_server_list(const std::string& listUrl,
                                             const std::string& sigUrl,
                                             const std::string& pubKeyBase64,
                                             std::string& error,
                                             int timeoutMs = 5000);

// "1.2.3.4:51820" → (ip, port)；port 缺省 51820。合法返回 true。
bool split_addr(const std::string& addr, std::string& ip, int& port);

} // namespace service
