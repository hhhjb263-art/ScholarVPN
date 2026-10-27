#pragma once

// ============================================================================
// src/update/update_checker.h —— 一次完整的更新检查
//
// 拆成两层是刻意的：
//   check_text()  纯函数：验签 + 解析 + 决策，不联网 —— 可以单元测试
//   check()       拉取策略与签名，再交给 check_text
//
// 状态语义（决定客户端能不能用）：
//   Ok                → 正常，按 decision 走
//   SignatureInvalid  → **拒绝使用**（用户硬要求：验签不通过就不让用）
//   NetworkFailed     → 可用上次缓存 / 放行（断网不该废掉程序）
//   PolicyInvalid     → 签名对但内容残缺，按"未配置"处理（不阻塞）
// ============================================================================

#include "update/update_policy.h"

#include <cstdint>
#include <string>

namespace update {

enum class CheckStatus {
    Ok,
    SignatureInvalid,
    NetworkFailed,
    PolicyInvalid
};

struct CheckResult {
    CheckStatus status = CheckStatus::NetworkFailed;
    Decision decision;
    std::string error;
    std::uint64_t generated = 0;
};

// 纯逻辑：验签 + 解析 + 决策（不联网，可单测）
CheckResult check_text(const std::string& policyBody,
                       const std::string& signatureBase64,
                       const std::string& releasePublicKeyPem,
                       const std::string& os,
                       const std::string& currentVersion);

// 完整检查：拉 policyUrl 与 signatureUrl，再走 check_text
CheckResult check(const std::string& policyUrl,
                  const std::string& signatureUrl,
                  const std::string& releasePublicKeyPem,
                  const std::string& os,
                  const std::string& currentVersion,
                  int timeoutMs = 5000);

const char* status_name(CheckStatus s);

} // namespace update
