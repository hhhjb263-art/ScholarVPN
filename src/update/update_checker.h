#pragma once

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

CheckResult check_text(const std::string& policyBody,
                       const std::string& signatureBase64,
                       const std::string& releasePublicKeyPem,
                       const std::string& os,
                       const std::string& currentVersion);

CheckResult check(const std::string& policyUrl,
                  const std::string& signatureUrl,
                  const std::string& releasePublicKeyPem,
                  const std::string& os,
                  const std::string& currentVersion,
                  int timeoutMs = 5000);

const char* status_name(CheckStatus s);

}
