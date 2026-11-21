#pragma once

#include <cstdint>
#include <string>

namespace update {

enum class Action {
    None,
    Optional,
    Forced
};

struct Policy {
    std::string latest;
    std::string minimum;
    std::string notes;
    std::string url;
    std::string sha256;
    std::uint64_t size = 0;
    std::uint64_t generated = 0;
    bool valid = false;
};

struct Decision {
    Action action = Action::None;
    Policy policy;
    std::string reason;
};

int compare_version(const std::string& a, const std::string& b);

bool parse_policy(const std::string& text, const std::string& os, Policy& out);

Decision decide(const Policy& p, const std::string& currentVersion);

const char* action_name(Action a);

}
