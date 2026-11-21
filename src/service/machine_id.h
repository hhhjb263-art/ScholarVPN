#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace service {

struct MachineInfo {
    std::string fp;
    std::string machine_id;
    std::string os;
    std::string cpu;
    std::uint64_t ram_mb = 0;
    std::string mac_hash;
};

MachineInfo collect_machine_info();

std::string fingerprint_of(const std::string& machine_id);

std::string hash_macs(const std::vector<std::string>& macs_any_format);

}
