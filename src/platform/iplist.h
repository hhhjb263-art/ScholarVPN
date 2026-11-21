#pragma once

#include "platform/cfgstr.h"
#include "platform/cidr.h"

#include <cstddef>
#include <string>
#include <vector>

namespace iplist {

struct Stats {
    std::size_t lines = 0;
    std::size_t valid = 0;
    std::size_t comments = 0;
    std::size_t malformed = 0;
};

void parse_text(const std::string& text, std::vector<cidr::Cidr>& out, Stats* stats = nullptr);

bool load_file(const cfgstr& path, std::vector<cidr::Cidr>& out, Stats* stats = nullptr);

void sort_unique(std::vector<cidr::Cidr>& list);

}
