#pragma once

// ============================================================================
// src/platform/iplist.h —— 国内 IP 段列表加载
//
// 数据格式刻意选最笨的纯文本：每行一个 CIDR，`#` 或 `;` 开头为注释。
// 理由：不需要 JSON 解析器；出问题时用 grep 就能定位；坏行跳过并计数，
// 绝不让一条脏数据导致整个分流失效（否则用户会遇到"只绕了一半"的诡异状态）。
// ============================================================================

#include "platform/cfgstr.h"
#include "platform/cidr.h"

#include <cstddef>
#include <string>
#include <vector>

namespace iplist {

struct Stats {
    std::size_t lines = 0;      // 总行数
    std::size_t valid = 0;      // 成功解析的 CIDR 数
    std::size_t comments = 0;   // 注释行
    std::size_t malformed = 0;  // 无法解析的非空行（数据损坏的指标）
};

// 从文本解析（原地追加到 out）
void parse_text(const std::string& text, std::vector<cidr::Cidr>& out, Stats* stats = nullptr);

// 读文件并解析。文件不存在/读失败返回 false，out 内容不变。
bool load_file(const cfgstr& path, std::vector<cidr::Cidr>& out, Stats* stats = nullptr);

// 排序并按数值去重（远程列表常见重复条目）
void sort_unique(std::vector<cidr::Cidr>& list);

} // namespace iplist
