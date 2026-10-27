#pragma once

// ============================================================================
// src/update/update_policy.h —— 客户端更新策略的解析与决策
//
// 策略由服务端侧托管（静态文件，客户端拉取后**验签**再解析），格式刻意用
// 最简单的 key = value：不需要 JSON 解析器，出问题时肉眼就能看懂。
//
// 决策逻辑放在客户端是刻意的：
//   服务端只提供 latest / minimum 两个阈值，怎么判定由客户端算。
//   好处是策略文件可以被缓存、被 CDN 分发，服务端不需要为每次查询做计算，
//   也不必为此改动 webadmin（scholarvpn.homes 那套后台）。
// ============================================================================

#include <cstdint>
#include <string>

namespace update {

enum class Action {
    None,       // 已是最新（或策略未配置）
    Optional,   // 有新版本，可忽略
    Forced      // 低于最低版本，必须升级才能使用
};

struct Policy {
    std::string latest;      // 最新版本，如 "1.7.0"
    std::string minimum;     // 最低可用版本；低于它强制升级
    std::string notes;       // 更新说明（单行）
    std::string url;         // 当前平台的安装包地址
    std::string sha256;      // 安装包哈希
    std::uint64_t size = 0;  // 安装包字节数（0 = 未知）
    std::uint64_t generated = 0;   // 策略生成时间（Unix 秒），用于防重放旧策略
    bool valid = false;
};

struct Decision {
    Action action = Action::None;
    Policy policy;
    std::string reason;   // 供日志与界面提示
};

// 语义化版本比较（只处理数字段，遇非数字返回 -2）：
//   a < b → -1    相等 → 0    a > b → 1    解析失败 → -2
// ⚠️ 必须按数值比较："1.10.0" 比 "1.9.0" 新，字符串比较会判反。
int compare_version(const std::string& a, const std::string& b);

// 解析策略文本。os 形如 "win-x64" / "linux-x64"，用于挑对应平台的 url/sha256/size。
// 返回 false 表示找不到 latest（视为策略无效）。
bool parse_policy(const std::string& text, const std::string& os, Policy& out);

// 结合当前版本给出决策
Decision decide(const Policy& p, const std::string& currentVersion);

const char* action_name(Action a);

} // namespace update
