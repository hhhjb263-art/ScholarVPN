#include "update/update_policy.h"

#include <cstdlib>
#include <map>

namespace update {

namespace {

std::string trim(const std::string& s)
{
    const std::size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos)
    {
        return std::string();
    }
    const std::size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

bool next_segment(const std::string& s, std::size_t& pos, int& out)
{
    if (pos >= s.size())
    {
        out = 0;
        return true;
    }
    const std::size_t dot = s.find('.', pos);
    const std::size_t end = (dot == std::string::npos) ? s.size() : dot;
    if (end == pos)
    {
        return false;
    }
    int value = 0;
    for (std::size_t i = pos; i < end; ++i)
    {
        const char c = s[i];
        if (c < '0' || c > '9')
        {
            return false;
        }
        value = value * 10 + (c - '0');
        if (value > 0xFFFF)
        {
            return false;
        }
    }
    out = value;
    pos = (dot == std::string::npos) ? s.size() : dot + 1;
    return true;
}

}

int compare_version(const std::string& a, const std::string& b)
{
    if (a.empty() || b.empty())
    {
        return -2;
    }
    std::size_t pa = 0;
    std::size_t pb = 0;
    for (int i = 0; i < 3; ++i)
    {
        int va = 0;
        int vb = 0;
        if (!next_segment(a, pa, va) || !next_segment(b, pb, vb))
        {
            return -2;
        }
        if (va != vb)
        {
            return (va < vb) ? -1 : 1;
        }
    }
    return 0;
}

// 解析已签名的更新策略文本；新增策略字段从这里扩展
bool parse_policy(const std::string& text, const std::string& os, Policy& out)
{
    out = Policy();

    std::map<std::string, std::string> kv;
    std::size_t pos = 0;
    while (pos <= text.size())
    {
        std::size_t nl = text.find('\n', pos);
        if (nl == std::string::npos)
        {
            nl = text.size();
        }
        const std::string line = trim(text.substr(pos, nl - pos));
        pos = nl + 1;

        if (line.empty() || line[0] == '#' || line[0] == ';')
        {
            continue;
        }
        const std::size_t eq = line.find('=');
        if (eq == std::string::npos)
        {
            continue;
        }
        kv[trim(line.substr(0, eq))] = trim(line.substr(eq + 1));
    }

    auto get = [&kv](const char* key) -> std::string {
        const auto it = kv.find(key);
        return (it == kv.end()) ? std::string() : it->second;
    };

    out.latest = get("latest");
    if (out.latest.empty())
    {
        return false;
    }
    out.minimum = get("minimum");
    out.notes = get("notes");
    out.url = get((os + "_url").c_str());
    if (out.url.empty())
    {
        out.url = get("url");
    }
    out.sha256 = get((os + "_sha256").c_str());
    if (out.sha256.empty())
    {
        out.sha256 = get("sha256");
    }

    std::string sizeStr = get((os + "_size").c_str());
    if (sizeStr.empty())
    {
        sizeStr = get("size");
    }
    if (!sizeStr.empty())
    {
        out.size = std::strtoull(sizeStr.c_str(), nullptr, 10);
    }
    const std::string genStr = get("generated");
    if (!genStr.empty())
    {
        out.generated = std::strtoull(genStr.c_str(), nullptr, 10);
    }

    out.valid = !out.url.empty() && !out.sha256.empty();
    return true;
}

// 由当前版本得出更新决策（无动作/提示/强制），是是否拦住连接的判定点
Decision decide(const Policy& p, const std::string& currentVersion)
{
    Decision d;
    d.policy = p;

    if (!p.valid || p.latest.empty())
    {
        d.action = Action::None;
        d.reason = "策略未配置";
        return d;
    }

    const int cLatest = compare_version(currentVersion, p.latest);
    if (cLatest == -2)
    {
        d.action = Action::Optional;
        d.reason = "当前版本号无法解析";
        return d;
    }

    if (!p.minimum.empty())
    {
        const int cMin = compare_version(currentVersion, p.minimum);
        if (cMin == -1)
        {
            d.action = Action::Forced;
            d.reason = "当前版本低于最低要求 " + p.minimum;
            return d;
        }
        if (cMin == -2)
        {
            d.action = (cLatest < 0) ? Action::Optional : Action::None;
            d.reason = "最低版本号无法解析，按可选处理";
            return d;
        }
    }

    if (cLatest < 0)
    {
        d.action = Action::Optional;
        d.reason = "有新版本 " + p.latest;
        return d;
    }

    d.action = Action::None;
    d.reason = "已是最新";
    return d;
}

const char* action_name(Action a)
{
    switch (a)
    {
    case Action::Forced:   return "forced";
    case Action::Optional: return "optional";
    default:               return "none";
    }
}

}
