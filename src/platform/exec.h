#pragma once

// ============================================================================
// src/platform/exec.h —— 最小化的外部命令执行（Linux 平台的 ip / resolvectl）
//
// Linux 端的地址/路由/DNS 操作走 `ip` / `resolvectl` 命令，而不是 netlink：
//   - 代码量从 ~600 行降到 ~200 行，出问题可以直接在命令行复现同一串命令；
//   - 性能不在这条路径上（连接/断连各执行几次，不是热路径）。
// Windows 分支给出空实现，保证同一份代码能两端编过。
// ============================================================================

#include <string>
#include <vector>

#if defined(_WIN32)

inline int run_cmd(const std::string& /*cmd*/, std::string* out = nullptr)
{
    if (out) out->clear();
    return -1;
}

inline std::vector<std::string> run_cmd_lines(const std::string& /*cmd*/)
{
    return {};
}

#else

#include <cstdio>
#include <sys/wait.h>

// 执行 shell 命令；返回退出码（-1 = 无法启动）。out 非空时收集 stdout。
inline int run_cmd(const std::string& cmd, std::string* out = nullptr)
{
    FILE* f = ::popen(cmd.c_str(), "r");
    if (f == nullptr)
    {
        return -1;
    }
    if (out != nullptr)
    {
        out->clear();
    }
    char buf[512];
    while (std::fgets(buf, sizeof(buf), f) != nullptr)
    {
        if (out != nullptr)
        {
            *out += buf;
        }
    }
    const int rc = ::pclose(f);
    if (rc == -1)
    {
        return -1;
    }
    return WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
}

// 逐行收集 stdout（去空行）
inline std::vector<std::string> run_cmd_lines(const std::string& cmd)
{
    std::vector<std::string> lines;
    std::string all;
    if (run_cmd(cmd, &all) != 0 && all.empty())
    {
        return lines;
    }
    std::string cur;
    for (char ch : all)
    {
        if (ch == '\n')
        {
            if (!cur.empty() && cur.back() == '\r') cur.pop_back();
            if (!cur.empty()) lines.push_back(cur);
            cur.clear();
        }
        else
        {
            cur.push_back(ch);
        }
    }
    if (!cur.empty()) lines.push_back(cur);
    return lines;
}

#endif
