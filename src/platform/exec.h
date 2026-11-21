#pragma once

#include <string>
#include <vector>

#if defined(_WIN32)

inline int run_cmd(const std::string&, std::string* out = nullptr)
{
    if (out) out->clear();
    return -1;
}

inline std::vector<std::string> run_cmd_lines(const std::string&)
{
    return {};
}

#else

#include <cstdio>
#include <sys/wait.h>

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
