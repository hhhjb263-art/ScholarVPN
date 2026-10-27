#include "platform/iplist.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace iplist {

namespace {

bool is_comment(const std::string& line)
{
    return !line.empty() && (line[0] == '#' || line[0] == ';');
}

} // namespace

void parse_text(const std::string& text, std::vector<cidr::Cidr>& out, Stats* stats)
{
    Stats local;
    Stats& st = (stats != nullptr) ? *stats : local;

    std::size_t pos = 0;
    while (pos <= text.size())
    {
        std::size_t nl = text.find('\n', pos);
        if (nl == std::string::npos)
        {
            nl = text.size();
        }
        std::string line = text.substr(pos, nl - pos);
        pos = nl + 1;

        // 去掉 CR（Windows 换行）与首尾空白
        while (!line.empty() && (line.back() == '\r' || line.back() == ' ' || line.back() == '\t'))
        {
            line.pop_back();
        }
        const std::size_t b = line.find_first_not_of(" \t");
        if (b != std::string::npos)
        {
            line.erase(0, b);
        }

        if (line.empty())
        {
            continue;   // 空行不计入任何统计
        }
        ++st.lines;

        if (is_comment(line))
        {
            ++st.comments;
            continue;
        }

        cidr::Cidr c{};
        if (!cidr::parse(line, c))
        {
            ++st.malformed;   // 脏数据：计数但不中断
            continue;
        }
        cidr::normalize(c);
        out.push_back(c);
        ++st.valid;
    }
}

bool load_file(const cfgstr& path, std::vector<cidr::Cidr>& out, Stats* stats)
{
#if defined(_WIN32)
    FILE* f = ::_wfopen(path.c_str(), L"rb");
#else
    FILE* f = std::fopen(path.c_str(), "rb");
#endif
    if (f == nullptr)
    {
        return false;
    }

    std::string text;
    char buf[4096];
    std::size_t n = 0;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0)
    {
        text.append(buf, n);
    }
    std::fclose(f);

    parse_text(text, out, stats);
    return true;
}

void sort_unique(std::vector<cidr::Cidr>& list)
{
    std::sort(list.begin(), list.end(), cidr::less);
    list.erase(std::unique(list.begin(), list.end(),
                           [](const cidr::Cidr& a, const cidr::Cidr& b) {
                               return a.addr == b.addr && a.prefix == b.prefix;
                           }),
               list.end());
}

} // namespace iplist
