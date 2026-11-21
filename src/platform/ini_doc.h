#pragma once

#include <cstdio>
#include <cstddef>
#include <fstream>
#include <ios>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

namespace scholinux
{

inline bool IniIEquals(const std::string& a, const std::string& b)
{
    if (a.size() != b.size())
    {
        return false;
    }
    for (std::size_t i = 0; i < a.size(); ++i)
    {
        char ca = a[i];
        char cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca = static_cast<char>(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = static_cast<char>(cb - 'A' + 'a');
        if (ca != cb)
        {
            return false;
        }
    }
    return true;
}

inline std::string IniTrim(const std::string& s)
{
    const std::size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos)
    {
        return std::string();
    }
    const std::size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

inline std::string ReadFileAsUtf8(const std::string& path)
{
    std::ifstream in(path, std::ios::binary);
    if (!in)
    {
        return std::string();
    }
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

    auto utf16_to_utf8 = [](const std::string& src, bool little) {
        std::string out;
        out.reserve(src.size());
        for (std::size_t i = 0; i + 1 < src.size(); i += 2)
        {
            const unsigned char lo = static_cast<unsigned char>(src[little ? i : i + 1]);
            const unsigned char hi = static_cast<unsigned char>(src[little ? i + 1 : i]);
            const unsigned int cp = static_cast<unsigned int>(lo) | (static_cast<unsigned int>(hi) << 8);
            if (cp < 0x80)
            {
                out.push_back(static_cast<char>(cp));
            }
            else if (cp < 0x800)
            {
                out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
            }
            else
            {
                out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
            }
        }
        return out;
    };

    if (raw.size() >= 3 && static_cast<unsigned char>(raw[0]) == 0xEF &&
        static_cast<unsigned char>(raw[1]) == 0xBB && static_cast<unsigned char>(raw[2]) == 0xBF)
    {
        return raw.substr(3);
    }
    if (raw.size() >= 2 && static_cast<unsigned char>(raw[0]) == 0xFF &&
        static_cast<unsigned char>(raw[1]) == 0xFE)
    {
        return utf16_to_utf8(raw.substr(2), true);
    }
    if (raw.size() >= 2 && static_cast<unsigned char>(raw[0]) == 0xFE &&
        static_cast<unsigned char>(raw[1]) == 0xFF)
    {
        return utf16_to_utf8(raw.substr(2), false);
    }
    return raw;
}

class IniDoc
{
public:
    enum Kind { Other = 0, Section, KeyValue };

    struct Line
    {
        Kind kind = Other;
        std::string text;
        std::string section;
        std::string key;
        std::string value;
    };

    bool load(const std::string& path)
    {
        m_lines.clear();
        const std::string text = ReadFileAsUtf8(path);
        std::istringstream ss(text);
        std::string raw;
        std::string cur;
        while (std::getline(ss, raw))
        {
            if (!raw.empty() && raw.back() == '\r')
            {
                raw.pop_back();
            }
            Line line;
            line.text = raw;
            const std::string trimmed = IniTrim(raw);
            if (!trimmed.empty() && trimmed.front() == '[' && trimmed.back() == ']')
            {
                line.kind = Section;
                line.section = trimmed.substr(1, trimmed.size() - 2);
                cur = line.section;
            }
            else if (!trimmed.empty() && trimmed.front() != ';' && trimmed.front() != '#')
            {
                const std::size_t eq = trimmed.find('=');
                if (eq != std::string::npos)
                {
                    line.kind = KeyValue;
                    line.section = cur;
                    line.key = IniTrim(trimmed.substr(0, eq));
                    line.value = IniTrim(trimmed.substr(eq + 1));
                }
            }
            m_lines.push_back(std::move(line));
        }
        return true;
    }

    bool save(const std::string& path) const
    {
        std::string out;
        for (const auto& line : m_lines)
        {
            out += line.text;
            out += '\n';
        }
        const std::string tmp = path + ".tmp";
        {
            std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
            if (!f)
            {
                return false;
            }
            f.write(out.data(), static_cast<std::streamsize>(out.size()));
            if (!f.good())
            {
                return false;
            }
        }
#if defined(_WIN32)
        std::remove(path.c_str());
#endif
        if (std::rename(tmp.c_str(), path.c_str()) != 0)
        {
            std::remove(tmp.c_str());
            return false;
        }
        return true;
    }

    std::vector<std::string> sections() const
    {
        std::vector<std::string> out;
        for (const auto& line : m_lines)
        {
            if (line.kind != Section)
            {
                continue;
            }
            bool dup = false;
            for (const auto& s : out)
            {
                if (IniIEquals(s, line.section)) { dup = true; break; }
            }
            if (!dup)
            {
                out.push_back(line.section);
            }
        }
        return out;
    }

    std::string get(const std::string& sec, const std::string& key, const std::string& def) const
    {
        for (const auto& line : m_lines)
        {
            if (line.kind == KeyValue && IniIEquals(line.section, sec) && IniIEquals(line.key, key))
            {
                return line.value;
            }
        }
        return def;
    }

    void set(const std::string& sec, const std::string& key, const std::string& val)
    {
        for (auto& line : m_lines)
        {
            if (line.kind == KeyValue && IniIEquals(line.section, sec) && IniIEquals(line.key, key))
            {
                line.value = val;
                line.text = line.key + "=" + val;
                return;
            }
        }
        insert_kv(sec, key, val);
    }

    void del_key(const std::string& sec, const std::string& key)
    {
        std::vector<Line> kept;
        for (auto& line : m_lines)
        {
            if (line.kind == KeyValue && IniIEquals(line.section, sec) && IniIEquals(line.key, key))
            {
                continue;
            }
            kept.push_back(std::move(line));
        }
        m_lines = std::move(kept);
    }

    void del_section(const std::string& sec)
    {
        std::vector<Line> kept;
        bool dropping = false;
        for (auto& line : m_lines)
        {
            if (line.kind == Section)
            {
                dropping = IniIEquals(line.section, sec);
            }
            if (!dropping)
            {
                kept.push_back(std::move(line));
            }
        }
        m_lines = std::move(kept);
    }

    const std::vector<Line>& lines() const { return m_lines; }

private:
    void insert_kv(const std::string& sec, const std::string& key, const std::string& val)
    {
        Line kv;
        kv.kind = KeyValue;
        kv.section = sec;
        kv.key = key;
        kv.value = val;
        kv.text = key + "=" + val;

        std::size_t secIdx = m_lines.size();
        std::size_t insertAt = m_lines.size();
        for (std::size_t i = 0; i < m_lines.size(); ++i)
        {
            if (m_lines[i].kind == Section && IniIEquals(m_lines[i].section, sec))
            {
                secIdx = i;
            }
        }
        if (secIdx == m_lines.size())
        {
            if (!m_lines.empty() && !m_lines.back().text.empty())
            {
                Line blank;
                m_lines.push_back(std::move(blank));
            }
            Line head;
            head.kind = Section;
            head.section = sec;
            head.text = "[" + sec + "]";
            m_lines.push_back(std::move(head));
            insertAt = m_lines.size();
        }
        else
        {
            insertAt = secIdx + 1;
            for (std::size_t i = secIdx + 1; i < m_lines.size(); ++i)
            {
                if (m_lines[i].kind == Section)
                {
                    break;
                }
                insertAt = i + 1;
            }
        }
        m_lines.insert(m_lines.begin() + static_cast<std::ptrdiff_t>(insertAt), std::move(kv));
    }

    std::vector<Line> m_lines;
};

}
