#pragma once

// ============================================================================
// src/platform/ini_doc.h —— 保留原始行结构的轻量 INI 文档
//
// 为什么单独抽出来：
//   1. Linux 端没有 Win32 的 Get/WritePrivateProfileString，需要自己解析；
//   2. 这段逻辑是纯标准库（无平台分支），可以在任何平台编译并单测——
//      配置读错的下场是"连不上服务器/用错身份"，不能靠肉眼 review 兜底。
//
// 设计取舍：
//   - 保留原始行（含注释、空行、未知键）：set/delete 只改目标行，
//     用户手写的注释和程序不认识的键不会被抹掉；
//   - 保留行顺序；新键插入所属节的末尾，新节追加到文件尾；
//   - 节名/键名大小写不敏感（对齐 Win32 GetPrivateProfileString 的语义）；
//   - 读：UTF-8 BOM / UTF-16LE / UTF-16BE 归一成 UTF-8（兼容 Windows 生成的 ini）；
//   - 写：UTF-8 无 BOM + 原子替换（写 .tmp 再 rename，避免半截文件）。
// ============================================================================

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
        return raw.substr(3);                       // UTF-8 BOM
    }
    if (raw.size() >= 2 && static_cast<unsigned char>(raw[0]) == 0xFF &&
        static_cast<unsigned char>(raw[1]) == 0xFE)
    {
        return utf16_to_utf8(raw.substr(2), true);  // UTF-16 LE
    }
    if (raw.size() >= 2 && static_cast<unsigned char>(raw[0]) == 0xFE &&
        static_cast<unsigned char>(raw[1]) == 0xFF)
    {
        return utf16_to_utf8(raw.substr(2), false); // UTF-16 BE
    }
    return raw;                                     // 视为 UTF-8
}

class IniDoc
{
public:
    enum Kind { Other = 0, Section, KeyValue };

    struct Line
    {
        Kind kind = Other;
        std::string text;      // 原始行（不含换行）
        std::string section;   // 所属节（KeyValue 用）
        std::string key;       // KeyValue 用
        std::string value;     // KeyValue 用
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
        // POSIX 的 rename 原子覆盖；Windows 的 std::rename 目标存在时直接失败。
        // （生产路径上 Windows 走 Win32 INI API，不经过这里；这条只为让本模块
        //  能在任意平台单测，同时保留 Linux 端的原子语义。）
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
                return line.value;   // 与 GetPrivateProfileString 一致：取第一个
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
            // 整节不存在：文件尾追加（与上一节之间留一个空行）
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

} // namespace scholinux
