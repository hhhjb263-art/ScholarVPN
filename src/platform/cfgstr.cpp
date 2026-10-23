#include "cfgstr.h"

#include <cstddef>
#include <cstdlib>

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shlobj.h>

// SHGetFolderPathW（cfg_config_root）需要 shell32；
// 这个 pragma 原来是写在 Config.cpp 里的，函数搬过来时漏了 → 编译能过、链接才炸
#pragma comment(lib, "shell32.lib")

std::string cfg_to_utf8(const cfgstr& s)
{
    if (s.empty())
    {
        return {};
    }
    const int len = ::WideCharToMultiByte(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                                          nullptr, 0, nullptr, nullptr);
    if (len <= 0)
    {
        return {};
    }
    std::string out(static_cast<std::size_t>(len), '\0');
    ::WideCharToMultiByte(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                          &out[0], len, nullptr, nullptr);
    return out;
}

cfgstr cfg_from_utf8(const std::string& s)
{
    if (s.empty())
    {
        return {};
    }
    const int len = ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                                          nullptr, 0);
    if (len <= 0)
    {
        return {};
    }
    cfgstr out(static_cast<std::size_t>(len), L'\0');
    ::MultiByteToWideChar(CP_UTF8, 0, s.c_str(), static_cast<int>(s.size()),
                          &out[0], len);
    return out;
}

cfgstr cfg_num(long long value)
{
    return std::to_wstring(value);
}

cfgstr cfg_path_join(const cfgstr& dir, const cfgstr& name)
{
    if (dir.empty())
    {
        return name;
    }
    const cfgstr::value_type last = dir.back();
    if (last == L'\\' || last == L'/')
    {
        return dir + name;
    }
    return dir + L"\\" + name;
}

cfgstr cfg_config_root()
{
    wchar_t path[MAX_PATH] = { 0 };
    if (::SHGetFolderPathW(nullptr, CSIDL_APPDATA, nullptr, 0, path) != S_OK)
    {
        ::GetCurrentDirectoryW(MAX_PATH, path);
    }
    return cfgstr(path);
}

bool cfg_unlink(const cfgstr& path)
{
    return ::DeleteFileW(path.c_str()) != 0;
}

bool cfg_restrict_file(const cfgstr& /*path*/)
{
    return true;   // Windows 由 DPAPI 加密私钥，不依赖文件权限
}

cfgstr cfg_app_dir()
{
    return cfg_path_join(cfg_config_root(), CS("ScholarVPN"));
}

#else // ---------------- POSIX / Linux ----------------

#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

std::string cfg_to_utf8(const cfgstr& s)
{
    // Linux 的 cfgstr 本身就是 UTF-8 字节流，零转换
    return s;
}

cfgstr cfg_from_utf8(const std::string& s)
{
    return s;
}

cfgstr cfg_num(long long value)
{
    return std::to_string(value);
}

cfgstr cfg_path_join(const cfgstr& dir, const cfgstr& name)
{
    if (dir.empty())
    {
        return name;
    }
    if (dir.back() == '/')
    {
        return dir + name;
    }
    return dir + "/" + name;
}

namespace {

// sudo 会把 $HOME 改成 /root。身份密钥与 config.ini 若跟着落到 /root，
// 用户下次普通身份运行就"变成一台新设备"，服务端要求重新注册令牌。
// 优先用 SUDO_UID 查真实家目录（比 $SUDO_USER / $HOME 都可靠）。
std::string real_home()
{
    if (const char* uid = std::getenv("SUDO_UID"); uid != nullptr && *uid != '\0')
    {
        char* end = nullptr;
        const unsigned long v = std::strtoul(uid, &end, 10);
        if (end != nullptr && *end == '\0')
        {
            if (const struct passwd* pw = ::getpwuid(static_cast<uid_t>(v)); pw != nullptr && pw->pw_dir != nullptr)
            {
                return std::string(pw->pw_dir);
            }
        }
    }
    if (const char* home = std::getenv("HOME"); home != nullptr && *home != '\0')
    {
        return std::string(home);
    }
    return std::string(".");
}

} // namespace

cfgstr cfg_config_root()
{
    if (const char* xdg = std::getenv("XDG_CONFIG_HOME"); xdg != nullptr && *xdg != '\0')
    {
        return std::string(xdg);
    }
    return cfg_path_join(real_home(), ".config");
}

bool cfg_unlink(const cfgstr& path)
{
    return ::unlink(path.c_str()) == 0;
}

bool cfg_restrict_file(const cfgstr& path)
{
    // 身份私钥：没有 DPAPI，必须靠 0600 兜底（属主可读写，组/其他无权限）
    return ::chmod(path.c_str(), 0600) == 0;
}

cfgstr cfg_app_dir()
{
    // Linux 惯例：小写目录名
    return cfg_path_join(cfg_config_root(), "scholarvpn");
}

#endif
