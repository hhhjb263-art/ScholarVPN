#include "logger.h"

#ifdef NDEBUG

#include <windows.h>
#include <direct.h>
#include <chrono>
#include <cstdarg>
#include <ctime>
#include <cwchar>
#include <mutex>
#include <string>

namespace {

std::mutex g_logMutex;
FILE* g_logFile = nullptr;

std::wstring GetExeDir()
{
    wchar_t buffer[MAX_PATH]{};
    const DWORD n = ::GetModuleFileNameW(nullptr, buffer, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return L"";
    const std::wstring path(buffer, n);
    const std::size_t slash = path.find_last_of(L"\\/");
    if (slash == std::wstring::npos) return L"";
    return path.substr(0, slash + 1);
}

std::tm LocalTime()
{
    const std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tm{};
    localtime_s(&tm, &t);
    return tm;
}

std::string CurrentTimestamp()
{
    const std::tm tm = LocalTime();
    const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::system_clock::now().time_since_epoch()) %
                    1000;
    char buf[64]{};
    std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d.%03d",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<int>(ms.count()));
    return buf;
}

} // namespace

namespace Logger {

void Init()
{
    std::lock_guard<std::mutex> lock(g_logMutex);
    if (g_logFile) return;

    const std::wstring dir = GetExeDir() + L"log";
    _wmkdir(dir.c_str()); // 目录已存在时失败可忽略

    const std::tm tm = LocalTime();
    wchar_t name[64]{};
    std::swprintf(name, 64, L"ScholarVPN_%04d-%02d-%02d_%02d-%02d-%02d.log",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec);

    g_logFile = _wfopen((dir + L"\\" + name).c_str(), L"ab");
    if (g_logFile)
    {
        // 写入 UTF-8 BOM，方便记事本等编辑器识别编码
        const char bom[] = "\xEF\xBB\xBF";
        std::fwrite(bom, 1, sizeof(bom) - 1, g_logFile);
    }
}

void Log(const char* fmt, ...)
{
    std::lock_guard<std::mutex> lock(g_logMutex);
    if (!g_logFile) return;

    char buf[4096]{};
    va_list args;
    va_start(args, fmt);
    const int n = std::vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    std::string msg = (n > 0)
                          ? std::string(buf, (static_cast<size_t>(n) < sizeof(buf)) ? static_cast<size_t>(n) : sizeof(buf) - 1)
                          : std::string();

    // 字符串字面量按系统 ANSI 代码页（GBK）编译进 exe，这里统一转成 UTF-8 再写入日志文件
    if (!msg.empty())
    {
        const int wlen = ::MultiByteToWideChar(CP_ACP, 0, msg.data(), static_cast<int>(msg.size()), nullptr, 0);
        if (wlen > 0)
        {
            std::wstring w(wlen, L'\0');
            ::MultiByteToWideChar(CP_ACP, 0, msg.data(), static_cast<int>(msg.size()), &w[0], wlen);
            const int ulen = ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), wlen, nullptr, 0, nullptr, nullptr);
            if (ulen > 0)
            {
                std::string utf8(ulen, '\0');
                ::WideCharToMultiByte(CP_UTF8, 0, w.c_str(), wlen, &utf8[0], ulen, nullptr, nullptr);
                msg.swap(utf8);
            }
        }
    }

    while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r'))
    {
        msg.pop_back();
    }

    const std::string line = "[" + CurrentTimestamp() + "] " + msg + "\n";
    std::fwrite(line.data(), 1, line.size(), g_logFile);
    std::fflush(g_logFile);
}

void Shutdown()
{
    std::lock_guard<std::mutex> lock(g_logMutex);
    if (g_logFile)
    {
        std::fclose(g_logFile);
        g_logFile = nullptr;
    }
}

} // namespace Logger

#endif // NDEBUG