#include "logger.h"
#include "platform/cfgstr.h"

#include <cerrno>
#include <chrono>
#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <mutex>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <direct.h>
#else
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace {

std::mutex g_logMutex;
FILE* g_logFile = nullptr;
LogSink g_sink;

// exe 所在目录（带尾部分隔符）；失败返回空串
cfgstr GetExeDir()
{
#if defined(_WIN32)
    wchar_t buffer[MAX_PATH]{};
    const DWORD n = ::GetModuleFileNameW(nullptr, buffer, MAX_PATH);
    if (n == 0 || n >= MAX_PATH) return cfgstr();
    const cfgstr path(buffer, n);
    const cfgstr::size_type slash = path.find_last_of(CS("\\/"));
    if (slash == cfgstr::npos) return cfgstr();
    return path.substr(0, slash + 1);
#else
    char buffer[4096]{};
    const ssize_t n = ::readlink("/proc/self/exe", buffer, sizeof(buffer) - 1);
    if (n <= 0) return cfgstr();
    const cfgstr path(buffer, static_cast<std::size_t>(n));
    const cfgstr::size_type slash = path.find_last_of(CS("/"));
    if (slash == cfgstr::npos) return cfgstr();
    return path.substr(0, slash + 1);
#endif
}

bool MakeDir(const cfgstr& dir)
{
    if (dir.empty()) return false;
#if defined(_WIN32)
    return ::_wmkdir(dir.c_str()) == 0 || errno == EEXIST;
#else
    return ::mkdir(dir.c_str(), 0755) == 0 || errno == EEXIST;
#endif
}

std::tm LocalTime()
{
    const std::time_t t = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm tm{};
#if defined(_WIN32)
    localtime_s(&tm, &t);
#else
    localtime_r(&t, &tm);
#endif
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

bool HasConsole()
{
#if defined(_WIN32)
    return ::GetConsoleWindow() != nullptr;
#else
    return ::isatty(STDOUT_FILENO) != 0;
#endif
}

} // namespace

namespace Logger {

void Init()
{
    std::lock_guard<std::mutex> lock(g_logMutex);
    if (g_logFile) return;

    const cfgstr dir = cfg_path_join(GetExeDir(), CS("log"));
    MakeDir(dir); // 目录已存在时失败可忽略

    const std::tm tm = LocalTime();
    char name[64]{};
    std::snprintf(name, sizeof(name), "ScholarVPN_%04d-%02d-%02d_%02d-%02d-%02d.log",
                  tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                  tm.tm_hour, tm.tm_min, tm.tm_sec);

    const cfgstr path = cfg_path_join(dir, cfg_from_utf8(name));
#if defined(_WIN32)
    g_logFile = ::_wfopen(path.c_str(), L"ab");
#else
    g_logFile = std::fopen(path.c_str(), "ab");
#endif
    if (g_logFile)
    {
        // 写入 UTF-8 BOM，方便记事本等编辑器识别编码；
        // Linux 下 tail/vim 不认 BOM 也不受影响，保持跨平台行为一致
        const char bom[] = "\xEF\xBB\xBF";
        std::fwrite(bom, 1, sizeof(bom) - 1, g_logFile);
    }
}

void Log(const char* fmt, ...)
{
    std::string line;
    {
        std::lock_guard<std::mutex> lock(g_logMutex);

        char buf[4096]{};
        va_list args;
        va_start(args, fmt);
        const int n = std::vsnprintf(buf, sizeof(buf), fmt, args);
        va_end(args);

        std::string msg = (n > 0)
                              ? std::string(buf, (static_cast<size_t>(n) < sizeof(buf)) ? static_cast<size_t>(n) : sizeof(buf) - 1)
                              : std::string();
        while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r'))
        {
            msg.pop_back();
        }

        line = "[" + CurrentTimestamp() + "] " + msg;

        // 有控制台才打印：Windows 打包为子系统时没有控制台；
        // Linux 下重定向到文件/被 systemd 接管时不是 tty，也不该往 stdout 灌
        if (HasConsole())
        {
            std::puts(line.c_str());
        }

        if (g_logFile)
        {
            std::fwrite(line.c_str(), 1, line.size(), g_logFile);
            std::fwrite("\n", 1, 1, g_logFile);
            std::fflush(g_logFile);
        }

        // 转发给订阅者（UI 日志窗口），在调用线程执行
        if (g_sink)
        {
            g_sink(line);
        }
    }
}

void SetSink(LogSink sink)
{
    std::lock_guard<std::mutex> lock(g_logMutex);
    g_sink = std::move(sink);
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
