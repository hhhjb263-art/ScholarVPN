#pragma once

#include <cstdio>
#include <functional>
#include <string>

using LogSink = std::function<void(const std::string&)>;

namespace Logger {
    void Init();
    void Log(const char* fmt, ...);
    void SetSink(LogSink sink);
    void Shutdown();
}

#define LOG_DBG(...) do { ::Logger::Log(__VA_ARGS__); } while (0)
#define LOG_KEY(...) do { ::Logger::Log(__VA_ARGS__); } while (0)
#define LOG_ERR(...) do { ::Logger::Log(__VA_ARGS__); } while (0)
