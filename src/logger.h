#pragma once

#include <cstdio>
#include <functional>
#include <string>

// 日志模块：
//   - Release（NDEBUG）：关键日志写入 exe 同目录 log\ScholarVPN_<时间戳>.log
//   - Debug：日志输出到控制台（stdout）
//   - 两种模式下日志都会转发给 SetSink 注册的回调（供 UI 日志窗口订阅）；
//     回调在产生日志的线程被调用，订阅方需自行切换到 UI 线程。

// 日志转发回调（UI 订阅用）
using LogSink = std::function<void(const std::string&)>;

namespace Logger {
    void Init();                          // 打开日志文件（Debug 为 no-op）
    void Log(const char* fmt, ...);       // 格式化 → 输出（Debug: stdout / Release: 文件）+ 转发 sink
    void SetSink(LogSink sink);           // 设置日志转发回调（覆盖式）
    void Shutdown();                      // 关闭日志文件
}

#define LOG_DBG(...) do { ::Logger::Log(__VA_ARGS__); } while (0)   // 调试明细
#define LOG_KEY(...)  do { ::Logger::Log(__VA_ARGS__); } while (0)   // 关键事件
#define LOG_ERR(...)  do { ::Logger::Log(__VA_ARGS__); } while (0)   // 错误/警告
