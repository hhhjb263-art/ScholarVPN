#pragma once

// 日志模块：
//   Release（NDEBUG）：只保留关键日志，写入 exe 同目录 log\ScholarVPN_<时间戳>.log，
//                     每行格式：[时间] 事件
//   Debug：保持原有控制台输出不变，本模块为空操作。

#include <iostream>
#include <cstdio>

#ifdef NDEBUG

#define LOG_DBG(msg)  ((void)0)                        // 调试明细：Release 不输出
#define LOG_KEY(...)  ::Logger::Log(__VA_ARGS__)       // 关键事件：写入日志文件
#define LOG_ERR(...)  ::Logger::Log(__VA_ARGS__)       // 错误/警告：写入日志文件

namespace Logger {
    void Init();                       // 创建 log 目录并打开日志文件
    void Log(const char* fmt, ...);    // 以 "[时间] 事件" 格式写入
    void Shutdown();                   // 关闭日志文件
}

#else

#define LOG_DBG(msg)  do { std::cout << msg; } while (0)
#define LOG_KEY(...)  do { std::printf(__VA_ARGS__); } while (0)
#define LOG_ERR(...)  do { std::fprintf(stderr, __VA_ARGS__); } while (0)

namespace Logger {
    inline void Init() {}
    inline void Shutdown() {}
}

#endif