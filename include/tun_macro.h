#pragma once
#include <cstdio>
#include <cassert>

#include "logger.h"

#ifdef _DEBUG
#define TUN_DEBUG_MODE 1
#else
#define TUN_DEBUG_MODE 0
#endif

#if TUN_DEBUG_MODE
#define TUN_DEBUG_LOG 1
#define TUN_VERBOSE_LOG 1
#else
#define TUN_DEBUG_LOG 0
#define TUN_VERBOSE_LOG 0
#endif

#if TUN_DEBUG_MODE
#define TUN_ASSERT(expr, msg) \
do { \
    if (!(expr)) { \
        fprintf(stderr, "[ASSERT FAIL] %s:%d %s\n", __FILE__, __LINE__, msg); \
        assert(false); \
    } \
} while(0)
#define TUN_API_CHECK(expr, retVal) TUN_ASSERT(expr, "api param invalid"); if(!(expr)) return retVal;
#else
#define TUN_ASSERT(expr, msg) ((void)0)
#define TUN_API_CHECK(expr, retVal) if(!(expr)) return retVal;
#endif

#define LOG_FATAL(fmt, ...)  do { ::Logger::Log("[FATAL] " fmt "\n", ##__VA_ARGS__); } while (0)
#define LOG_ERROR(fmt, ...)  do { ::Logger::Log("[ERROR] " fmt "\n", ##__VA_ARGS__); } while (0)
#define LOG_WARN(fmt, ...)   do { ::Logger::Log("[WARN]  " fmt "\n", ##__VA_ARGS__); } while (0)
#define LOG_INFO(fmt, ...)   do { ::Logger::Log("[INFO]  " fmt "\n", ##__VA_ARGS__); } while (0)

#if TUN_DEBUG_LOG
#define LOG_DEBUG(fmt, ...)  do { ::Logger::Log("[DEBUG] " fmt "\n", ##__VA_ARGS__); } while (0)
#else
#define LOG_DEBUG(fmt, ...) ((void)0)
#endif

#if TUN_VERBOSE_LOG
#define LOG_TRACE(fmt, ...)  do { ::Logger::Log("[TRACE] " fmt "\n", ##__VA_ARGS__); } while (0)
#else
#define LOG_TRACE(fmt, ...) ((void)0)
#endif
