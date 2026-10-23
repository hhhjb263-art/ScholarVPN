#pragma once

// ============================================================================
// src/platform/sock_compat.h —— 跨平台 socket 兼容层
//
// 目标：`UDP.cpp` / `tcp.cpp` 里不再出现 SOCKET / WSAStartup / closesocket /
// WSAGetLastError / WSAPoll / ioctlsocket(FIONBIO) / InetNtopA 这些 Win32 符号。
// 协议逻辑（三阶段认证 / AES-GCM / 心跳 / 队列）一行都不用动。
//
// 约定：
//   sock_t        socket 句柄       Windows: SOCKET   Linux: int
//   SOCK_INVALID  无效句柄
//   SOCK_ERR      失败返回值
//   sock_len_t    socklen 类型      Windows: int      Linux: socklen_t
//   sock_ssize_t  send/recv 返回值  Windows: int      Linux: ssize_t
//   sock_pollfd   poll 描述符       Windows: WSAPOLLFD Linux: struct pollfd
//   sock_close / sock_last_error / sock_poll / sock_set_nonblocking / sock_ntop
//
// 错误码用 kSockXxx 常量，避免在业务代码里出现 WSA* / errno 分叉。
// ============================================================================

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>

#if defined(_WIN32)

// NOMINMAX 必须在 windows.h 之前：否则全局 min/max 宏会把 std::min(...) 展开成
// std::((a) < (b) ? (a) : (b)) —— 编译器报的就是 C2059/C2589 那一串语法错误
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#pragma comment(lib, "Ws2_32.lib")

using sock_t = SOCKET;
using sock_len_t = int;
using sock_ssize_t = int;
using sock_pollfd = WSAPOLLFD;

#define SOCK_INVALID INVALID_SOCKET
#define SOCK_ERR SOCKET_ERROR

inline int sock_close(sock_t s) { return ::closesocket(s); }
inline int sock_last_error() { return ::WSAGetLastError(); }
inline int sock_poll(sock_pollfd* fds, unsigned n, int timeout_ms)
{
    return ::WSAPoll(fds, static_cast<ULONG>(n), timeout_ms);
}
inline bool sock_set_nonblocking(sock_t s)
{
    u_long on = 1;
    return ::ioctlsocket(s, FIONBIO, &on) == 0;
}
inline const char* sock_ntop(const struct in_addr& addr, char* buf, std::size_t cap)
{
    return ::InetNtopA(AF_INET, const_cast<struct in_addr*>(&addr), buf, static_cast<DWORD>(cap));
}

// Windows 的 UDP socket 在收到 ICMP 端口不可达后，下一次 recvfrom 返回 WSAECONNRESET；
// Linux 只有在 connect() 过的 UDP socket 上才有等价语义（见 UDP::raw_send 注释）
constexpr int kSockWouldBlock = WSAEWOULDBLOCK;
constexpr int kSockInProgress = WSAEWOULDBLOCK;
constexpr int kSockConnReset = WSAECONNRESET;
constexpr int kSockConnRefused = WSAECONNREFUSED;
constexpr int kSockTimedOut = WSAETIMEDOUT;
constexpr int kSockNetUnreach = WSAENETUNREACH;
constexpr int kSockHostUnreach = WSAEHOSTUNREACH;
constexpr int kSockAddrNotAvail = WSAEADDRNOTAVAIL;
constexpr int kSockHostDown = WSAEHOSTDOWN;

// 进程级 socket 运行时。
// 只 start 一次、且**故意**不调 WSACleanup：
//   原实现的 UDP 每个实例析构时 WSACleanup 一次，init 的 3 条失败路径又各调一次，
//   而 WSAStartup 只成功调用一次 → 引用计数必然提前归零，
//   下一个实例的 socket() 会直接失败（重连几次后"连不上了"，日志还看不出原因）。
//   Winsock 的清理交给进程退出，代价可忽略。
inline bool sock_runtime_start()
{
    static std::atomic<bool> inited{ false };
    bool expected = false;
    if (inited.compare_exchange_strong(expected, true, std::memory_order_acq_rel))
    {
        WSADATA wsa{};
        if (::WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
        {
            inited.store(false, std::memory_order_release);
            return false;
        }
    }
    return true;
}

inline void sock_runtime_stop()
{
    // 见上：不递减、不 WSACleanup，避免多实例/失败路径把运行时提前拆掉
}

#else // ---------------------------- POSIX / Linux ----------------------------

#include <arpa/inet.h>
#include <cerrno>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

using sock_t = int;
using sock_len_t = socklen_t;
using sock_ssize_t = ssize_t;
using sock_pollfd = struct pollfd;

#define SOCK_INVALID (-1)
#define SOCK_ERR (-1)

inline int sock_close(sock_t s) { return ::close(s); }
inline int sock_last_error() { return errno; }
inline int sock_poll(sock_pollfd* fds, unsigned n, int timeout_ms)
{
    return ::poll(fds, static_cast<nfds_t>(n), timeout_ms);
}
inline bool sock_set_nonblocking(sock_t s)
{
    const int flags = ::fcntl(s, F_GETFL, 0);
    if (flags < 0)
    {
        return false;
    }
    return ::fcntl(s, F_SETFL, flags | O_NONBLOCK) == 0;
}
inline const char* sock_ntop(const struct in_addr& addr, char* buf, std::size_t cap)
{
    return ::inet_ntop(AF_INET, &addr, buf, static_cast<socklen_t>(cap));
}

constexpr int kSockWouldBlock = EWOULDBLOCK;   // Linux 上 == EAGAIN
constexpr int kSockInProgress = EINPROGRESS;   // 非阻塞 connect：连接正在建立
constexpr int kSockConnReset = ECONNRESET;
constexpr int kSockConnRefused = ECONNREFUSED;
constexpr int kSockTimedOut = ETIMEDOUT;
constexpr int kSockNetUnreach = ENETUNREACH;
constexpr int kSockHostUnreach = EHOSTUNREACH;
constexpr int kSockAddrNotAvail = EADDRNOTAVAIL;
constexpr int kSockHostDown = EHOSTDOWN;

inline bool sock_runtime_start() { return true; }   // 无需进程级初始化
inline void sock_runtime_stop() {}

#endif

// 两端 send/recv 的缓冲区指针都能接受 char*/void*，这里统一成一个别名，
// 免得业务代码里到处 reinterpret_cast
using sock_buf = char;
