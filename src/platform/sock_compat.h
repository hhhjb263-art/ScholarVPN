#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <cstring>

#if defined(_WIN32)

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

constexpr int kSockWouldBlock = WSAEWOULDBLOCK;
constexpr int kSockInProgress = WSAEWOULDBLOCK;
constexpr int kSockConnReset = WSAECONNRESET;
constexpr int kSockConnRefused = WSAECONNREFUSED;
constexpr int kSockTimedOut = WSAETIMEDOUT;
constexpr int kSockNetUnreach = WSAENETUNREACH;
constexpr int kSockHostUnreach = WSAEHOSTUNREACH;
constexpr int kSockAddrNotAvail = WSAEADDRNOTAVAIL;
constexpr int kSockHostDown = WSAEHOSTDOWN;

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
}

#else

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

constexpr int kSockWouldBlock = EWOULDBLOCK;
constexpr int kSockInProgress = EINPROGRESS;
constexpr int kSockConnReset = ECONNRESET;
constexpr int kSockConnRefused = ECONNREFUSED;
constexpr int kSockTimedOut = ETIMEDOUT;
constexpr int kSockNetUnreach = ENETUNREACH;
constexpr int kSockHostUnreach = EHOSTUNREACH;
constexpr int kSockAddrNotAvail = EADDRNOTAVAIL;
constexpr int kSockHostDown = EHOSTDOWN;

inline bool sock_runtime_start() { return true; }
inline void sock_runtime_stop() {}

#endif

using sock_buf = char;
