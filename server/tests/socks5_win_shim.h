#pragma once
// ============================================================================
// POSIX→Winsock 兼容垫片（仅用于在 Windows 开发机上做 socks5.cpp 运行期自测）
//
// 目的：让部署在 Linux 的 server/Socks5/socks5.cpp 能在 Windows 上原样编译运行，
// 从而用真实 socket 验证 SOCKS5 握手/认证/CONNECT/双向中继逻辑。
// 用法见 socks5_selftest.cpp 顶部说明。
//
// 覆盖点：
//   - close/send/recv/connect/accept4/setsockopt/getsockopt/getsockname/
//     bind/listen/shutdown/socket → Winsock 包装，并把 WSAGetLastError()
//     映射回 errno（socks5.cpp 的错误判断走 errno）
//   - fcntl(F_GETFL/F_SETFL, O_NONBLOCK) → ioctlsocket(FIONBIO)
//   - poll → WSAPoll；SOCK_CLOEXEC/SOCK_NONBLOCK/MSG_NOSIGNAL 置 0
//   - getaddrinfo/freeaddrinfo/inet_pton/inet_ntop → ws2tcpip
//
// 注意：本垫片只为测试存在，不参与 Linux 构建（正式构建用系统头文件）。
// ============================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <cerrno>
#include <cstdint>
#include <sys/types.h>

using socklen_t = int;
using nfds_t = unsigned long;
// MSVC 无 ssize_t（POSIX 读写的返回类型）
#ifndef _SSIZE_T_DEFINED
#define _SSIZE_T_DEFINED
using ssize_t = long long;
#endif

// MSVC 的 errno.h 缺这些名字（socks5.cpp 的错误分支要用）
#ifndef EINPROGRESS
#define EINPROGRESS 10036
#endif
#ifndef ETIMEDOUT
#define ETIMEDOUT 10060
#endif
#ifndef ENETUNREACH
#define ENETUNREACH 10051
#endif
#ifndef EHOSTUNREACH
#define EHOSTUNREACH 10065
#endif
#ifndef ECONNREFUSED
#define ECONNREFUSED 10061
#endif
#ifndef EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#ifndef SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#endif
#ifndef SOCK_NONBLOCK
#define SOCK_NONBLOCK 0
#endif
#ifndef SHUT_RDWR
#define SHUT_RDWR SD_BOTH
#endif
#ifndef SHUT_WR
#define SHUT_WR SD_SEND
#endif

// Winsock 错误 → errno（socks5.cpp 只依赖这几个）
static inline int sock_shim_errno(int wsa)
{
    switch (wsa) {
    case WSAEWOULDBLOCK:  return EAGAIN;
    case WSAEINPROGRESS:  return EINPROGRESS;
    case WSAETIMEDOUT:    return ETIMEDOUT;
    case WSAECONNREFUSED: return ECONNREFUSED;
    case WSAENETUNREACH:  return ENETUNREACH;
    case WSAEHOSTUNREACH: return EHOSTUNREACH;
    case WSAEACCES:       return EACCES;
    case WSAEINTR:        return EINTR;
    case WSAEMFILE:       return EMFILE;
    default:              return EIO;
    }
}

static inline void sock_shim_set_errno(void)
{
    errno = sock_shim_errno(WSAGetLastError());
}

static inline int shim_close(int fd) { return ::closesocket(static_cast<SOCKET>(fd)); }
static inline int shim_send(int fd, const void* buf, size_t n, int flags)
{
    const int r = ::send(static_cast<SOCKET>(fd), static_cast<const char*>(buf),
                         static_cast<int>(n), flags);
    if (r < 0) sock_shim_set_errno();
    return r;
}
static inline int shim_recv(int fd, void* buf, size_t n, int flags)
{
    const int r = ::recv(static_cast<SOCKET>(fd), static_cast<char*>(buf),
                         static_cast<int>(n), flags);
    if (r < 0) sock_shim_set_errno();
    return r;
}
static inline int shim_connect(int fd, const struct sockaddr* sa, socklen_t len)
{
    const int r = ::connect(static_cast<SOCKET>(fd), sa, static_cast<int>(len));
    if (r < 0) {
        // POSIX 非阻塞 connect 返回 EINPROGRESS；Winsock 返回 WSAEWOULDBLOCK
        const int wsa = WSAGetLastError();
        errno = (wsa == WSAEWOULDBLOCK) ? EINPROGRESS : sock_shim_errno(wsa);
    }
    return r;
}
static inline int shim_accept4(int listen_fd, struct sockaddr* sa, socklen_t* len, int)
{
    const SOCKET s = ::accept(static_cast<SOCKET>(listen_fd), sa, len);
    if (s == INVALID_SOCKET) {
        sock_shim_set_errno();
        return -1;
    }
    return static_cast<int>(s);
}
static inline int shim_setsockopt(int fd, int level, int name, const void* val, socklen_t len)
{
    const int r = ::setsockopt(static_cast<SOCKET>(fd), level, name,
                               static_cast<const char*>(val), len);
    if (r < 0) sock_shim_set_errno();
    return r;
}
static inline int shim_getsockopt(int fd, int level, int name, void* val, socklen_t* len)
{
    const int r = ::getsockopt(static_cast<SOCKET>(fd), level, name,
                               static_cast<char*>(val), len);
    if (r < 0) sock_shim_set_errno();
    return r;
}
static inline int shim_getsockname(int fd, struct sockaddr* sa, socklen_t* len)
{
    const int r = ::getsockname(static_cast<SOCKET>(fd), sa, len);
    if (r < 0) sock_shim_set_errno();
    return r;
}
static inline int shim_bind(int fd, const struct sockaddr* sa, socklen_t len)
{
    const int r = ::bind(static_cast<SOCKET>(fd), sa, static_cast<int>(len));
    if (r < 0) sock_shim_set_errno();
    return r;
}
static inline int shim_listen(int fd, int backlog)
{
    const int r = ::listen(static_cast<SOCKET>(fd), backlog);
    if (r < 0) sock_shim_set_errno();
    return r;
}
static inline int shim_shutdown(int fd, int how)
{
    const int r = ::shutdown(static_cast<SOCKET>(fd), how);
    if (r < 0) sock_shim_set_errno();
    return r;
}
static inline int shim_socket(int domain, int type, int protocol)
{
    const SOCKET s = ::socket(domain, type, protocol);
    if (s == INVALID_SOCKET) {
        sock_shim_set_errno();
        return -1;
    }
    return static_cast<int>(s);
}

// fcntl：只支持 socks5.cpp 用到的 F_GETFL / F_SETFL(+O_NONBLOCK)
#define O_NONBLOCK 1
#define F_GETFL 3
#define F_SETFL 4
static inline int shim_fcntl(int fd, int cmd, int arg)
{
    if (cmd == F_GETFL)
        return 0;
    if (cmd == F_SETFL) {
        u_long mode = (arg & O_NONBLOCK) ? 1 : 0;
        if (ioctlsocket(static_cast<SOCKET>(fd), FIONBIO, &mode) != 0) {
            sock_shim_set_errno();
            return -1;
        }
        return 0;
    }
    errno = EINVAL;
    return -1;
}

// poll → WSAPoll（POLLIN 等常量取 Winsock 定义，已有则不重复定义）
#ifndef POLLIN
#define POLLIN POLLRDNORM
#endif
#ifndef POLLOUT
#define POLLOUT POLLWRNORM
#endif
#ifndef POLLERR
#define POLLERR 0x0008
#endif
#ifndef POLLHUP
#define POLLHUP 0x0010
#endif
#ifndef POLLNVAL
#define POLLNVAL 0x0020
#endif
static inline int shim_poll(struct pollfd* fds, nfds_t n, int timeout)
{
    const int r = ::WSAPoll(fds, n, timeout);
    if (r < 0) sock_shim_set_errno();
    return r;
}

#define close shim_close
#define send shim_send
#define recv shim_recv
#define connect shim_connect
#define accept4 shim_accept4
#define setsockopt shim_setsockopt
#define getsockopt shim_getsockopt
#define getsockname shim_getsockname
#define bind shim_bind
#define listen shim_listen
#define shutdown shim_shutdown
#define socket shim_socket
#define fcntl shim_fcntl
#define poll shim_poll
