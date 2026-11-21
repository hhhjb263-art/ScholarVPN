#include "tcpserver.h"
#include "../core/log.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <utility>
#include <vector>
#include <system_error>

namespace {
constexpr size_t kMaxTcpConns = 128;
constexpr int kReadFramesBudget = 64;
constexpr size_t kMaxRxBufBytes = 512 * 1024;
}

TCPServer::TCPServer(UDP& udp)
    : m_udp(udp)
{
}

TCPServer::~TCPServer()
{
    stop();
}

bool TCPServer::start(const std::string& listen_ip, uint16_t port)
{
    if (m_running.load())
        return false;

    m_listen_fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (m_listen_fd < 0) {
        fprintf(stderr, "[TCP] socket() failed: %s\n", strerror(errno));
        return false;
    }
    int reuse = 1;
    setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if(listen_ip.empty()){
        addr.sin_addr.s_addr = INADDR_ANY;
    }else{
        int ret = inet_pton(AF_INET,listen_ip.c_str(),&addr.sin_addr);
        if(ret != 1){
            fprintf(stderr,"[TCP] invalid listen ip %s\n", listen_ip.c_str());
            close(m_listen_fd);
            m_listen_fd = -1;
            return false;
        }
    }
    if (bind(m_listen_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        fprintf(stderr, "[TCP] bind() failed (%s:%u): %s\n",
                listen_ip.c_str(), static_cast<unsigned>(port), strerror(errno));
        close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }
    if (listen(m_listen_fd, 64) < 0) {
        fprintf(stderr, "[TCP] listen() failed: %s\n", strerror(errno));
        close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }

    m_epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (m_epoll_fd < 0) {
        fprintf(stderr, "[TCP] epoll_create1() failed: %s\n", strerror(errno));
        close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = m_listen_fd;
    if (epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, m_listen_fd, &ev) < 0) {
        fprintf(stderr, "[TCP] epoll_ctl(listen) failed: %s\n", strerror(errno));
        close(m_epoll_fd);
        m_epoll_fd = -1;
        close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }
    m_wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (m_wake_fd < 0) {
        fprintf(stderr, "[TCP] eventfd() failed: %s\n", strerror(errno));
        close(m_epoll_fd);
        m_epoll_fd = -1;
        close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }
    ev.events = EPOLLIN;
    ev.data.fd = m_wake_fd;
    epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, m_wake_fd, &ev);

    m_listen_ip = listen_ip;
    m_port = port;
    m_running.store(true);
    try {
        m_event_thread = std::thread(&TCPServer::event_loop, this);
    } catch (const std::system_error& e) {
        fprintf(stderr, "[TCP] 启动事件线程失败: %s\n", e.what());
        m_running.store(false);
        close(m_wake_fd);
        m_wake_fd = -1;
        close(m_epoll_fd);
        m_epoll_fd = -1;
        close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }
    fprintf(stderr, "[TCP] 监听 %s:%u（epoll 事件驱动，同端口双栈，等待客户端 TCP 连接）\n",
            listen_ip.c_str(), static_cast<unsigned>(port));

    m_udp.set_tcp_tx_wake([this] { wake(); });
    return true;
}

void TCPServer::stop()
{
    if (!m_running.exchange(false))
        return;
    if (m_wake_fd >= 0) {
        const uint64_t one = 1;
        const ssize_t n = write(m_wake_fd, &one, sizeof(one));
        (void)n;
    }
    if (m_event_thread.joinable())
        m_event_thread.join();
    m_udp.set_tcp_tx_wake(nullptr);
    for (auto& kv : m_conns) {
        if (kv.second.session && kv.second.session->tcp_fd == kv.first)
            kv.second.session->tcp_fd = -1;
        close(kv.first);
    }
    m_conns.clear();
    if (m_listen_fd >= 0) {
        close(m_listen_fd);
        m_listen_fd = -1;
    }
    if (m_epoll_fd >= 0) {
        close(m_epoll_fd);
        m_epoll_fd = -1;
    }
    if (m_wake_fd >= 0) {
        close(m_wake_fd);
        m_wake_fd = -1;
    }
    fprintf(stderr, "[TCP] 监听已停止\n");
}

void TCPServer::event_loop()
{
    std::vector<epoll_event> events(64);
    while (m_running.load()) {
        const int n = epoll_wait(m_epoll_fd, events.data(),
                                 static_cast<int>(events.size()), 200);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "[TCP] epoll_wait() failed: %s\n", strerror(errno));
            break;
        }
        for (int i = 0; i < n; ++i) {
            const int fd = events[i].data.fd;
            if (fd == m_listen_fd) {
                handle_accept();
                continue;
            }
            if (fd == m_wake_fd) {
                uint64_t v = 0;
                const ssize_t rd = read(m_wake_fd, &v, sizeof(v));
                (void)rd;
                continue;
            }
            const uint32_t revents = events[i].events;
            auto it = m_conns.find(fd);
            if (it == m_conns.end())
                continue;
            if (revents & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
                drop_conn(fd, "对端关闭/连接错误");
                continue;
            }
            if (revents & EPOLLIN) {
                if (!read_conn(fd, it->second)) {
                    drop_conn(fd, "读失败/对端关闭");
                    continue;
                }
                if (it->second.session && it->second.session->tcp_drop.load()) {
                    drop_conn(fd, "会话请求断开");
                    continue;
                }
                if (!flush_conn_tx(fd, it->second)) {
                    drop_conn(fd, "发送失败");
                    continue;
                }
            }
            if (revents & EPOLLOUT) {
                if (!flush_conn_tx(fd, it->second)) {
                    drop_conn(fd, "发送失败");
                    continue;
                }
            }
        }
        pump_tx();
        for (auto it = m_conns.begin(); it != m_conns.end(); ) {
            const int fd = it->first;
            const bool drop = it->second.session && it->second.session->tcp_drop.load();
            ++it;
            if (drop)
                drop_conn(fd, "会话请求断开");
        }
    }
}

void TCPServer::wake()
{
    if (!m_running.load())
        return;
    if (m_wake_fd >= 0) {
        const uint64_t one = 1;
        const ssize_t n = write(m_wake_fd, &one, sizeof(one));
        (void)n;
    }
}

void TCPServer::pump_tx()
{
    for (auto it = m_conns.begin(); it != m_conns.end(); ) {
        const int fd = it->first;
        Conn& c = it->second;
        ++it;
        bool pending = false;
        if (c.session) {
            std::lock_guard<std::mutex> lock(c.session->tcp_tx_mutex);
            pending = !c.session->tcp_tx.empty();
        }
        if (pending || c.txOff < c.txBuf.size()) {
            if (!flush_conn_tx(fd, c)) {
                drop_conn(fd, "发送失败");
            }
        }
    }
}

void TCPServer::handle_accept()
{
    for (;;) {
        sockaddr_in peer{};
        socklen_t peer_len = sizeof(peer);
        const int fd = accept4(m_listen_fd, reinterpret_cast<sockaddr*>(&peer), &peer_len,
                               SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            if (errno == EINTR)
                continue;
            if (errno == EMFILE || errno == ENFILE) {
                fprintf(stderr, "[TCP] accept() fd 耗尽，暂停接收新连接\n");
                break;
            }
            fprintf(stderr, "[TCP] accept() failed: %s\n", strerror(errno));
            break;
        }

        {
            int one = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            const int bufsize = 4 * 1024 * 1024;
            setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
            setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
        }

        if (m_conns.size() >= kMaxTcpConns) {
            fprintf(stderr, "[TCP] TCP 连接数达上限 %zu，拒绝新连接\n", kMaxTcpConns);
            close(fd);
            continue;
        }

        std::shared_ptr<Session> s = m_udp.get_or_create_session(peer, true);
        if (!s) {
            close(fd);
            continue;
        }
        s->tcp_fd.store(fd);
        s->tcp_drop.store(false);

        epoll_event ev{};
        ev.events = EPOLLIN | EPOLLRDHUP;
        ev.data.fd = fd;
        if (epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
            fprintf(stderr, "[TCP] epoll_ctl(ADD) failed: %s\n", strerror(errno));
            s->tcp_fd.store(-1);
            m_udp.release_session(s->peer_key);
            close(fd);
            continue;
        }
        m_conns[fd] = Conn{ s, {} };
        fprintf(stderr, "[TCP] 新连接 %s fd=%d（当前会话 %d）\n",
                s->peer_key.c_str(), fd, m_udp.client_count());
    }
}

bool TCPServer::read_conn(int fd, Conn& c)
{
    if (c.readTmp.size() < 1441 + 64)
        c.readTmp.resize(1441 + 64);
    std::vector<uint8_t>& tmp = c.readTmp;
    int frames = 0;
    for (;;) {
        const ssize_t n = recv(fd, tmp.data(), tmp.size(), 0);
        if (n == 0)
            return false;
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;
            if (errno == EINTR)
                continue;
            fprintf(stderr, "[TCP] recv() failed (%s): %s\n",
                    c.session ? c.session->peer_key.c_str() : "?", strerror(errno));
            return false;
        }
        if (c.rxBuf.size() + static_cast<size_t>(n) > kMaxRxBufBytes) {
            fprintf(stderr, "[TCP] 接收缓冲超限 %zu，连接作废 (%s)\n",
                    kMaxRxBufBytes, c.session ? c.session->peer_key.c_str() : "?");
            return false;
        }
        c.rxBuf.insert(c.rxBuf.end(), tmp.data(), tmp.data() + n);

        for (;;) {
            if (c.rxBuf.size() < Ktunnel_header)
                break;
            tunnel_header hdr{};
            memcpy(&hdr, c.rxBuf.data(), Ktunnel_header);
            if (hdr.magic != Kmagic) {
                fprintf(stderr, "[TCP] 非法 magic=0x%08X，连接作废 (%s)\n",
                        hdr.magic, c.session ? c.session->peer_key.c_str() : "?");
                return false;
            }
            const size_t pay_len = ntohs(hdr.payload_len);
            if (pay_len > Max_payload_len) {
                fprintf(stderr, "[TCP] 帧超长: %zu，连接作废 (%s)\n", pay_len,
                        c.session ? c.session->peer_key.c_str() : "?");
                return false;
            }
            if (c.rxBuf.size() < Ktunnel_header + pay_len)
                break;

            if (c.session)
                m_udp.handle_framed(*c.session, hdr,
                                     c.rxBuf.data() + Ktunnel_header, pay_len);
            c.rxBuf.erase(c.rxBuf.begin(),
                          c.rxBuf.begin() + static_cast<std::ptrdiff_t>(Ktunnel_header + pay_len));

            if (c.session && c.session->tcp_drop.load())
                return false;
            if (++frames >= kReadFramesBudget) {
                return true;
            }
        }
    }
    return true;
}

bool TCPServer::flush_conn_tx(int fd, Conn& c)
{
    if (c.session) {
        std::deque<std::vector<uint8_t>> frames;
        {
            std::lock_guard<std::mutex> lock(c.session->tcp_tx_mutex);
            frames.swap(c.session->tcp_tx);
            c.session->tcp_tx_bytes = 0;
        }
        for (auto& f : frames)
            c.txBuf.insert(c.txBuf.end(), f.begin(), f.end());
    }
    bool blocked = false;
    while (c.txOff < c.txBuf.size()) {
        const ssize_t n = send(fd, c.txBuf.data() + c.txOff,
                               c.txBuf.size() - c.txOff, MSG_NOSIGNAL);
        if (n > 0) {
            c.txOff += static_cast<size_t>(n);
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            blocked = true;
            break;
        }
        fprintf(stderr, "[TCP] send() failed (%s): %s\n",
                c.session ? c.session->peer_key.c_str() : "?", strerror(errno));
        return false;
    }
    if (c.txOff >= c.txBuf.size()) {
        c.txBuf.clear();
        c.txOff = 0;
        if (c.txBuf.capacity() > 256 * 1024) {
            std::vector<uint8_t>().swap(c.txBuf);
        }
    } else if (c.txOff >= 4096) {
        c.txBuf.erase(c.txBuf.begin(), c.txBuf.begin() + static_cast<std::ptrdiff_t>(c.txOff));
        c.txOff = 0;
    }
    const bool need_out = (c.txOff < c.txBuf.size()) && blocked;
    if (need_out != c.want_epollout) {
        epoll_event ev{};
        ev.events = EPOLLIN | EPOLLRDHUP | (need_out ? EPOLLOUT : 0);
        ev.data.fd = fd;
        if (epoll_ctl(m_epoll_fd, EPOLL_CTL_MOD, fd, &ev) < 0) {
            fprintf(stderr, "[TCP] epoll_ctl(MOD) failed: %s\n", strerror(errno));
            return false;
        }
        c.want_epollout = need_out;
    }
    return true;
}

void TCPServer::drop_conn(int fd, const char* reason)
{
    auto it = m_conns.find(fd);
    if (it == m_conns.end())
        return;
    const std::shared_ptr<Session> s = std::move(it->second.session);
    m_conns.erase(it);
    epoll_ctl(m_epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
    if (s) {
        {
            std::lock_guard<std::mutex> lock(s->send_mutex);
            s->tcp_fd.store(-1);
            close(fd);
        }
        {
            std::lock_guard<std::mutex> lock(s->tcp_tx_mutex);
            s->tcp_tx.clear();
            s->tcp_tx_bytes = 0;
        }
        fprintf(stderr, "[TCP] 连接断开 fd=%d (%s): %s\n", fd, s->peer_key.c_str(), reason);
    } else {
        close(fd);
    }
    m_udp.release_session(s ? s->peer_key : std::string());
}
