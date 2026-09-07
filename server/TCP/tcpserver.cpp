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

// ============================================================================
// TCPServer 实现（类声明见 tcpserver.h）
// epoll 事件驱动：单事件线程管理监听 socket + 全部连接（非阻塞 fd），
// 取代旧"每连接一个线程 + detach"模型——连接数不再受线程数限制，
// fd 的 close 全部收敛在本线程（唯一 owner），跨线程只通过 Session.tcp_drop
// 标志请求断开。会话防护（pending 配额 / 每源上限 / 未认证 10s 清理）走
// UDP 类的 get_or_create_session / release_session，对 TCP 同样生效。
// ============================================================================

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
    // 重启场景：TIME_WAIT 状态下允许重绑同端口
    int reuse = 1;
    setsockopt(m_listen_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = listen_ip.empty() ? INADDR_ANY : inet_addr(listen_ip.c_str());
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
    // 唤醒管道：stop() 从别的线程写 eventfd，让阻塞中的 epoll_wait 立即返回
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
    return true;
}

void TCPServer::stop()
{
    if (!m_running.exchange(false))
        return;
    // 写 eventfd 唤醒 epoll_wait，事件线程在一个周期内退出
    if (m_wake_fd >= 0) {
        const uint64_t one = 1;
        const ssize_t n = write(m_wake_fd, &one, sizeof(one));
        (void)n;
    }
    if (m_event_thread.joinable())
        m_event_thread.join();
    // 线程已回收：统一关闭全部连接（本线程接管 fd 所有权，无并发）
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

// 事件线程：epoll_wait 驱动 accept / 读事件 / 断开请求扫描。
// 200ms 超时兜底：即使没有事件（含 stop() 唤醒丢失的极端情况）也能周期性
// 检查 m_running 与 tcp_drop 标志
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
                // stop() 唤醒：清空计数，回循环头检查 m_running
                uint64_t v = 0;
                const ssize_t rd = read(m_wake_fd, &v, sizeof(v));
                (void)rd;
                continue;
            }
            const uint32_t revents = events[i].events;
            // 事件数组中的 fd 可能已被前一个事件的处理清理：逐个重新查表
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
                }
            }
        }
        // 扫描其他线程请求断开的连接（发送队列满/发送失败/心跳超时/
        // disconnect/互踢）。规模 ≤ max-clients 且每 ≤200ms 一次，成本可忽略
        for (auto it = m_conns.begin(); it != m_conns.end(); ) {
            const int fd = it->first;
            const bool drop = it->second.session && it->second.session->tcp_drop.load();
            ++it;                 // 先前进再 drop（drop_conn 内部会 erase）
            if (drop)
                drop_conn(fd, "会话请求断开");
        }
    }
}

// accept：非阻塞排空 backlog，每连接挂会话（复用 pending 配额/每源上限），
// 注册 epoll 后由事件循环统一分帧处理
void TCPServer::handle_accept()
{
    for (;;) {
        sockaddr_in peer{};
        socklen_t peer_len = sizeof(peer);
        const int fd = accept4(m_listen_fd, reinterpret_cast<sockaddr*>(&peer), &peer_len,
                               SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (fd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;          // backlog 已排空
            if (errno == EINTR)
                continue;
            if (errno == EMFILE || errno == ENFILE) {
                fprintf(stderr, "[TCP] accept() fd 耗尽，暂停接收新连接\n");
                break;
            }
            fprintf(stderr, "[TCP] accept() failed: %s\n", strerror(errno));
            break;
        }

        // TCP_NODELAY：VPN 帧是小包频发（隧道头+密文），Nagle 会累积 40ms 级
        // 延迟（配合对端延迟 ACK 更糟），必须逐包即时发出；顺带放大收发缓冲
        {
            int one = 1;
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
            const int bufsize = 4 * 1024 * 1024;
            setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &bufsize, sizeof(bufsize));
            setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &bufsize, sizeof(bufsize));
        }

        // 取/建会话：pending 配额 / 每 IP 上限 / 未认证快速清理对 TCP 同样生效
        std::shared_ptr<Session> s = m_udp.get_or_create_session(peer);
        if (!s) {
            close(fd);         // 会话表满：丢弃连接
            continue;
        }
        s->tcp_fd = fd;
        s->tcp_drop.store(false);

        epoll_event ev{};
        ev.events = EPOLLIN | EPOLLRDHUP;
        ev.data.fd = fd;
        if (epoll_ctl(m_epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
            fprintf(stderr, "[TCP] epoll_ctl(ADD) failed: %s\n", strerror(errno));
            s->tcp_fd = -1;
            m_udp.release_session(s->peer_key);
            close(fd);
            continue;
        }
        m_conns[fd] = Conn{ s, {} };
        fprintf(stderr, "[TCP] 新连接 %s fd=%d（当前会话 %d）\n",
                s->peer_key.c_str(), fd, m_udp.client_count());
    }
}

// 读事件：非阻塞 recv 循环排空内核缓冲，一次吃完所有完整帧再回读
// （应用层读速度最大化，避免内核接收缓冲堆积）。
// 返回 false = 连接作废（对端关闭/致命错误/非法帧头），调用方 drop
bool TCPServer::read_conn(int fd, Conn& c)
{
    std::vector<uint8_t> tmp(1441 + 64);
    for (;;) {
        const ssize_t n = recv(fd, tmp.data(), tmp.size(), 0);
        if (n == 0)            // 对端优雅关闭
            return false;
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                break;         // 内核缓冲已排空：本连接这轮读完
            if (errno == EINTR)
                continue;
            fprintf(stderr, "[TCP] recv() failed (%s): %s\n",
                    c.session ? c.session->peer_key.c_str() : "?", strerror(errno));
            return false;
        }
        c.rxBuf.insert(c.rxBuf.end(), tmp.data(), tmp.data() + n);

        // 分帧：一次 recv 携带的多条粘包全部处理完再回读
        for (;;) {
            if (c.rxBuf.size() < Ktunnel_header)
                break;         // 半包：等下一段数据
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
                break;         // 半包：等下一段数据

            // 整帧到手：AAD = 帧头起始（handle_framed 内部由 payload 推导）。
            // handle_framed 的 disconnect 分支只置 tcp_drop（release 交本函数
            // 调用后的 drop_conn 统一收尾），之后不要再直接使用 session 表状态
            if (c.session)
                m_udp.handle_framed(*c.session, hdr,
                                     c.rxBuf.data() + Ktunnel_header, pay_len);
            c.rxBuf.erase(c.rxBuf.begin(),
                          c.rxBuf.begin() + static_cast<std::ptrdiff_t>(Ktunnel_header + pay_len));

            if (c.session && c.session->tcp_drop.load())
                return false;  // 处理中断开请求（disconnect/互踢等）：立即收尾
        }
    }
    return true;
}

// 断开收尾：本线程是 fd 唯一 owner。epoll 移除 + close + 会话释放（幂等：
// 会话可能已被其他路径释放，release_session 内部查表为空直接返回）
void TCPServer::drop_conn(int fd, const char* reason)
{
    auto it = m_conns.find(fd);
    if (it == m_conns.end())
        return;
    const std::shared_ptr<Session> s = std::move(it->second.session);
    m_conns.erase(it);
    epoll_ctl(m_epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
    close(fd);
    if (!s)
        return;
    s->tcp_fd = -1;   // fd 已关闭：send_packet/send_all 不再使用
    fprintf(stderr, "[TCP] 连接断开 fd=%d (%s): %s\n", fd, s->peer_key.c_str(), reason);
    m_udp.release_session(s->peer_key);
}
