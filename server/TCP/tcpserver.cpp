#include "tcpserver.h"
#include "../core/log.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <vector>

// ============================================================================
// TCPServer 实现（类声明见 tcpserver.h）
// 会话防护（pending 配额 / 每源上限 / 未认证 10s 清理）走 UDP 类的
// get_or_create_session / release_session，对 TCP 同样生效。
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

    m_listen_fd = socket(AF_INET, SOCK_STREAM, 0);
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
    if (listen(m_listen_fd, 16) < 0) {
        fprintf(stderr, "[TCP] listen() failed: %s\n", strerror(errno));
        close(m_listen_fd);
        m_listen_fd = -1;
        return false;
    }

    m_listen_ip = listen_ip;
    m_port = port;
    m_running.store(true);
    m_accept_thread = std::thread(&TCPServer::accept_loop, this);
    fprintf(stderr, "[TCP] 监听 %s:%u（同端口双栈，等待客户端 TCP 连接）\n",
            listen_ip.c_str(), static_cast<unsigned>(port));
    return true;
}

void TCPServer::stop()
{
    if (!m_running.exchange(false))
        return;
    // 关闭监听 socket：accept 的阻塞调用被唤醒并退出线程。
    // 存量连接由对端断开/心跳超时/进程退出自然终结（学习项目取舍）
    if (m_listen_fd >= 0) {
        close(m_listen_fd);
        m_listen_fd = -1;
    }
    if (m_accept_thread.joinable())
        m_accept_thread.join();
    fprintf(stderr, "[TCP] 监听已停止\n");
}

// accept 线程：每连接取/建会话（复用 pending 配额/每源上限防护），
// 挂上 tcp_fd 后交给独立的分帧收包线程。
// 用 poll 超时循环而非裸阻塞 accept()：stop() 从别的线程 close() 监听 fd
// 无法可靠打断 Linux 上阻塞中的 accept()（信号还会被 SA_RESTART 自动重启），
// 会导致 join(accept 线程) 永远等不到、Ctrl+C 后进程无法退出。
void TCPServer::accept_loop()
{
    while (m_running.load()) {
        struct pollfd pfd{};
        pfd.fd = m_listen_fd;
        pfd.events = POLLIN;
        pfd.revents = 0;
        // 500ms 超时：stop() 后最多一个周期内退出（关闭 fd 也会让 poll 返回）
        const int pr = poll(&pfd, 1, 500);
        if (pr <= 0)
            continue;                       // 超时 / fd 已关闭 / 被信号打断：回到循环头检查 m_running
        if ((pfd.revents & POLLIN) == 0)
            continue;                       // POLLNVAL/POLLERR 等：下轮重新 poll

        sockaddr_in peer{};
        socklen_t peer_len = sizeof(peer);
        int fd = accept(m_listen_fd, reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (fd < 0) {
            if (!m_running.load())
                break;              // stop() 关闭监听导致，正常退出
            // 瞬时错误（ECONNABORTED 等）：继续 accept，绝不退出线程
            fprintf(stderr, "[TCP] accept() failed: %s\n", strerror(errno));
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
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
            close(fd);
            continue;               // 会话表满：丢弃连接
        }
        s->tcp_fd = fd;
        fprintf(stderr, "[TCP] 新连接 %s（当前会话 %d）\n",
                s->peer_key.c_str(), m_udp.client_count());

        // 每连接收包线程：分帧 -> handle_framed。detach 简化生命周期：
        // 线程退出条件 = 连接死亡（自身关 fd + release_session）或进程退出
        std::thread(&TCPServer::conn_loop, this, s, fd).detach();
    }
}

// 每连接收包线程：recv -> 喂接收缓冲 -> 分帧凑齐一条 -> handle_framed。
// 帧规则：tunnel_header(12B) + payload；客户端 TCP 帧标 v_tcp，
// handle_framed 内部按会话传输类型（tcp_fd >= 0 -> v_tcp）校验/回包。
void TCPServer::conn_loop(std::shared_ptr<Session> s, int fd)
{
    std::vector<uint8_t> rxBuf;         // 接收累积缓冲
    size_t rxHave = 0;
    size_t consumed = 0;                // 已交付帧字节数（下次循环先消费）
    std::vector<uint8_t> tmp(1441 + 64);

    for (;;) {
        ssize_t n = recv(fd, tmp.data(), tmp.size(), 0);
        if (n == 0) {           // 对端优雅关闭
            fprintf(stderr, "[TCP] 客户端断开: %s\n", s->peer_key.c_str());
            break;
        }
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
            if (errno == EINTR)
                continue;
            fprintf(stderr, "[TCP] recv() failed (%s): %s\n",
                    s->peer_key.c_str(), strerror(errno));
            break;
        }
        rxBuf.insert(rxBuf.end(), tmp.data(), tmp.data() + n);
        rxHave += static_cast<size_t>(n);

        // 分帧循环：一次 recv 可能携带多条粘包，凑齐一条处理一条
        for (;;)
        {
            if (rxHave < Ktunnel_header)        // 半包：等下一段数据
                break;
            tunnel_header hdr{};
            memcpy(&hdr, rxBuf.data(), Ktunnel_header);
            if (hdr.magic != Kmagic) {
                fprintf(stderr, "[TCP] 非法 magic=0x%08X，连接作废 (%s)\n",
                        hdr.magic, s->peer_key.c_str());
                close(fd);
                m_udp.release_session(s->peer_key);
                return;
            }
            size_t pay_len = ntohs(hdr.payload_len);            if (pay_len > Max_payload_len) {
                fprintf(stderr, "[TCP] 帧超长: %zu，连接作废 (%s)\n", pay_len, s->peer_key.c_str());
                close(fd);
                m_udp.release_session(s->peer_key);
                return;
            }
            if (rxHave < Ktunnel_header + pay_len)     // 半包：等下一段数据
                break;

            // 整帧到手：AAD = 帧头起始（handle_framed 内部由 payload 推导）
            m_udp.handle_framed(*s, hdr, rxBuf.data() + Ktunnel_header, pay_len);

            // handle_framed 的 disconnect 分支可能已 release 会话：
            // 引用是否仍在表中不再重要，本连接随客户端断开自然终结
            consumed = Ktunnel_header + pay_len;
            rxBuf.erase(rxBuf.begin(), rxBuf.begin() + static_cast<std::ptrdiff_t>(consumed));
            rxHave -= consumed;
        }
    }

    // 连接死亡统一收尾：关 fd + 释放会话（配额即时归还）
    close(fd);
    m_udp.release_session(s->peer_key);
}