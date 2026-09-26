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

namespace {
// 真实 TCP 连接数硬上限（独立于会话配额：未认证连接同样占 fd/内存）
constexpr size_t kMaxTcpConns = 128;
// read_conn 单连接单轮预算：最多处理 64 帧（突发流量下单连接不再长期
// 独占事件线程，其他连接/监听/断开扫描按轮次获得服务）
constexpr int kReadFramesBudget = 64;
// 接收累积缓冲上限：远超合法半帧（~2×1441B）即视为恶意流（只发帧头
// 不发载荷），断开连接防内存无界增长
constexpr size_t kMaxRxBufBytes = 512 * 1024;
} // namespace

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
    if(listen_ip.empty()){
        addr.sin_addr.s_addr = INADDR_ANY;
    }else{
        int ret = inet_pton(AF_INET,listen_ip.c_str(),&addr.sin_addr);
        // 返回 0 = 格式非法：若不拦截会落到 sin_addr.s_addr=0，等于意外监听 0.0.0.0
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

    // 注册跨线程唤醒钩子：send_packet 把已加密整帧提交进 Session.tcp_tx 后
    // 经此写入 eventfd，事件循环立即排空写出（否则最坏 200ms 才被发现）
    m_udp.set_tcp_tx_wake([this] { wake(); });
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
    // 唤醒钩子注销（调用方 VpnCore::stop 已先停 UDP 线程，此后无并发读者；
    // 即使 TCP 独立启停，互斥保护下的注销也安全）
    m_udp.set_tcp_tx_wake(nullptr);
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
                    continue;
                }
                // 读路径处理期间可能产生回包（心跳应答/identity_ok）：
                // 立即 flush 降低延迟，不等下一轮 pump
                if (!flush_conn_tx(fd, it->second)) {
                    drop_conn(fd, "发送失败");
                    continue;
                }
            }
            if (revents & EPOLLOUT) {
                // socket 由满转可写：续写 txBuf
                if (!flush_conn_tx(fd, it->second)) {
                    drop_conn(fd, "发送失败");
                    continue;
                }
            }
        }
        // 排空所有连接的跨线程提交帧（唤醒兜底：即使 eventfd 唤醒丢失，
        // 200ms 周期也会处理）+ 扫描断开请求
        pump_tx();
        // 扫描其他线程请求断开的连接（发送积压超限/心跳超时/
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

// eventfd 唤醒：stop() 与"跨线程有帧待发"共用。未运行/未初始化时静默
// （钩子注册后 UDP 线程仍可能最后一次调用，此时连接已统一关闭）
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

// 每轮事件循环末尾：搬运所有连接会话队列里的待发帧并尽力写出。
// 连接数 ≤ max-clients（默认 64），每轮一次全表扫描成本可忽略
void TCPServer::pump_tx()
{
    for (auto it = m_conns.begin(); it != m_conns.end(); ) {
        const int fd = it->first;
        Conn& c = it->second;
        ++it;                 // 先前进（drop_conn 会 erase 当前项）
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

        // 真实 TCP 连接数硬上限：会话配额挡不住"接受连接后建会话失败/被淘汰"
        // 的连接堆积（未认证 fd 同样占用内存与文件描述符）
        if (m_conns.size() >= kMaxTcpConns) {
            fprintf(stderr, "[TCP] TCP 连接数达上限 %zu，拒绝新连接\n", kMaxTcpConns);
            close(fd);
            continue;
        }

        // 取/建会话：pending 配额 / 每 IP 上限 / 未认证快速清理对 TCP 同样生效
        std::shared_ptr<Session> s = m_udp.get_or_create_session(peer, true);
        if (!s) {
            close(fd);         // 会话表满：丢弃连接
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

// 读事件：非阻塞 recv 循环排空内核缓冲，单轮预算内处理所有完整帧
// （预算=64 帧：突发流量下单连接不再长期独占事件线程；预算用尽或内核
// 缓冲排空即返回，level-triggered epoll 下一轮继续。帧头/载荷校验失败、
// 接收缓冲超限 = 恶意流，直接断开防内存无界增长）。
// 返回 false = 连接作废（对端关闭/致命错误/非法帧头），调用方 drop
bool TCPServer::read_conn(int fd, Conn& c)
{
    // 临时接收缓冲挂在连接上复用（原先每次调用新建一个 1.5KB vector：
    // 这函数每收到一段数据就跑一次，是热路径上的堆分配/释放）
    if (c.readTmp.size() < 1441 + 64)
        c.readTmp.resize(1441 + 64);
    std::vector<uint8_t>& tmp = c.readTmp;
    int frames = 0;
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
        if (c.rxBuf.size() + static_cast<size_t>(n) > kMaxRxBufBytes) {
            fprintf(stderr, "[TCP] 接收缓冲超限 %zu，连接作废 (%s)\n",
                    kMaxRxBufBytes, c.session ? c.session->peer_key.c_str() : "?");
            return false;
        }
        c.rxBuf.insert(c.rxBuf.end(), tmp.data(), tmp.data() + n);

        // 分帧：一次 recv 携带的多条粘包全部处理完再回读（预算内）
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
            if (++frames >= kReadFramesBudget) {
                return true;   // 预算用尽：剩余数据留给下一轮（其他连接先服务）
            }
        }
    }
    return true;
}

// 发送：把 Session.tcp_tx 的跨线程提交帧搬进 txBuf，从 txOff 起非阻塞写。
// socket 满（EAGAIN）即返回并订阅 EPOLLOUT——事件线程绝不为慢客户端
// 阻塞（原 send_all_fd 在共享发送线程/事件线程上最多轮询 5s 的瓶颈）。
// 返回 false = 连接作废（调用方 drop）
bool TCPServer::flush_conn_tx(int fd, Conn& c)
{
    // 1) 搬运跨线程提交的整帧（mutex 只覆盖队列操作，锁内无系统调用）
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
    // 2) 尽力写出
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
    // 3) 收缩已发完的空间（整帧写完直接清空；部分帧少量前移，避免
    // 每次都 memmove 整个缓冲）
    if (c.txOff >= c.txBuf.size()) {
        c.txBuf.clear();
        c.txOff = 0;
        if (c.txBuf.capacity() > 256 * 1024) {
            std::vector<uint8_t>().swap(c.txBuf);   // 释放峰值容量
        }
    } else if (c.txOff >= 4096) {
        c.txBuf.erase(c.txBuf.begin(), c.txBuf.begin() + static_cast<std::ptrdiff_t>(c.txOff));
        c.txOff = 0;
    }
    // 4) 订阅 EPOLLOUT：仅当仍有未发数据且 socket 已满
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

// 断开收尾：本线程是 fd 唯一 owner。epoll 移除 + close + 会话释放（幂等：
// 会话可能已被其他路径释放，release_session 内部查表为空直接返回）。
// close 与发送互斥：send_packet（send_work/heartbeat 线程）持 send_mutex
// 提交整帧到 tcp_tx 队列——close 必须先拿到同一把锁再摘除 fd，杜绝
// "发送线程拿旧 fd 写到被系统复用的新连接"的竞争
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
            s->tcp_fd.store(-1);   // fd 已关闭：send_packet 不再使用
            close(fd);
        }
        // 清空跨线程待发队列（已加密帧随连接一起丢弃，防止
        // "连接已死、队列还在积压"的内存滞留）
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
