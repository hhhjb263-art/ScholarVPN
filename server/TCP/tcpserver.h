#pragma once
// ============================================================================
// TCPServer —— 服务端 TCP 传输模式（epoll 事件驱动）
// 单线程事件循环管理监听 socket 与全部客户端连接（连接 fd 全部非阻塞）：
//   - accept：复用 UDP 类的会话防护（pending 配额 / 每源上限 / 未认证清理）
//   - 读事件：排空内核缓冲，一次吃完所有完整帧（handle_framed 共用）
//   - 断开：本线程是连接 fd 的唯一 owner（统一 close）；
//     其他线程（发送队列满 / 发送失败 / 心跳超时 / disconnect / 同身份互踢）
//     通过 Session.tcp_drop 标志请求断开，事件循环周期性扫描执行，
//     杜绝跨线程 close 的 fd 复用竞争
// 会话表 / 认证 / 加密 / 心跳全部复用 UDP 类（组合引用），
// 每条连接的会话带 tcp_fd，send_packet 按 fd 分流。
// 帧规则：每条消息 = tunnel_header(12B) + payload，按 payload_len 凑帧；
// 客户端 TCP 帧标 v_tcp，服务端按会话传输类型校验/回包。
// ============================================================================

#include "../UDP/UDP.h"
#include "../UDP/Session.h"

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

class TCPServer
{
public:
    explicit TCPServer(UDP& udp);
    ~TCPServer();

    TCPServer(const TCPServer&) = delete;
    TCPServer& operator=(const TCPServer&) = delete;

    // 监听 listen_ip:port（与 UDP 同端口双栈），启动 epoll 事件线程
    bool start(const std::string& listen_ip, uint16_t port);
    // 停止：唤醒并回收事件线程，统一关闭全部连接与监听 socket
    void stop();
    bool is_running() const { return m_running.load(); }

private:
private:
    // 每连接状态：会话 + 接收累积缓冲（分帧状态机）+ 发送缓冲。
    // 全部仅事件线程访问（跨线程提交的帧先落在 Session.tcp_tx，
    // 由事件线程 pump_tx/flush_conn_tx 搬运到 txBuf 再写 socket）
    struct Conn
    {
        std::shared_ptr<Session> session;
        std::vector<uint8_t> rxBuf;
        // 待发缓冲：跨线程入队的已加密整帧 + 尚未写完的部分帧；
        // txOff = 已写出偏移。socket 满（EAGAIN）时订阅 EPOLLOUT 续写
        std::vector<uint8_t> txBuf;
        size_t txOff = 0;
        bool want_epollout = false;
    };

    void event_loop();
    void handle_accept();
    // 读事件：排空内核缓冲并处理所有完整帧；返回 false = 连接作废（调用方 drop）
    bool read_conn(int fd, Conn& c);
    // 发送：把 Session.tcp_tx 的跨线程提交帧搬进 txBuf 并非阻塞写出；
    // 未写完订阅 EPOLLOUT。返回 false = 连接作废（调用方 drop）
    bool flush_conn_tx(int fd, Conn& c);
    // 每轮事件循环末尾：排空所有连接的待发队列（唤醒兜底）
    void pump_tx();
    // eventfd 唤醒（stop 与跨线程"有帧待发"共用；未运行时静默）
    void wake();
    // 断开收尾：epoll 移除 + close（唯一 owner）+ 会话释放。幂等
    void drop_conn(int fd, const char* reason);

    UDP& m_udp;                 // 会话表 + 消息处理 + 发送（经 Session.tcp_fd）
    int m_listen_fd = -1;
    int m_epoll_fd = -1;
    int m_wake_fd = -1;         // eventfd：stop() 唤醒阻塞中的 epoll_wait
    std::string m_listen_ip;
    uint16_t m_port = 0;
    std::atomic<bool> m_running{ false };
    std::thread m_event_thread;
    std::unordered_map<int, Conn> m_conns;   // fd → 连接状态（仅事件线程访问）
};
