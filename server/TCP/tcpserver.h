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
    // 每连接状态：会话 + 接收累积缓冲（分帧状态机）。仅事件线程访问
    struct Conn
    {
        std::shared_ptr<Session> session;
        std::vector<uint8_t> rxBuf;
    };

    void event_loop();
    void handle_accept();
    // 读事件：排空内核缓冲并处理所有完整帧；返回 false = 连接作废（调用方 drop）
    bool read_conn(int fd, Conn& c);
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
