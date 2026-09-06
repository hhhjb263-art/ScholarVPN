#pragma once
// ============================================================================
// TCPServer —— 服务端 TCP 传输模式
// 监听/accept 线程 + 每连接分帧线程；会话表 / 认证 / 加密 / 心跳全部
// 复用 UDP 类（组合引用），每条连接的会话带 tcp_fd，send_packet 按 fd 分流。
// 帧规则：每条消息 = tunnel_header(12B) + payload，按 payload_len 凑帧；
// 客户端 TCP 帧标 v_tcp，服务端按会话传输类型校验/回包。
// ============================================================================

#include "../UDP/UDP.h"
#include "../UDP/Session.h"

#include <atomic>
#include <memory>
#include <string>
#include <thread>

class TCPServer
{
public:
    explicit TCPServer(UDP& udp);
    ~TCPServer();

    TCPServer(const TCPServer&) = delete;
    TCPServer& operator=(const TCPServer&) = delete;

    // 监听 listen_ip:port（与 UDP 同端口双栈），启动 accept 线程
    bool start(const std::string& listen_ip, uint16_t port);
    // 停止：关闭监听 socket（accept 线程退出）；存量连接随进程/对端断开自然终结
    void stop();
    bool is_running() const { return m_running.load(); }

private:
    void accept_loop();
    // 每连接收包线程：分帧状态机 -> handle_framed（会话表/认证/加密共用）。
    // 连接死亡：关闭 fd + release_session（配额即时归还）
    void conn_loop(std::shared_ptr<Session> s, int fd);

    UDP& m_udp;                 // 会话表 + 消息处理 + 发送（经 Session.tcp_fd）
    int m_listen_fd = -1;
    std::string m_listen_ip;
    uint16_t m_port = 0;
    std::atomic<bool> m_running{ false };
    std::thread m_accept_thread;
};