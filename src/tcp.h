#pragma once
// ============================================================================
// TCP 隧道：继承 UDP 基类，只覆写 4 个传输钩子 + 协议版本字节。
// 协议（三阶段认证 / AES-256-GCM / 心跳 / 队列 / 重连状态机）全部复用基类。
//
// socket 保持非阻塞：读侧 recv_frame 用 WSAPoll 短超时等数据（无 sleep 轮询），
// 写侧 raw_send 用 WSAPoll 等可写；stop() 靠 closesocket 让 poll 立即出错返回。
//
// 帧规则：每条消息 = tunnel_header(12B) + payload，按 payload_len 凑帧。
// recv_frame 先吃接收缓冲：粘包帧逐帧连续交付（外层循环每帧调一次，
// 交付期间不碰 recv），缓冲不足才 poll+recv 补数据。
// 协议版本：TCP 帧标 v_tcp（错误传输的报文在接收侧 version 校验被丢弃）。
// 实现在 tcp.cpp；本头文件仅声明。
// ============================================================================

#include "UDP.h"
#include <vector>

class TCP : public UDP
{
public:
    TCP(const char* remoteip, uint16_t port,
        bool is_running = false, size_t queueMax = 4096);

    // 协议版本：TCP 帧标 v_tcp
    uint8_t proto_version() const override;

protected:
    // ---- 传输钩子（基类声明，此处覆写）----
    sock_t open_socket() override;      // SOCK_STREAM（连接在 establish 里做）
    bool establish() override;          // 非阻塞 connect + 4s 超时 + TCP_NODELAY
    bool raw_send(const uint8_t* data, size_t len) override;   // send_all 循环写
    bool recv_frame(tunnel_header& hdr, const uint8_t*& payload,
                    size_t& pay_len, bool& got) override;      // 分帧状态机
                    // 返回 false = 连接死亡（收包线程应退出）

private:
    // 从接收缓冲取一帧（不动 socket）：1=整帧已交付 0=数据不足 -1=非法帧（连接作废）
    int take_frame(tunnel_header& hdr, const uint8_t*& payload, size_t& pay_len);
    // 回收已消费的前缀（只在"读空"或"已消费超过 64KB"时做一次 memmove，
    // 不再是每帧一次 vector::erase）
    void compact_rx();

    // 把 m_txPending 里没写完的字节尽力冲出去（预算 200ms，写不动就留着）。
    // @return false = 连接已死（致命错误，调用方应停止发送）
    bool flush_tx_pending();

    std::vector<uint8_t> m_rxBuf;       // 接收累积缓冲（可能同时含多帧）
    size_t m_rxOff = 0;                 // 已消费前缀长度（有效数据从 data()+m_rxOff 起）
    size_t m_consumed = 0;              // 上一帧交付的字节数（下次调用先推进 m_rxOff）

    // ---- 发送积压 ----
    // 为什么需要它：外层 TCP 是可靠传输，应用层一旦丢帧就等于人为制造丢包，
    // 内层 TCP 会把它当拥塞信号反复重传 + 砍拥塞窗口，吞吐直接塌陷
    // （TCP-over-TCP 最忌讳的做法）。所以 socket 暂时不可写时不再丢帧，
    // 而是把整帧留在这里，等 socket 可写再冲出去。
    //
    // 只在 m_send_mutex 保护下访问（send_packet 持锁调 raw_send，
    // send_work 与 recv_work 两个线程因此天然串行），不需要额外加锁。
    std::vector<uint8_t> m_txPending;
    size_t m_txPendingOff = 0;          // 已写出前缀长度
    uint32_t m_txBacklogLogged = 0;     // "转入积压"日志的已打印次数（限流，防刷屏）
};