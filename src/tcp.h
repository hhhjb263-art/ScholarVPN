#pragma once
// ============================================================================
// TCP 隧道：继承 UDP 基类，只覆写 4 个传输钩子 + 协议版本字节。
// 协议（三阶段认证 / AES-256-GCM / 心跳 / 队列 / 重连状态机）全部复用基类。
//
// 帧规则：每条消息 = tunnel_header(12B) + payload，按 payload_len 凑帧；
// 粘包/半包由本类的接收缓冲状态机处理，凑齐一帧交付一次。
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
    SOCKET open_socket() override;      // SOCK_STREAM（连接在 establish 里做）
    bool establish() override;          // 非阻塞 connect + 4s 超时 + TCP_NODELAY
    bool raw_send(const uint8_t* data, size_t len) override;   // send_all 循环写
    bool recv_frame(tunnel_header& hdr, const uint8_t*& payload,
                    size_t& pay_len, bool& got) override;      // 分帧状态机
                    // 返回 false = 连接死亡（收包线程应退出）

private:
    std::vector<uint8_t> m_rxBuf;       // 接收累积缓冲
    size_t m_rxHave = 0;                // 已收字节数
    size_t m_consumed = 0;              // 已交付帧字节数（下次调用先消费）
};