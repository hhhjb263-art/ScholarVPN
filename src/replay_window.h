#pragma once
#include <cstdint>

// ============================================================================
// 反重放滑动窗口（收端校验，对密文帧生效；WireGuard/IPsec 同款语义）
//   每帧 sequence 在 AAD 内不可篡改，且发送端每次发送都递增（重传也是
//   新序号），故"同一序号再次出现"必然是重放/网络复制：
//     seq > highest             → 放行并滑动窗口
//     highest-窗口内且未见过     → 放行（正常 UDP 乱序）
//     其余                      → 静默丢弃（不断连，防注入式 DoS）
// 线程约定：handle_frame 仅在 recv 线程执行（天然串行），无需加锁；
//           与服务端 Session::ReplayWindow 语义一致（64 位位图）。
// 重要：accept() 会修改状态，必须在 AES-GCM 验证成功【之后】调用；
//       解密前只允许 too_old()（不修改状态）做廉价预检——未认证报文
//       不能推进窗口（否则伪造高序号会污染窗口，合法报文被误判太旧）。
// 实例随隧道连接重置（新会话新密钥，init()/stop() 调 reset()）。
// ============================================================================
class ReplayWindow {
public:
    // seq 为主机序；返回 true = 放行，false = 重放帧（丢弃）。
    // 只应在帧通过 GCM 验证后调用
    bool accept(uint32_t seq)
    {
        const uint64_t s = seq;
        if (m_highest == kNone) {
            m_highest = s;
            m_window = 1;
            return true;
        }
        if (s > m_highest) {
            const uint64_t shift = s - m_highest;
            m_window = (shift >= kWindow) ? 1 : ((m_window << shift) | 1);
            m_highest = s;
            return true;
        }
        const uint64_t age = m_highest - s;
        if (age >= kWindow)
            return false;   // 太旧（已滑出窗口）
        const uint64_t bit = 1ull << age;
        if (m_window & bit)
            return false;   // 已见过：重放
        m_window |= bit;
        return true;
    }

    // 不修改状态的"过旧"预检（解密前调用）：未初始化/比最高序号新/窗口内
    // 均返回 false；已见最高序号之外太旧的返回 true
    bool too_old(uint32_t seq) const
    {
        if (m_highest == kNone)
            return false;
        const uint64_t s = seq;
        if (s > m_highest)
            return false;
        return (m_highest - s) >= kWindow;
    }

    void reset()
    {
        m_highest = kNone;
        m_window = 0;
    }

private:
    static constexpr uint64_t kWindow = 64;
    static constexpr uint64_t kNone = ~0ull;   // 未初始化哨兵
    uint64_t m_highest = kNone;
    uint64_t m_window = 0;
};
