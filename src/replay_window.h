#pragma once
#include <cstdint>

class ReplayWindow {
public:
    // 会推进窗口，必须在 AEAD 验证通过后调用；解密前只能用 too_old() 做预检
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
            return false;
        const uint64_t bit = 1ull << age;
        if (m_window & bit)
            return false;
        m_window |= bit;
        return true;
    }

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
    static constexpr uint64_t kNone = ~0ull;
    uint64_t m_highest = kNone;
    uint64_t m_window = 0;
};
