package com.scholarvpn.client.tunnel

/**
 * 反重放滑动窗口（WireGuard/IPsec 同款语义）。
 *
 * 每帧 sequence 在 AAD 内不可篡改，且两端每次发送都递增（重传也是新序号），
 * 因此"同一序号再次出现"必然是重放/网络复制——用滑窗识别：
 *   seq > highest          → 放行，滑动窗口
 *   highest-窗口内且未见过  → 放行（正常 UDP 乱序）
 *   其余                   → 静默丢弃（不断连，防注入式 DoS）
 *
 * 重要：accept() 会修改状态，必须在 AES-GCM 验证成功【之后】调用；
 * 解密前只允许 isStale()（不修改状态）做廉价预检——未认证报文不能推进
 * 窗口（否则伪造高序号会污染窗口，后续合法报文被误判太旧）。
 *
 * 实例与隧道会话同生命周期：重连 = 新会话新密钥，窗口自然重置。
 * 注：32 位序号回绕由发送侧在 2^31 处强制换会话规避（TunnelClient），
 * 本窗口单会话生命周期内不会遇到回绕。
 */
class ReplayWindow(private val size: Int = 64) {
    init { require(size in 1..64) { "窗口必须 ≤64（Long 位图）" } }

    private var highest = -1L        // 已见最高序号（-1 = 未初始化）
    private var window = 0L          // 位 i = (highest - i) 已见过

    /** 不修改状态的"过旧"预检（解密前调用）：true = 太旧必是重放，直接丢弃 */
    @Synchronized
    fun isStale(seq: Long): Boolean {
        if (highest < 0) return false
        if (seq > highest) return false
        return highest - seq >= size
    }

    /** @return true = 放行；false = 重放帧（丢弃）。只应在帧验签成功后调用 */
    @Synchronized
    fun accept(seq: Long): Boolean {
        if (highest < 0) {
            highest = seq
            window = 1L
            return true
        }
        if (seq > highest) {
            val shift = (seq - highest).coerceAtMost(size.toLong()).toInt()
            window = if (shift >= size) 1L else ((window shl shift) or 1L)
            highest = seq
            return true
        }
        val age = highest - seq
        if (age >= size) return false          // 太旧（已滑出窗口）
        val bit = 1L shl age.toInt()
        if (window and bit != 0L) return false // 已见过：重放
        window = window or bit
        return true
    }
}
