package com.scholarvpn.client.vpn

import kotlinx.coroutines.flow.MutableStateFlow

/**
 * VPN 连接状态（进程级单例）：Service 更新，UI 订阅。
 * phase 供 UI 判断"是否可断开"，message 为展示文本。
 * busyIndex = 正在连接/已连接的服务器卡片下标（-1 = 空闲），
 * UI 据此把断开按钮渲染在对应卡片上、禁用其他卡片。
 * TODO(M3)：接入完整界面时扩展结构化状态（虚拟 IP / 速率等）。
 */
object VpnStatus {
    enum class Phase { IDLE, CONNECTING, CONNECTED, RECONNECTING, FAILED }

    val phase = MutableStateFlow(Phase.IDLE)
    val message = MutableStateFlow("未连接")
    val busyIndex = MutableStateFlow(-1)   // 忙碌中的卡片下标（-1=无）

    /** 令牌被服务端消费/作废后由 Service 递增，UI 收到即刷新卡片列表（防废令牌回写） */
    val tokenClearTick = MutableStateFlow(0)

    /** 连接进行中（含重连等待）——期间不允许再发起连接 */
    fun isBusy(phase: Phase): Boolean =
        phase == Phase.CONNECTING || phase == Phase.CONNECTED || phase == Phase.RECONNECTING
}
