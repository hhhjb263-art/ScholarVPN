package com.scholarvpn.client.vpn

import kotlinx.coroutines.flow.MutableStateFlow

object VpnStatus {
    enum class Phase { IDLE, CONNECTING, CONNECTED, RECONNECTING, FAILED }

    val phase = MutableStateFlow(Phase.IDLE)
    val message = MutableStateFlow("未连接")
    val busyIndex = MutableStateFlow(-1)

    val tokenClearTick = MutableStateFlow(0)

    fun isBusy(phase: Phase): Boolean =
        phase == Phase.CONNECTING || phase == Phase.CONNECTED || phase == Phase.RECONNECTING
}
