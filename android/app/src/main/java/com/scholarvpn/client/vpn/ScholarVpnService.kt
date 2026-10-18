package com.scholarvpn.client.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.provider.Settings
import android.util.Log
import androidx.core.app.NotificationCompat
import com.scholarvpn.client.MainActivity
import com.scholarvpn.client.tunnel.TunnelClient
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Android VPN 服务：平台的"虚拟网卡"。
 *
 * establish() 返回的 fd 即 tun 设备——对应 Windows 端 WintunTun；
 * addAddress/addRoute/addDnsServer 由系统托管——对应 AdapterConfig/RouteManager/DnsLeakGuard
 * 的角色（DNS 防泄漏 = 路由强制走隧道，系统自动回切）。
 *
 * 数据通路（照抄 ClientApp 的两个桥接循环）：
 *   线程1  tun fd 读 IP 包 → tunnel.sendData()     （上行）
 *   协程2  tunnel.incomingPackets → tun fd 写       （下行）
 *
 * 链路自愈（对应 C++ ReconnectManager）：隧道死亡（WiFi↔移动网络切换 /
 * 心跳超时 / 对端断开）→ 指数退避自动重连（1s→2s→…→30s 封顶），
 * 认证通过即重置计数；身份被拒（AuthDenied）不再重试（重试无意义）。
 */
class ScholarVpnService : VpnService() {

    companion object {
        const val TAG = "ScholarVpn"
        const val ACTION_CONNECT = "com.scholarvpn.client.CONNECT"
        const val ACTION_DISCONNECT = "com.scholarvpn.client.DISCONNECT"
        private const val CHANNEL_ID = "vpn"
        private const val NOTIFICATION_ID = 1
        private const val RECONNECT_BASE_MS = 1_000L
        private const val RECONNECT_MAX_MS = 30_000L
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var tunnel: TunnelClient? = null
    private val running = AtomicBoolean(false)
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    // ---- 物理网络监听（事件驱动，替代纯心跳超时探测） ----

    private val cm by lazy { getSystemService(ConnectivityManager::class.java) }

    /** 当前可见的物理网络集合（不含 VPN 自己） */
    private val physicalNetworks = mutableSetOf<Network>()

    /** 防抖：网络抖动（如 WiFi 短暂扫描）可能连续回调，2s 内不重复判死 */
    private val lastNetEventMs = AtomicLong(0L)
    private var netWatchRegistered = false

    /**
     * 重连退避的「提前唤醒」信号。
     *
     * 退避等待期间若物理网络恢复，没必要把剩下的 30s 等完——网络一回来就重试。
     * CONFLATED：多次网络事件只保留一个信号；每次进退避前清空残留，
     * 避免"上一次的旧信号"让下一次退避瞬间穿透（那样等于没有退避）。
     */
    private val retrySignal = Channel<Unit>(Channel.CONFLATED)

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            val first = synchronized(physicalNetworks) {
                val wasEmpty = physicalNetworks.isEmpty()
                physicalNetworks.add(network)
                wasEmpty
            }
            Log.i(TAG, "物理网络可用: $network（当前 ${physicalNetworks.size} 个）")
            if (first) tunnel?.onPhysicalNetworkAvailable()
            // 网络一恢复就打断退避等待：重连成功的那一刻往往就是网络刚回来的那一刻，
            // 让用户少等最多 30s
            retrySignal.trySend(Unit)
        }

        override fun onLost(network: Network) {
            val remaining = synchronized(physicalNetworks) {
                physicalNetworks.remove(network)
                physicalNetworks.size
            }
            Log.i(TAG, "物理网络丢失: $network（剩余 $remaining 个）")

            // 关键判断：只要**任何**物理网络丢失就判死重连。
            // 理由：Java Socket 在创建时绑定到当时默认网络的源地址，WiFi 断掉后
            // 即使 4G 还在，旧 socket 的源 IP 也已失效——不重建连接就永远收不到包。
            // 重连成本（约 3~4s 三阶段握手）远低于干等 25s 心跳超时。
            //
            // 2s 防抖：WiFi 扫描/信号抖动可能连续回调，避免打出重连风暴
            val now = System.currentTimeMillis()
            val prev = lastNetEventMs.get()
            if (now - prev >= 2_000L && lastNetEventMs.compareAndSet(prev, now)) {
                tunnel?.onPhysicalNetworkLost()
            }
        }
    }

    /**
     * 注册物理网络监听。只监听 WIFI / CELLULAR / ETHERNET，
     * 不含 TRANSPORT_VPN——否则会收到自己建立的 tun 网络，形成"自己切换自己"的循环。
     */
    private fun registerNetworkWatch() {
        if (netWatchRegistered) return
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
            .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
            .addTransportType(NetworkCapabilities.TRANSPORT_ETHERNET)
            .build()
        netWatchRegistered = runCatching {
            cm.registerNetworkCallback(request, networkCallback)
            true
        }.getOrElse {
            Log.w(TAG, "注册网络监听失败（降级为纯心跳探测）: ${it.message}")
            false
        }
    }

    private fun unregisterNetworkWatch() {
        if (!netWatchRegistered) return
        netWatchRegistered = false
        runCatching { cm.unregisterNetworkCallback(networkCallback) }
        synchronized(physicalNetworks) { physicalNetworks.clear() }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // 每条启动来源都记一行日志：下次"它又自己连上了"可以直接从 logcat 看出是谁拉起的
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                Log.i(TAG, "onStartCommand: 断开（用户点击/通知按钮）")
                stopVpn()
                return START_NOT_STICKY
            }
            ACTION_CONNECT -> {
                Log.i(TAG, "onStartCommand: 连接（用户点击）")
                startVpn("连接中…")
            }
            // 系统拉起：VpnService.SERVICE_INTERFACE = "android.net.VpnService"。
            // 「始终开启的 VPN」（Always-on）在 VPN 被断开后、以及系统重启后，
            // 都会用这个 action 让系统重新拉起本服务——它**不是**用户点了连接。
            // 之前这里落进 else 分支静默 startVpn()，表现为"每次点断开，它又自己连上"。
            VpnService.SERVICE_INTERFACE -> {
                if (isAlwaysOnVpn()) {
                    Log.i(TAG, "onStartCommand: 系统「始终开启的 VPN」拉起，自动重连")
                    startVpn("系统常驻 VPN（始终开启的 VPN）自动连接中…")
                } else {
                    // 系统重启后的恢复等：同样不是在用户点击下发生的
                    Log.i(TAG, "onStartCommand: 系统拉起（非用户点击），自动连接")
                    startVpn("连接中…")
                }
            }
            else -> {
                Log.i(TAG, "onStartCommand: 非用户 action=${intent?.action}（如 START_STICKY 重启），自动连接")
                startVpn("连接中…")
            }
        }
        return START_STICKY
    }

    /**
     * 本应用是否被设为「始终开启的 VPN」（Android 的 Always-on VPN）。
     *
     * 为什么需要它：Always-on 模式下用户/应用断开 VPN 后，系统会立刻重新拉起本服务
     * （onStartCommand 收到 "android.net.VpnService"），用户看到的现象就是
     * "点了断开它又自己连上"。这是系统策略、不是 bug——能做的就是解释清楚，
     * 并告诉用户去哪里关（系统设置 → 网络 → VPN → 始终开启的 VPN）。
     *
     * 用字面量读 Settings.Secure：ALWAYS_ON_VPN_APP 常量是 @hide，直接引用会编译不过。
     */
    private fun isAlwaysOnVpn(): Boolean = try {
        Settings.Secure.getString(contentResolver, "always_on_vpn_app") == packageName
    } catch (_: Exception) {
        false   // 读不到就当作没开（不弹误导性提示）
    }

    private fun startVpn(statusText: String = "连接中…") {
        startForeground()   // Android 12+ 要求启动后尽快进入前台状态
        if (!running.compareAndSet(false, true)) return
        registerNetworkWatch()   // 先挂网络事件，首次握手期间切网也能及时感知
        updateStatus(VpnStatus.Phase.CONNECTING, statusText)
        runSessionLoop()
    }

    /**
     * 退避等待：到期返回，或被网络事件提前唤醒（返回 true）。
     *
     * 进来先清空残留信号——否则"上一次网络变化"留下的旧信号会让本次等待
     * 瞬间穿透，等于退避形同虚设（可能立刻打满服务端限速）。
     */
    private suspend fun backoffWait(ms: Long): Boolean {
        while (retrySignal.tryReceive().isSuccess) { /* 丢弃过期信号 */ }
        return withTimeoutOrNull(ms) { retrySignal.receive() } != null
    }

    /**
     * 会话监督循环：连接 → 桥接 → 等待链路死亡 → 退避重连。
     * 每次 connect 成功后 attempt 清零；建立新 tun 前先关旧 fd。
     */
    private fun runSessionLoop() {
        serviceScope.launch {
            val store = VpnSettings(applicationContext)
            val identitySeed = IdentityStore(applicationContext).getOrCreateIdentitySeed()
            var attempt = 0

            while (running.get()) {
                val client = buildClient(store, identitySeed)
                tunnel = client
                val dead = CompletableDeferred<Unit>()
                client.onDead = {
                    Log.w(TAG, "链路失效: ${client.state.get()}")
                    dead.complete(Unit)
                }
                try {
                    closeTun()
                    val auth = client.connect()   // 三阶段认证（挂起直到 identity_ok）
                    attempt = 0
                    Log.i(TAG, "认证通过：虚拟 IP ${auth.ipString}/${auth.prefix}")
                    // 注册成功：令牌一次性作废（下次连接自动登录模式，对齐 C++ 端）
                    if (store.activeConfig()?.registerToken != null) {
                        store.clearRegisterToken()
                        Log.i(TAG, "注册成功，register_token 已清空")
                    }
                    val vpn = establishVpn(auth)
                        ?: throw IllegalStateException("establish() 失败：VPN 授权被撤销")
                    vpnInterface = vpn
                    client.startHeartbeat()
                    startBridges(vpn, client)
                    updateStatus(VpnStatus.Phase.CONNECTED, "已连接 · ${auth.ipString}")
                    Log.i(TAG, "VPN 数据面已启动")

                    dead.await()   // 等链路死亡（心跳超时/网络切换/对端断开）
                    closeTun()
                    updateStatus(VpnStatus.Phase.RECONNECTING, "链路断开，重连中…")
                    backoffWait(1_000)
                } catch (e: TunnelClient.AuthDeniedException) {
                    if (e.reasonCode == 1) {
                        // 令牌无效或已使用：自动清空并以登录模式重试（对齐 C++ 端行为）
                        Log.w(TAG, "注册令牌无效或已使用，自动清空并以登录模式重试")
                        store.clearRegisterToken()
                        VpnStatus.tokenClearTick.value++   // 通知 UI 刷新卡片（防废令牌回写）
                        attempt = 0                        // 换模式重试不计失败次数
                        updateStatus(VpnStatus.Phase.CONNECTING, "令牌无效，已清除，以登录模式重试…")
                        delay(500)
                    } else {
                        // 未注册/签名失败等身份问题重试无意义：报告并停止
                        Log.e(TAG, "身份认证被拒: ${e.message}", e)
                        updateStatus(VpnStatus.Phase.FAILED, "连接失败: ${e.message}")
                        stopVpn()
                        return@launch
                    }
                } catch (e: Exception) {
                    attempt++
                    val backoff = minOf(RECONNECT_MAX_MS, RECONNECT_BASE_MS shl (attempt - 1).coerceAtMost(5))
                    Log.w(TAG, "连接失败(第${attempt}次): ${e.message}，${backoff / 1000}s 后重连")
                    updateStatus(VpnStatus.Phase.RECONNECTING,
                        "重连中（第${attempt}次，${backoff / 1000}s 后重试）")
                    // 网络恢复会提前唤醒，不必把整个退避等完
                    if (backoffWait(backoff)) Log.i(TAG, "网络事件提前唤醒退避，立即重试")
                } finally {
                    client.stop()
                }
            }
        }
    }

    private fun buildClient(store: VpnSettings, identitySeed: ByteArray): TunnelClient {
        val config = store.activeConfig()
            ?: throw IllegalStateException("未配置服务器（先添加服务器卡片）")
        VpnStatus.busyIndex.value = store.activeIndex()   // UI 把断开按钮渲染在该卡片上
        return TunnelClient(
            serverIp = config.ip,
            serverPort = config.port,
            useTcp = config.useTcp,
            clientId = config.clientId,
            registerToken = config.registerToken,
            identityPrivSeed = identitySeed,
            serverPubKey = config.serverPubKey,
        )
    }

    /** 建立 tun 接口（MTU 1400 = 协议 KMax_data_payload） */
    private fun establishVpn(auth: TunnelClient.Authenticated): ParcelFileDescriptor? =
        Builder()
            .setSession("ScholarVPN")
            .setMtu(1400)
            .addAddress(auth.ipString, auth.prefix)
            .addRoute("0.0.0.0", 0)                 // 接管默认路由（IPv4）
            // 注意：**不要**在这里加 .addRoute("::", 0)（IPv6 kill-switch）。
            // 2026-09-25 实测回归：加了 ::/0 之后，V6 优先的应用（国内 App、QUIC/HTTP3）
            // 的包被拉进 tun 后由客户端本地静默丢弃（TunnelClient.sendData 的 IPv4-only
            // 过滤），应用要等连接超时（10~20s）才回落 IPv4 —— 表现为"VPN 连上了但
            // 很多 App 打不开/很慢"。改回不接管 IPv6（IPv6 走物理网卡）后恢复正常。
            // 代价是 IPv6 流量会绕过隧道、泄漏真实出口 IP；要既堵泄漏又不卡，正确做法是
            // 对 IPv6 包回 ICMPv6 Destination Unreachable / TCP RST（让应用快速失败），
            // 这需要在真机上验证，尚未实现。
            .addDnsServer("8.8.8.8")                // DNS 强制走隧道（防泄漏）
            .addDnsServer("1.1.1.1")
            // 关键：把本应用自身流量排除出隧道（等价 Windows 端 route_manager
            // 的"服务器绕过路由"），否则隧道自己的包被路由回 tun 形成回环
            .addDisallowedApplication(packageName)
            .establish()

    /** 双向桥接：tun fd ↔ 隧道（对应 ClientApp 的 tun_to_udp/udp_to_tun 循环） */
    private fun startBridges(vpn: ParcelFileDescriptor, client: TunnelClient) {
        val input = FileInputStream(vpn.fileDescriptor)
        val output = FileOutputStream(vpn.fileDescriptor)

        // 上行：tun → 隧道。tun 是字符设备：一次 read 返回一个完整 IP 包。
        // 隧道死亡（isAlive=false）即退出——重连后由新会话的桥接接管，避免对死隧道空转
        Thread({
            val buf = ByteArray(32 * 1024)
            try {
                while (running.get() && client.isAlive) {
                    val n = input.read(buf)
                    if (n > 0) client.sendData(buf, 0, n)
                }
            } catch (_: Exception) {
            } finally {
                runCatching { input.close() }
            }
        }, "tun-to-tunnel").apply { isDaemon = true }.start()

        // 下行：隧道 → tun
        serviceScope.launch {
            try {
                while (running.get()) {
                    val packet = client.incomingPackets.receive()
                    try {
                        // 显式给长度：缓冲是池化复用的，比实际包大，
                        // 用 write(buf) 会把尾部残留灌进 tun
                        output.write(packet.buf, 0, packet.len)
                    } finally {
                        // 无论写成功与否都归还，否则池会漏干、退化成每包新分配
                        client.recycleRxPacket(packet)
                    }
                }
            } catch (_: Exception) {
                // 通道关闭 / fd 关闭：随会话退出
            } finally {
                runCatching { output.close() }
            }
        }
    }

    private fun closeTun() {
        runCatching { vpnInterface?.close() }   // fd 关闭 = 系统自动回切路由/DNS
        vpnInterface = null
    }

    private fun stopVpn() {
        if (!running.getAndSet(false)) return
        unregisterNetworkWatch()   // 先撤监听，避免停机过程中回调又拉起重连
        tunnel?.stop()
        tunnel = null
        closeTun()
        serviceScope.cancel()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        VpnStatus.phase.value = VpnStatus.Phase.IDLE
        VpnStatus.busyIndex.value = -1
        // 开了「始终开启的 VPN」时，系统会在断开后立刻重新拉起本服务（见 onStartCommand），
        // 因此这里必须把原因说清楚，否则用户只会看到"点了断开它又自己连上"
        val alwaysOn = isAlwaysOnVpn()
        VpnStatus.message.value = if (alwaysOn)
            "已断开。但系统已开启「始终开启的 VPN」，会立刻自动重连；要彻底关闭请到 " +
                "系统设置 → 网络和互联网 → VPN → 关闭「始终开启的 VPN」"
        else
            "未连接"
        Log.i(TAG, if (alwaysOn) "VPN 已断开（检测到 Always-on VPN，系统会立即重连）" else "VPN 已断开")
    }

    private fun updateStatus(phase: VpnStatus.Phase, text: String) {
        VpnStatus.phase.value = phase
        VpnStatus.message.value = text
        updateNotification(text)
    }

    // ---- 前台通知 ----

    private fun startForeground() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ID, "VPN 状态", NotificationManager.IMPORTANCE_LOW))
        startForeground(NOTIFICATION_ID, buildNotification("启动中…"))
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun buildNotification(text: String): Notification =
        NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_notify_error)   // TODO(M3)：专用图标
            .setContentTitle("ScholarVPN")
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(
                PendingIntent.getActivity(
                    this, 0, Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE))
            // 通知栏一键断开
            .addAction(0, "断开",
                PendingIntent.getService(
                    this, 1,
                    Intent(this, ScholarVpnService::class.java).apply { action = ACTION_DISCONNECT },
                    PendingIntent.FLAG_IMMUTABLE))
            .build()

    override fun onRevoke() {
        // 用户在系统设置撤销 VPN 权限（或 Always-on 冲突）
        stopVpn()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}
