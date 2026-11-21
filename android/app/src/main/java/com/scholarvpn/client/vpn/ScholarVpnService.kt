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
import com.scholarvpn.client.service.MachineId
import com.scholarvpn.client.service.ServiceClient
import com.scholarvpn.client.tunnel.TunnelClient
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

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

    private val cm by lazy { getSystemService(ConnectivityManager::class.java) }

    private val physicalNetworks = mutableSetOf<Network>()

    private val lastNetEventMs = AtomicLong(0L)
    private var netWatchRegistered = false

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
            retrySignal.trySend(Unit)
        }

        override fun onLost(network: Network) {
            val remaining = synchronized(physicalNetworks) {
                physicalNetworks.remove(network)
                physicalNetworks.size
            }
            Log.i(TAG, "物理网络丢失: $network（剩余 $remaining 个）")

            val now = System.currentTimeMillis()
            val prev = lastNetEventMs.get()
            if (now - prev >= 2_000L && lastNetEventMs.compareAndSet(prev, now)) {
                tunnel?.onPhysicalNetworkLost()
            }
        }
    }

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
            VpnService.SERVICE_INTERFACE -> {
                if (isAlwaysOnVpn()) {
                    Log.i(TAG, "onStartCommand: 系统「始终开启的 VPN」拉起，自动重连")
                    startVpn("系统常驻 VPN（始终开启的 VPN）自动连接中…")
                } else {
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

    private fun isAlwaysOnVpn(): Boolean = try {
        Settings.Secure.getString(contentResolver, "always_on_vpn_app") == packageName
    } catch (_: Exception) {
        false
    }

    private fun startVpn(statusText: String = "连接中…") {
        startForeground()
        if (!running.compareAndSet(false, true)) return
        registerNetworkWatch()
        updateStatus(VpnStatus.Phase.CONNECTING, statusText)
        runSessionLoop()
    }

    private suspend fun backoffWait(ms: Long): Boolean {
        while (retrySignal.tryReceive().isSuccess) { }
        return withTimeoutOrNull(ms) { retrySignal.receive() } != null
    }

    // 会话主循环：连接 → 建 TUN → 转发，断开后按退避重连
    private fun runSessionLoop() {
        serviceScope.launch {
            val store = VpnSettings(applicationContext)
            val identitySeed = IdentityStore(applicationContext).getOrCreateIdentitySeed()
            var attempt = 0
            var selfHealed = false

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
                    val auth = client.connect()
                    attempt = 0
                    Log.i(TAG, "认证通过：虚拟 IP ${auth.ipString}/${auth.prefix}")
                    if (store.activeConfig()?.registerToken != null) {
                        store.clearRegisterToken()
                        Log.i(TAG, "注册成功，register_token 已清空")
                    }
                    val activeCfg = store.activeConfig()
                    // 内网访问只对自建卡片开放；受管服务器一律按全流量走隧道
                    val subnets = if (activeCfg?.managed == true) {
                        if (activeCfg.intranetSubnets.isNotBlank()) {
                            Log.w(TAG, "受管服务器不支持内网访问，已忽略内网网段配置")
                        }
                        emptyList()
                    } else {
                        parseIntranetSubnets(activeCfg?.intranetSubnets ?: "")
                    }
                    val vpn = establishVpn(auth, subnets)
                        ?: throw IllegalStateException("establish() 失败：VPN 授权被撤销")
                    vpnInterface = vpn
                    client.startHeartbeat()
                    startBridges(vpn, client)
                    updateStatus(VpnStatus.Phase.CONNECTED, "已连接 · ${auth.ipString}")
                    Log.i(TAG, "VPN 数据面已启动")

                    dead.await()
                    closeTun()
                    updateStatus(VpnStatus.Phase.RECONNECTING, "链路断开，重连中…")
                    backoffWait(1_000)
                } catch (e: TunnelClient.AuthDeniedException) {
                    if (e.reasonCode == 1) {
                        Log.w(TAG, "注册令牌无效或已使用，自动清空并以登录模式重试")
                        store.clearRegisterToken()
                        VpnStatus.tokenClearTick.value++
                        attempt = 0
                        updateStatus(VpnStatus.Phase.CONNECTING, "令牌无效，已清除，以登录模式重试…")
                        delay(500)
                    } else if (!selfHealed && selfHealRegister(store)) {
                        // 服务端不认识本机公钥：现场补一次注册，每个会话只补一次
                        selfHealed = true
                        attempt = 0
                        Log.w(TAG, "身份未注册，已自动补注册，重试握手")
                        updateStatus(VpnStatus.Phase.CONNECTING, "身份未注册，已自动注册，重试中…")
                        delay(300)
                    } else {
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
                    if (backoffWait(backoff)) Log.i(TAG, "网络事件提前唤醒退避，立即重试")
                } finally {
                    client.stop()
                }
            }
        }
    }

    private suspend fun selfHealRegister(store: VpnSettings): Boolean =
        withContext(Dispatchers.IO) {
            try {
                val info = MachineId.collect(applicationContext)
                val creds = ServiceClient.registerTrial(info)
                if (creds.token.isBlank()) return@withContext false
                val list = ServiceClient.fetchServerList(creds.fp.ifBlank { info.fp })
                store.applyManagedServers(
                    list.map { it.addr to it.pubkeyB64 }, creds.clientId, creds.token)
                store.saveServiceState(VpnSettings.ServiceState(
                    fp = creds.fp.ifBlank { info.fp },
                    clientId = creds.clientId,
                    token = creds.token,
                    status = creds.status,
                    expireAt = creds.expireAt,
                    quotaBytes = creds.quotaBytes,
                    usedBytes = creds.usedBytes,
                    limitKind = creds.limitKind,
                    remaining = creds.remaining,
                ))
                VpnStatus.tokenClearTick.value++
                true
            } catch (e: Exception) {
                Log.w(TAG, "自动补注册失败: ${e.message}")
                false
            }
        }

    private fun buildClient(store: VpnSettings, identitySeed: ByteArray): TunnelClient {
        val config = store.activeConfig()
            ?: throw IllegalStateException("未配置服务器（先添加服务器卡片）")
        VpnStatus.busyIndex.value = store.activeIndex()
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

    // 用服务端下发的虚拟 IP 建 TUN，并把本应用排除在隧道外避免自己把自己绕死
    // subnets 为空 = 全流量走隧道；非空 = 只把这些网段送进隧道（内网访问）
    private fun establishVpn(
        auth: TunnelClient.Authenticated,
        subnets: List<Pair<String, Int>>,
    ): ParcelFileDescriptor? {
        val b = Builder()
            .setSession("ScholarVPN")
            .setMtu(1400)
            .addAddress(auth.ipString, auth.prefix)
        if (subnets.isEmpty()) {
            b.addRoute("0.0.0.0", 0)
            b.addDnsServer("8.8.8.8")
            b.addDnsServer("1.1.1.1")
        } else {
            for ((host, len) in subnets) {
                b.addRoute(host, len)
            }
        }
        return b.addDisallowedApplication(packageName).establish()
    }

    // 解析 "192.168.10.0/24,10.20.0.0/16"；拒绝 /0，避免误配成全局代理
    private fun parseIntranetSubnets(spec: String): List<Pair<String, Int>> {
        val out = ArrayList<Pair<String, Int>>()
        for (raw in spec.split(',', ';', ' ', '\t', '\n')) {
            val t = raw.trim()
            if (t.isEmpty()) continue
            val i = t.lastIndexOf('/')
            if (i <= 0) continue
            val host = t.substring(0, i).trim()
            val len = t.substring(i + 1).trim().toIntOrNull() ?: continue
            if (len !in 1..32) continue
            out.add(host to len)
        }
        return out
    }

    private fun startBridges(vpn: ParcelFileDescriptor, client: TunnelClient) {
        val input = FileInputStream(vpn.fileDescriptor)
        val output = FileOutputStream(vpn.fileDescriptor)

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

        serviceScope.launch {
            try {
                while (running.get()) {
                    val packet = client.incomingPackets.receive()
                    try {
                        output.write(packet.buf, 0, packet.len)
                    } finally {
                        client.recycleRxPacket(packet)
                    }
                }
            } catch (_: Exception) {
            } finally {
                runCatching { output.close() }
            }
        }
    }

    private fun closeTun() {
        runCatching { vpnInterface?.close() }
        vpnInterface = null
    }

    private fun stopVpn() {
        if (!running.getAndSet(false)) return
        unregisterNetworkWatch()
        tunnel?.stop()
        tunnel = null
        closeTun()
        serviceScope.cancel()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        VpnStatus.phase.value = VpnStatus.Phase.IDLE
        VpnStatus.busyIndex.value = -1
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
            .setSmallIcon(android.R.drawable.stat_notify_error)
            .setContentTitle("ScholarVPN")
            .setContentText(text)
            .setOngoing(true)
            .setContentIntent(
                PendingIntent.getActivity(
                    this, 0, Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE))
            .addAction(0, "断开",
                PendingIntent.getService(
                    this, 1,
                    Intent(this, ScholarVpnService::class.java).apply { action = ACTION_DISCONNECT },
                    PendingIntent.FLAG_IMMUTABLE))
            .build()

    override fun onRevoke() {
        stopVpn()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}
