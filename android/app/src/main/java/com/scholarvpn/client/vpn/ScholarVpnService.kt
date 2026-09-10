package com.scholarvpn.client.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
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
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.atomic.AtomicBoolean

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

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                stopVpn()
                return START_NOT_STICKY
            }
            else -> startVpn()
        }
        return START_STICKY
    }

    private fun startVpn() {
        startForeground()   // Android 12+ 要求启动后尽快进入前台状态
        if (!running.compareAndSet(false, true)) return
        updateStatus(VpnStatus.Phase.CONNECTING, "连接中…")
        runSessionLoop()
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
                    delay(1_000)
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
                    delay(backoff)
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
                    output.write(packet)
                    output.flush()
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
        tunnel?.stop()
        tunnel = null
        closeTun()
        serviceScope.cancel()
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
        VpnStatus.phase.value = VpnStatus.Phase.IDLE
        VpnStatus.message.value = "未连接"
        VpnStatus.busyIndex.value = -1
        Log.i(TAG, "VPN 已断开")
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
