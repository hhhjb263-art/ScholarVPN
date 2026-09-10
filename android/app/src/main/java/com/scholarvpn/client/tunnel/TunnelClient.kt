package com.scholarvpn.client.tunnel

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.cancelChildren
import java.io.EOFException
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * 隧道客户端：三阶段认证状态机 + 心跳保活 + 数据面收发（纯 Kotlin）。
 * 协议线格式以 docs/ANDROID_PROTOCOL_SPEC.md 为唯一标准；
 * 认证/超时/重传参数与 Windows 端 src/UDP.cpp 一致（5s 超时、500ms 重传、10 次）。
 *
 * 传输二选一：UDP（DatagramSocket，connect 过滤来源）或 TCP（Socket + FrameAssembler 分帧），
 * 认证/加密/心跳共用同一套逻辑——对应 C++ 端 UDP 基类 + TCP 子类的钩子结构。
 */
class TunnelClient(
    private val serverIp: String,
    private val serverPort: Int,
    private val useTcp: Boolean,
    private val clientId: String,
    private val registerToken: ByteArray?,
    /** 客户端 Ed25519 私钥 seed（32 字节，来自加密存储） */
    private val identityPrivSeed: ByteArray,
    /** 服务器 Ed25519 公钥（32 字节 raw，用于阶段1验签防中间人） */
    private val serverPubKey: ByteArray,
) {
    sealed class State {
        object Idle : State()
        object Handshaking : State()      // 阶段1：nonce 交换 + 服务器验签
        object DerivingKeys : State()     // 阶段2：X25519 ECDH + HKDF
        object Authenticating : State()   // 阶段3：身份报文
        object Connected : State()        // 认证通过，隧道可用
        data class Failed(val reason: String) : State()
    }

    /** 阶段3通过：服务端分配的虚拟 IP（4 字节，网络序=点分序）与前缀 */
    data class Authenticated(val virtualIp: ByteArray, val prefix: Int) {
        val ipString: String get() = virtualIp.joinToString(".") { (it.toInt() and 0xFF).toString() }
    }

    class AuthDeniedException(val reasonCode: Int) :
        IOException(if (reasonCode == 1) "注册令牌无效或已使用" else "身份未注册（先在服务端 --gen-token 注册）")

    companion object {
        private const val AUTH_TIMEOUT_MS = 5_000L     // 每阶段总超时（对齐 C++ kAuthTimeout）
        private const val AUTH_RETRY_MS = 500L         // 重传间隔（对齐 kAuthRetryInterval）
        private const val AUTH_MAX_RETRIES = 10        // 对齐 kAuthMaxRetries
        private const val HEARTBEAT_INTERVAL_MS = 1_000L
        private const val HEARTBEAT_TIMEOUT_MS = 5_000L
        private const val TCP_CONNECT_TIMEOUT_MS = 4_000
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val running = AtomicBoolean(false)
    private val sequence = AtomicInteger(0)
    private val lastRxMs = AtomicLong(0)
    private val deadNotified = AtomicBoolean(false)

    val state = AtomicReference<State>(State.Idle)

    /** 认证结果（Connected 后非空） */
    val authenticated = AtomicReference<Authenticated?>(null)

    /** 链路死亡回调（心跳超时/对端断开/连接错误）；重连由上层负责（TODO M4 退避状态机） */
    @Volatile var onDead: (() -> Unit)? = null

    /** 服务端→客户端的上行 IP 包（VpnService 桥接线程消费，写 tun fd） */
    val incomingPackets = Channel<ByteArray>(4096)

    // ---- 会话上下文 ----
    private lateinit var nonceC: ByteArray
    private var nonceS: ByteArray = ByteArray(0)
    private var dhSrvPub: ByteArray = ByteArray(0)
    private var keyTx: ByteArray = ByteArray(0)
    private var keyRx: ByteArray = ByteArray(0)
    private val keysReady = AtomicBoolean(false)

    // 阶段1/阶段3 的响应投递（recv 线程 complete，认证协程 await）
    private var serverHello = CompletableDeferred<Pair<ByteArray, ByteArray>>()   // (nonceS, dhSrvPub)
    private var identityResult = CompletableDeferred<Authenticated>()

    private var socketUdp: DatagramSocket? = null
    private var socketTcp: Socket? = null
    private val tcpAssembler = FrameAssembler()

    /** 反重放滑窗（仅密文帧；序号在 AAD 内不可篡改，重放帧静默丢弃） */
    private val replayWindow = ReplayWindow()

    private val remoteAddress: InetSocketAddress get() = InetSocketAddress(serverIp, serverPort)
    private val wireVersion: Byte get() = if (useTcp) Protocol.VERSION_TCP else Protocol.VERSION_UDP

    // ==================================================================
    // 连接：三阶段认证（挂起函数，成功返回 Authenticated，失败抛异常）
    // ==================================================================
    suspend fun connect(): Authenticated = withContext(Dispatchers.IO) {
        check(running.compareAndSet(false, true)) { "已在运行" }
        state.set(State.Handshaking)
        startSockets()
        startRecvLoop()

        // ---- 阶段1：auth_hello → server_hello（明文 + 服务器签名验证）----
        nonceC = TunnelCrypto.randomBytes(Protocol.AUTH_NONCE_LEN)
        val hello = retryLoop("阶段1（服务器握手）",
            resend = { rawSendFrame(Protocol.TYPE_AUTH_HELLO, nonceC) },
            wait = { serverHello.await() })
        nonceS = hello.first
        dhSrvPub = hello.second

        // ---- 阶段2：X25519 ECDH + HKDF 派生方向性密钥（无报文交互）----
        state.set(State.DerivingKeys)
        val (dhCliPriv, dhCliPub) = TunnelCrypto.generateX25519KeyPair()
        rawSendFrame(Protocol.TYPE_AUTH_CLIENT_HELLO, dhCliPub)
        val sharedSecret = TunnelCrypto.x25519(dhCliPriv, dhSrvPub)
        val (tx, rx) = TunnelCrypto.deriveSessionKeys(sharedSecret, nonceC, nonceS)
        keyTx = tx; keyRx = rx
        keysReady.set(true)

        // ---- 阶段3：密文身份报文 → identity_ok / identity_deny ----
        state.set(State.Authenticating)
        val identityPayload = Protocol.buildIdentityPayload(
            nonceC, nonceS, dhCliPub, dhSrvPub,
            TunnelCrypto.ed25519PubFromSeed(identityPrivSeed), clientId)
        val body = Protocol.buildIdentityBody(
            register = registerToken != null && registerToken.isNotEmpty(),
            token = registerToken?.takeIf { it.isNotEmpty() },
            identityPayload = identityPayload,
            signature = TunnelCrypto.ed25519Sign(identityPrivSeed, identityPayload),
        )
        val auth = retryLoop("阶段3（身份认证）",
            resend = { sendEncrypted(Protocol.TYPE_IDENTITY, body) },
            wait = { identityResult.await() })

        authenticated.set(auth)
        state.set(State.Connected)
        auth
    }

    /**
     * 阶段重传循环：立即发一次，之后每 500ms 重传一次；
     * 总超时 5s / 最多 10 次（对齐 C++ 端 kAuthTimeout/kAuthRetryInterval/kAuthMaxRetries）。
     * 响应到达时 wait() 返回；认证被拒（deferred 异常完成）时异常直接穿透。
     */
    private suspend fun <T> retryLoop(
        label: String,
        resend: () -> Unit,
        wait: suspend () -> T,
    ): T {
        val start = System.currentTimeMillis()
        var retries = 0
        resend()
        while (true) {
            try {
                return withTimeout(AUTH_RETRY_MS) { wait() }
            } catch (_: TimeoutCancellationException) {
                if (System.currentTimeMillis() - start >= AUTH_TIMEOUT_MS || ++retries > AUTH_MAX_RETRIES) {
                    throw IOException("$label 超时（服务端无响应，检查 IP/端口/防火墙）")
                }
                resend()
            }
        }
    }

    // ------------------------------------------------------------------
    // 收循环：UDP 一报文一帧；TCP 排空读缓冲后逐帧处理（先吃缓冲语义）
    // ------------------------------------------------------------------
    private fun startRecvLoop() {
        scope.launch {
            try {
                if (useTcp) recvLoopTcp() else recvLoopUdp()
            } catch (_: SocketException) {
                // socket 关闭（stop()）：正常退出路径
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                if (running.get()) notifyDead("连接错误: ${e.message}")
            }
        }
    }

    private suspend fun recvLoopUdp() {
        val s = socketUdp ?: throw IOException("UDP socket 未创建")
        val buf = ByteArray(Protocol.HEADER_SIZE + Protocol.MAX_PAYLOAD_LEN)
        val pkt = DatagramPacket(buf, buf.size)
        while (running.get() && scope.isActive) {
            s.receive(pkt)   // connected socket：内核过滤非服务器来源
            if (pkt.length < Protocol.HEADER_SIZE) continue
            dispatchFrame(buf, pkt.length)
        }
    }

    private suspend fun recvLoopTcp() {
        val input = socketTcp!!.getInputStream()
        val chunk = ByteArray(Protocol.HEADER_SIZE + Protocol.MAX_PAYLOAD_LEN + 64)
        while (running.get() && scope.isActive) {
            val n = input.read(chunk)
            if (n < 0) throw EOFException("服务端关闭连接")
            if (n == 0) continue
            // 一次 recv 的粘包帧全部处理完再回读（先吃缓冲，不逐帧卡 recv）
            for (frame in tcpAssembler.feed(chunk, n)) {
                dispatchFrame(frame.raw, frame.raw.size)
            }
        }
    }

    /** 帧统一处理：版本校验 → 刷新存活 → 密文解密分发 / 阶段1明文 */
    private fun dispatchFrame(buf: ByteArray, len: Int) {
        val header = try {
            Protocol.decodeHeader(buf, 0)
        } catch (_: Exception) {
            return   // 非法帧：丢弃
        }
        if (header.version != wireVersion) return   // 传输不匹配（对应 C++ 版本校验）
        lastRxMs.set(System.currentTimeMillis())

        if (header.type in Protocol.ENCRYPTED_TYPES) {
            if (!keysReady.get()) return   // 密钥未就绪：丢弃
            // 反重放：序号过滑窗（重放帧在解密前即丢弃；AAD 保证序号不可篡改）
            if (!replayWindow.accept(header.sequence.toLong() and 0xFFFFFFFFL)) return
            val inner = TunnelCrypto.gcmOpen(keyRx, buf, Protocol.HEADER_SIZE, len - Protocol.HEADER_SIZE, buf, 0)
                ?: return   // 解密失败静默丢弃
            handleInner(inner[0], inner, 1, inner.size - 1)
        } else if (header.type == Protocol.TYPE_AUTH_SERVER_HELLO) {
            handleServerHello(buf.copyOfRange(Protocol.HEADER_SIZE, len))
        }
        // 其余明文类型（明文 heart/disconnect）不受理——对齐 C++ 端防伪造语义
    }

    /** 阶段1响应：校验长度 + Ed25519 验签（防中间人），失败 = 致命 */
    private fun handleServerHello(payload: ByteArray) {
        if (payload.size != Protocol.SERVER_HELLO_LEN) {
            serverHello.completeExceptionally(
                IOException("ServerHello 长度 ${payload.size} != ${Protocol.SERVER_HELLO_LEN}（两端版本不一致?）"))
            return
        }
        val nS = payload.copyOfRange(0, Protocol.AUTH_NONCE_LEN)
        val dhPub = payload.copyOfRange(Protocol.AUTH_NONCE_LEN, Protocol.AUTH_NONCE_LEN + Protocol.AUTH_DH_PUB_LEN)
        val sig = payload.copyOfRange(Protocol.AUTH_NONCE_LEN + Protocol.AUTH_DH_PUB_LEN, payload.size)
        val sigPayload = nonceC + nS + dhPub
        if (!TunnelCrypto.ed25519Verify(serverPubKey, sigPayload, sig)) {
            serverHello.completeExceptionally(
                IOException("服务器签名验证失败：疑似中间人攻击，断开"))
            return
        }
        serverHello.complete(nS to dhPub)
    }

    /** 密文内层分发（对应 C++ handle_frame 的密文分支），分段取载荷 */
    private fun handleInner(type: Byte, src: ByteArray, off: Int, len: Int) {
        when (type) {
            Protocol.TYPE_DATA -> {
                if (len > 0) {
                    val packet = src.copyOfRange(off, off + len)
                    incomingPackets.trySend(packet)   // 桥接消费不动则丢弃（隧道内 TCP 重传兜底）
                }
            }
            Protocol.TYPE_HEART -> runCatching { sendEncrypted(Protocol.TYPE_HEART_RESPONSE, ByteArray(0)) }
            Protocol.TYPE_IDENTITY_OK -> {
                if (len >= 5) {
                    identityResult.complete(
                        Authenticated(src.copyOfRange(off, off + 4), src[off + 4].toInt() and 0xFF))
                }
            }
            Protocol.TYPE_IDENTITY_DENY -> {
                val reason = if (len == 0) 0 else src[off].toInt()
                identityResult.completeExceptionally(AuthDeniedException(reason))
            }
            Protocol.TYPE_DISCONNECT -> notifyDead("服务端显式断开")
            else -> Unit   // heart_response 等：仅刷新 lastRx
        }
    }

    // ------------------------------------------------------------------
    // 发送
    // ------------------------------------------------------------------

    /** 明文帧（阶段1三种消息） */
    private fun rawSendFrame(type: Byte, payload: ByteArray) {
        val head = Protocol.encodeHeader(wireVersion, type, payload.size, sequence.getAndIncrement())
        rawSend(head + payload)
    }

    /** 密文帧（控制面：identity/心跳等，载荷为独立数组） */
    fun sendEncrypted(type: Byte, payload: ByteArray) {
        sendEncryptedSeg(type, payload, 0, payload.size)
    }

    /**
     * 密文帧（分段版，热路径）：AAD = 含密文长度的帧头，payload = nonce||ct||tag。
     * 整帧单次分配；payload 直接从 [data] 段加密，零拷贝（规格 §4）
     */
    private fun sendEncryptedSeg(type: Byte, data: ByteArray, off: Int, len: Int) {
        if (!keysReady.get()) throw IOException("密钥未就绪")
        val sealedLen = 1 + len + Protocol.GCM_NONCE_LEN + Protocol.GCM_TAG_LEN
        val frame = ByteArray(Protocol.HEADER_SIZE + sealedLen)
        Protocol.encodeHeaderInto(frame, 0, wireVersion, type, sealedLen, sequence.getAndIncrement())
        TunnelCrypto.gcmSealInto(keyTx, type, data, off, len, frame, 0, frame, Protocol.HEADER_SIZE)
        rawSend(frame)
    }

    /** 上行数据面：VpnService 桥接线程调用（tun fd 读到的 IP 包，不复制直接加密发送） */
    fun sendData(buf: ByteArray, off: Int = 0, len: Int = buf.size): Boolean {
        if (!isAlive || len <= 0 || len > Protocol.MAX_DATA_PAYLOAD) return false
        return runCatching {
            sendEncryptedSeg(Protocol.TYPE_DATA, buf, off, len)
            true
        }.getOrDefault(false)
    }

    /** 隧道是否可用（桥接线程以此判活退出，避免对已死隧道空转） */
    val isAlive: Boolean get() = running.get() && keysReady.get()

    private fun rawSend(frame: ByteArray) {
        if (useTcp) {
            val out = socketTcp?.getOutputStream() ?: throw IOException("TCP 未连接")
            synchronized(out) {   // 整帧原子写（防多线程交错破坏分帧，对齐 C++ m_send_mutex）
                out.write(frame)
                out.flush()
            }
        } else {
            val s = socketUdp ?: throw IOException("UDP 未连接")
            s.send(DatagramPacket(frame, frame.size, remoteAddress))
        }
    }

    // ------------------------------------------------------------------
    // 心跳（Connected 后启动）
    // ------------------------------------------------------------------
    fun startHeartbeat() {
        scope.launch {
            // 按到期时间精确休眠（每 1s 唤醒一次，替代 100ms 轮询——省电减热）
            var nextHeart = System.currentTimeMillis() + HEARTBEAT_INTERVAL_MS
            while (running.get() && scope.isActive) {
                val now = System.currentTimeMillis()
                val last = lastRxMs.get()
                if (last != 0L && now - last > HEARTBEAT_TIMEOUT_MS) {
                    notifyDead("心跳超时（${HEARTBEAT_TIMEOUT_MS / 1000}s 无对端报文）")
                    return@launch
                }
                if (now >= nextHeart) {
                    runCatching { sendEncrypted(Protocol.TYPE_HEART, ByteArray(0)) }
                    nextHeart = now + HEARTBEAT_INTERVAL_MS
                    continue
                }
                delay(nextHeart - now)
            }
        }
    }

    // ------------------------------------------------------------------
    // 生命周期
    // ------------------------------------------------------------------

    private fun startSockets() {
        if (useTcp) {
            socketTcp = Socket().apply {
                tcpNoDelay = true
                // 放大收发缓冲（对齐两端 4MB）：移动网络高 RTT 下默认 128KB
                // 会限制单连接吞吐（带宽×延迟积不够）
                runCatching { receiveBufferSize = 4 * 1024 * 1024 }
                runCatching { sendBufferSize = 4 * 1024 * 1024 }
                connect(remoteAddress, TCP_CONNECT_TIMEOUT_MS)   // 对齐 C++ 端 4s 建连超时
            }
        } else {
            socketUdp = DatagramSocket().apply {
                runCatching { receiveBufferSize = 4 * 1024 * 1024 }
                runCatching { sendBufferSize = 4 * 1024 * 1024 }
                connect(remoteAddress)   // 内核过滤非服务器来源
            }
        }
        lastRxMs.set(System.currentTimeMillis())
    }

    private fun notifyDead(reason: String) {
        state.set(State.Failed(reason))
        if (deadNotified.compareAndSet(false, true)) {
            onDead?.invoke()
        }
    }

    fun stop() {
        if (!running.getAndSet(false)) return
        // 显式断开（密文内层，尽力而为）
        if (keysReady.get() && authenticated.get() != null) {
            runCatching { sendEncrypted(Protocol.TYPE_DISCONNECT, ByteArray(0)) }
        }
        runCatching { socketUdp?.close() }
        runCatching { socketTcp?.close() }
        scope.coroutineContext.cancelChildren()
        incomingPackets.close()   // 唤醒并退出下行桥接协程
        state.set(State.Idle)
        authenticated.set(null)
        keysReady.set(false)
    }
}
