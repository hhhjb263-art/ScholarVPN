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
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

class TunnelClient(
    private val serverIp: String,
    private val serverPort: Int,
    private val useTcp: Boolean,
    private val clientId: String,
    private val registerToken: ByteArray?,
    private val identityPrivSeed: ByteArray,
    private val serverPubKey: ByteArray,
) {
    sealed class State {
        object Idle : State()
        object Handshaking : State()
        object DerivingKeys : State()
        object Authenticating : State()
        object Connected : State()
        data class Failed(val reason: String) : State()
    }

    data class Authenticated(val virtualIp: ByteArray, val prefix: Int) {
        val ipString: String get() = virtualIp.joinToString(".") { (it.toInt() and 0xFF).toString() }
    }

    class AuthDeniedException(val reasonCode: Int) :
        IOException(if (reasonCode == 1) "注册令牌无效或已使用" else "身份未注册（先在服务端 --gen-token 注册）")
    // reason=1 令牌失效需清空后改走登录；reason=0 表示本机公钥未登记

    companion object {
        private const val AUTH_TIMEOUT_MS = 8_000L
        private const val AUTH_RETRY_MS = 500L
        private const val AUTH_MAX_RETRIES = 16
        private const val HEARTBEAT_INTERVAL_MS = 10_000L
        private const val HEARTBEAT_TIMEOUT_MS = 25_000L
        private const val TCP_CONNECT_TIMEOUT_MS = 4_000
    }

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val running = AtomicBoolean(false)
    private val sequence = AtomicInteger(0)
    private val lastRxMs = AtomicLong(0)
    private val deadNotified = AtomicBoolean(false)

    val state = AtomicReference<State>(State.Idle)

    val authenticated = AtomicReference<Authenticated?>(null)

    @Volatile var onDead: (() -> Unit)? = null

    val incomingPackets = Channel<RxPacket>(512)

    private val rxPool = ConcurrentLinkedQueue<RxPacket>()

    private fun obtainRxPacket(len: Int): RxPacket {
        while (true) {
            val p = rxPool.poll() ?: break
            if (p.buf.size >= len) {
                p.len = len
                return p
            }
        }
        return RxPacket(ByteArray(maxOf(len, Protocol.MAX_DATA_PAYLOAD)), len)
    }

    fun recycleRxPacket(p: RxPacket) {
        if (rxPool.size < 128) rxPool.offer(p)
    }

    private lateinit var nonceC: ByteArray
    private var nonceS: ByteArray = ByteArray(0)
    private var dhSrvPub: ByteArray = ByteArray(0)
    private var keyTx: ByteArray = ByteArray(0)
    private var keyRx: ByteArray = ByteArray(0)
    private val keysReady = AtomicBoolean(false)

    private var serverHello = CompletableDeferred<Pair<ByteArray, ByteArray>>()
    private var identityResult = CompletableDeferred<Authenticated>()

    private var socketUdp: DatagramSocket? = null
    private var socketTcp: Socket? = null
    private val tcpAssembler = FrameAssembler()

    private val replayWindow = ReplayWindow()

    private val rxScratch = ByteArray(Protocol.MAX_PAYLOAD_LEN)

    private val txScratch: ThreadLocal<ByteArray> = ThreadLocal.withInitial {
        ByteArray(Protocol.HEADER_SIZE + 1 + Protocol.MAX_DATA_PAYLOAD +
            Protocol.GCM_NONCE_LEN + Protocol.GCM_TAG_LEN)
    }

    private val remoteAddress: InetSocketAddress get() = InetSocketAddress(serverIp, serverPort)
    private val wireVersion: Byte get() = if (useTcp) Protocol.VERSION_TCP else Protocol.VERSION_UDP

    // 三段握手：ServerHello → X25519 派生会话密钥 → 身份认证（注册或登录）
    suspend fun connect(): Authenticated = withContext(Dispatchers.IO) {
        check(running.compareAndSet(false, true)) { "已在运行" }
        state.set(State.Handshaking)
        startSockets()
        startRecvLoop()

        nonceC = TunnelCrypto.randomBytes(Protocol.AUTH_NONCE_LEN)
        val hello = retryLoop("阶段1（服务器握手）",
            resend = { rawSendFrame(Protocol.TYPE_AUTH_HELLO, nonceC) },
            wait = { serverHello.await() })
        nonceS = hello.first
        dhSrvPub = hello.second

        state.set(State.DerivingKeys)
        val (dhCliPriv, dhCliPub) = TunnelCrypto.generateX25519KeyPair()
        val identityPayload = Protocol.buildIdentityPayload(
            nonceC, nonceS, dhCliPub, dhSrvPub,
            TunnelCrypto.ed25519PubFromSeed(identityPrivSeed), clientId)
        val body = Protocol.buildIdentityBody(
            register = registerToken != null && registerToken.isNotEmpty(),
            token = registerToken?.takeIf { it.isNotEmpty() },
            identityPayload = identityPayload,
            signature = TunnelCrypto.ed25519Sign(identityPrivSeed, identityPayload),
        )
        rawSendFrame(Protocol.TYPE_AUTH_CLIENT_HELLO, dhCliPub)
        val sharedSecret = TunnelCrypto.x25519(dhCliPriv, dhSrvPub)
        val (tx, rx) = TunnelCrypto.deriveSessionKeys(sharedSecret, nonceC, nonceS)
        keyTx = tx; keyRx = rx
        keysReady.set(true)

        state.set(State.Authenticating)
        val auth = retryLoop("阶段3（身份认证）",
            resend = {
                rawSendFrame(Protocol.TYPE_AUTH_CLIENT_HELLO, dhCliPub)
                sendEncrypted(Protocol.TYPE_IDENTITY, body)
            },
            wait = { identityResult.await() })

        authenticated.set(auth)
        state.set(State.Connected)
        auth
    }

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
                if (deadNotified.get()) {
                    throw IOException("$label 中断：链路已失效（${state.get()}）")
                }
                if (System.currentTimeMillis() - start >= AUTH_TIMEOUT_MS || ++retries > AUTH_MAX_RETRIES) {
                    throw IOException("$label 超时（服务端无响应，检查 IP/端口/防火墙）")
                }
                resend()
            }
        }
    }

    // 收循环：UDP 一报文一帧；TCP 先排空读缓冲再逐帧处理粘包
    private fun startRecvLoop() {
        scope.launch {
            try {
                if (useTcp) recvLoopTcp() else recvLoopUdp()
            } catch (_: SocketException) {
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
            s.receive(pkt)
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
            for (frame in tcpAssembler.feed(chunk, n)) {
                dispatchFrame(frame.raw, frame.raw.size)
            }
        }
    }

    // 帧分发：版本/长度校验 → 解密 → 按类型交给上层；新增报文类型在这里挂分支
    private fun dispatchFrame(buf: ByteArray, len: Int) {
        val header = try {
            Protocol.decodeHeader(buf, 0)
        } catch (_: Exception) {
            return
        }
        if (header.version != wireVersion) return

        if (header.type in Protocol.ENCRYPTED_TYPES) {
            if (!keysReady.get()) return
            val seq = header.sequence.toLong() and 0xFFFFFFFFL
            if (replayWindow.isStale(seq)) return
            val plainLen = TunnelCrypto.gcmOpenInto(
                keyRx, buf, Protocol.HEADER_SIZE, len - Protocol.HEADER_SIZE, buf, 0, rxScratch)
            if (plainLen < 0) return
            if (!replayWindow.accept(seq)) return
            lastRxMs.set(System.currentTimeMillis())
            handleInner(rxScratch[0], rxScratch, 1, plainLen - 1)
        } else if (header.type == Protocol.TYPE_AUTH_SERVER_HELLO) {
            handleServerHello(buf.copyOfRange(Protocol.HEADER_SIZE, len))
        }
    }

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

    private fun handleInner(type: Byte, src: ByteArray, off: Int, len: Int) {
        when (type) {
            Protocol.TYPE_DATA -> {
                if (len > 0) {
                    val p = obtainRxPacket(len)
                    System.arraycopy(src, off, p.buf, 0, len)
                    if (!incomingPackets.trySend(p).isSuccess) recycleRxPacket(p)
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
            else -> Unit
        }
    }

    private fun rawSendFrame(type: Byte, payload: ByteArray) {
        val head = Protocol.encodeHeader(wireVersion, type, payload.size, sequence.getAndIncrement())
        rawSend(head + payload)
    }

    fun sendEncrypted(type: Byte, payload: ByteArray) {
        sendEncryptedSeg(type, payload, 0, payload.size)
    }

    private fun sendEncryptedSeg(type: Byte, data: ByteArray, off: Int, len: Int) {
        if (!keysReady.get()) throw IOException("密钥未就绪")
        val seqNum = sequence.getAndIncrement().toLong() and 0xFFFFFFFFL
        if (seqNum >= 0x80000000L) {
            notifyDead("发送序号空间耗尽，重连换新会话密钥")
            return
        }
        val sealedLen = 1 + len + Protocol.GCM_NONCE_LEN + Protocol.GCM_TAG_LEN
        val total = Protocol.HEADER_SIZE + sealedLen
        val scratch = txScratch.get()!!
        val frame = if (total <= scratch.size) scratch else ByteArray(total)
        Protocol.encodeHeaderInto(frame, 0, wireVersion, type, sealedLen, seqNum.toInt())
        TunnelCrypto.gcmSealInto(keyTx, type, data, off, len, frame, 0, frame, Protocol.HEADER_SIZE)
        rawSend(frame, total)
    }

    // 数据面入口：把 TUN 读到的 IP 包切段加密后发出
    fun sendData(buf: ByteArray, off: Int = 0, len: Int = buf.size): Boolean {
        if (!isAlive || len <= 0 || len > Protocol.MAX_DATA_PAYLOAD) return false
        if (len < 20 || (buf[off].toInt() and 0xF0) != 0x40) return false
        return runCatching {
            sendEncryptedSeg(Protocol.TYPE_DATA, buf, off, len)
            true
        }.getOrDefault(false)
    }

    val isAlive: Boolean get() = running.get() && keysReady.get()

    private fun rawSend(frame: ByteArray, len: Int = frame.size) {
        if (useTcp) {
            val out = socketTcp?.getOutputStream() ?: throw IOException("TCP 未连接")
            synchronized(out) {
                out.write(frame, 0, len)
            }
        } else {
            val s = socketUdp ?: throw IOException("UDP 未连接")
            s.send(DatagramPacket(frame, 0, len, remoteAddress))
        }
    }

    // 心跳：超时未收到服务端响应判定链路失效，交给上层重连
    fun startHeartbeat() {
        scope.launch {
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
                }
                val deadlineRx = if (last != 0L) last + HEARTBEAT_TIMEOUT_MS + 1 else Long.MAX_VALUE
                val wakeAt = minOf(nextHeart, deadlineRx)
                delay((wakeAt - System.currentTimeMillis()).coerceAtLeast(1L))
            }
        }
    }

    private fun startSockets() {
        if (useTcp) {
            socketTcp = Socket().apply {
                tcpNoDelay = true
                runCatching { receiveBufferSize = 4 * 1024 * 1024 }
                runCatching { sendBufferSize = 4 * 1024 * 1024 }
                connect(remoteAddress, TCP_CONNECT_TIMEOUT_MS)
            }
        } else {
            socketUdp = DatagramSocket().apply {
                runCatching { receiveBufferSize = 4 * 1024 * 1024 }
                runCatching { sendBufferSize = 4 * 1024 * 1024 }
                connect(remoteAddress)
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

    fun onPhysicalNetworkLost() {
        if (!running.get()) return
        notifyDead("物理网络已断开（系统事件）")
    }

    fun onPhysicalNetworkAvailable() {
    }

    fun stop() {
        if (!running.getAndSet(false)) return
        if (keysReady.get() && authenticated.get() != null) {
            runCatching { sendEncrypted(Protocol.TYPE_DISCONNECT, ByteArray(0)) }
        }
        runCatching { socketUdp?.close() }
        runCatching { socketTcp?.close() }
        scope.coroutineContext.cancelChildren()
        incomingPackets.close()
        state.set(State.Idle)
        authenticated.set(null)
        keysReady.set(false)
    }
}

class RxPacket(
    val buf: ByteArray,
    var len: Int,
)
