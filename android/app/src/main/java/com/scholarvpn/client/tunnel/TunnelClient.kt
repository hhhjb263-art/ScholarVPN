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
        // 每阶段总超时：8s（原 5s，对齐 C++ 端 kAuthTimeout）。移动网实测
        // 一次成功握手要 3~4s（RTT 2~4s + 丢包重传），5s 只剩几百毫秒余量，
        // 链路稍差就整轮失败重连。8s × 3 阶段 < 服务端未认证会话 30s 的清理窗口，
        // 不会出现"客户端还在握手、服务端已把会话清掉"的错配。
        private const val AUTH_TIMEOUT_MS = 8_000L
        private const val AUTH_RETRY_MS = 500L         // 重传间隔（对齐 kAuthRetryInterval）
        private const val AUTH_MAX_RETRIES = 16        // 与 8s 预算一致（16 × 500ms）
        // 10s，对齐服务端 kHeartbeatInterval（server/UDP/UDP.cpp:60）。
        //
        // 为什么从 1s 改成 10s（2026-10-18，真机发热问题）：
        // 移动网络的射频有「尾时器」——发完任何一个包后，射频功放要维持高功耗约
        // 5~10 秒才会回落到空闲态。1 秒一次心跳意味着尾时器**每秒被重置一次**，
        // 射频永远进不了低功耗，手机背面持续发烫、待机掉电极快。
        //
        // 这不是 CPU 忙等（数据面是阻塞 read/receive，本身已是事件驱动），
        // 所以加回调/改 epoll 都没用——唯一的解就是把发包间隔拉到大于尾时器。
        //
        // 10s 的依据：
        //  - 服务端心跳也是 10s、30s 判失联，客户端 10s 完全够保活；
        //  - 运营商 NAT 表项超时普遍 30~120s，10s 远在安全线内；
        //  - 10s > 尾时器上限（约 10s），射频能真正回落空闲态。
        private const val HEARTBEAT_INTERVAL_MS = 10_000L
        // 25s（原 15s）：心跳间隔拉到 10s 后，正常情况每 10s 必收到服务端心跳，
        // 25s 等于容忍连续丢 2 个心跳包，仍早于服务端的 30s 判死线。
        // 不能沿用 15s——那样一次丢包就误判失联，重连比心跳还费电。
        private const val HEARTBEAT_TIMEOUT_MS = 25_000L
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

    /**
     * 服务端→客户端的上行 IP 包（VpnService 桥接线程消费，写 tun fd）。
     *
     * 容量 512（原 4096）：每个元素是一个 IP 包（最大 1400B），
     * 4096 满载就是 ~5.6MB 的堆占用——低端机上会持续触发 GC，表现为后台发烫。
     * 512 个包 ≈ 700KB，按 20Mbps 下行算约 0.28s 的缓冲，足够吸收调度抖动；
     * 真堵住了由 TCP 重传兜底（trySend 丢弃策略不变）。
     *
     * 元素类型是 [RxPacket] 而非裸 ByteArray：消费方写完后要把缓冲还回池子，
     * 稳态下每包零分配（原来每包 copyOfRange 一次 1400B）。
     * **消费方必须调用 [recycleRxPacket]**，否则退化为每次新分配（不会出错，只是白优化）。
     */
    val incomingPackets = Channel<RxPacket>(512)

    /**
     * 下行包缓冲池。生产者是 recv 线程，回收者是写 tun 的协程，
     * 跨线程访问故用并发队列。
     *
     * 池上限 128：约 180KB 常驻，够覆盖"通道满 + 消费慢"的瞬时峰值，
     * 再多就是白占内存。
     */
    private val rxPool = ConcurrentLinkedQueue<RxPacket>()

    /** 取一个至少 [len] 字节的包缓冲（优先复用池中够大的） */
    private fun obtainRxPacket(len: Int): RxPacket {
        while (true) {
            val p = rxPool.poll() ?: break
            if (p.buf.size >= len) {
                p.len = len
                return p
            }
            // 太小：丢弃继续找（池里其余元素可能更大）
        }
        return RxPacket(ByteArray(maxOf(len, Protocol.MAX_DATA_PAYLOAD)), len)
    }

    /** 消费方写完 tun 后归还缓冲 */
    fun recycleRxPacket(p: RxPacket) {
        if (rxPool.size < 128) rxPool.offer(p)
    }

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

    /**
     * 下行解密复用缓冲（热路径，避免每包 new ByteArray）。
     *
     * 只有 recv 单线程访问（recvLoopUdp / recvLoopTcp 不会同时跑），因此无需同步。
     * 大小取 MAX_PAYLOAD_LEN：明文 = 密文段 - nonce(12) - tag(16)，必小于该值。
     */
    private val rxScratch = ByteArray(Protocol.MAX_PAYLOAD_LEN)

    /**
     * 上行组帧复用缓冲（ThreadLocal，热路径避免每包 new ByteArray）。
     *
     * 为什么能复用：[rawSend] 是**同步**发送——UDP 的 `send` 把数据拷进内核即返回，
     * TCP 的 `write` 也是拷进发送缓冲即返回。返回之后这块内存就没人再读了。
     *
     * 为什么用 ThreadLocal 而不是实例字段：上行发送有多个调用方
     * （tun 桥接线程、recv 线程回 heart_response、心跳协程），
     * 共享一块缓冲会互相覆盖；每线程一块最省心，代价只有 1.4KB × 线程数。
     *
     * 大小 = 帧头(12) + 内层type(1) + 最大载荷(1400) + nonce(12) + tag(16) = 1441
     */
    private val txScratch: ThreadLocal<ByteArray> = ThreadLocal.withInitial {
        ByteArray(Protocol.HEADER_SIZE + 1 + Protocol.MAX_DATA_PAYLOAD +
            Protocol.GCM_NONCE_LEN + Protocol.GCM_TAG_LEN)
    }

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
        // 阶段3 的身份报文（含 Ed25519 签名）先算好，再发 auth_client_hello：
        // 手机上 BouncyCastle 签名要几百毫秒，夹在两帧之间会白白推迟身份报文上行的
        // 时机（服务端的握手窗口从收到 auth_hello 起算，能省一点是一点）。
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

        // ---- 阶段3：密文身份报文 → identity_ok / identity_deny ----
        state.set(State.Authenticating)
        val auth = retryLoop("阶段3（身份认证）",
            resend = {
                // 与 C++ 端一致：重传身份报文的同时也重传 auth_client_hello（本端临时
                // DH 公钥）。这一帧在阶段2 只发一次，UDP 上丢一次服务端就永远派生不出
                // 会话密钥，之后所有密文帧（含身份报文）都会在解密前被丢弃，表现为
                // 握手超时后断开重连。服务端对该帧有阶段机保护（非 HELLO 阶段
                // 直接拒绝，不会覆盖已派生密钥），所以重传幂等且安全。
                rawSendFrame(Protocol.TYPE_AUTH_CLIENT_HELLO, dhCliPub)
                sendEncrypted(Protocol.TYPE_IDENTITY, body)
            },
            wait = { identityResult.await() })

        authenticated.set(auth)
        state.set(State.Connected)
        auth
    }

    /**
     * 阶段重传循环：立即发一次，之后每 500ms 重传一次；
     * 总超时 8s / 最多 16 次（AUTH_TIMEOUT_MS / AUTH_RETRY_MS / AUTH_MAX_RETRIES）。
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
                // 链路已经死了（recv 循环读到 EOF/出错、或心跳判死）：继续重传毫无意义，
                // 立刻抛出以让上层尽快重连，而不是把整个超时预算耗光后再重连
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

        if (header.type in Protocol.ENCRYPTED_TYPES) {
            if (!keysReady.get()) return   // 密钥未就绪：丢弃
            val seq = header.sequence.toLong() and 0xFFFFFFFFL
            // 反重放分两步：解密前只做"不修改状态"的过旧预检（未认证报文
            // 不能污染窗口），GCM 验证成功后才提交窗口与存活时间
            if (replayWindow.isStale(seq)) return
            // 零分配解密：明文直接落到 rxScratch，避免每包一次 ByteArray 分配
            val plainLen = TunnelCrypto.gcmOpenInto(
                keyRx, buf, Protocol.HEADER_SIZE, len - Protocol.HEADER_SIZE, buf, 0, rxScratch)
            if (plainLen < 0) return   // 解密失败静默丢弃（不推进窗口、不刷新存活）
            if (!replayWindow.accept(seq)) return   // 重放帧：静默丢弃
            lastRxMs.set(System.currentTimeMillis())   // 仅已认证报文刷新存活
            handleInner(rxScratch[0], rxScratch, 1, plainLen - 1)
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
                    // 从池里取缓冲直接拷贝，避免每包 copyOfRange 一次分配
                    val p = obtainRxPacket(len)
                    System.arraycopy(src, off, p.buf, 0, len)
                    // 桥接消费不动则丢弃（隧道内 TCP 重传兜底）；
                    // 发送失败必须立刻回收，否则"已出池但无人消费"的缓冲会永久流失
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
     *
     * 组帧写进线程本地复用缓冲 [txScratch]，不再每包 `new ByteArray(1429)`。
     * 安全性依赖 [rawSend] 同步完成发送（见 txScratch 注释）。
     */
    private fun sendEncryptedSeg(type: Byte, data: ByteArray, off: Int, len: Int) {
        if (!keysReady.get()) throw IOException("密钥未就绪")
        // 序号安全上限（=2^31）：触发重连换新会话（新密钥=新反重放窗口），
        // 防止 32 位序号回绕被滑窗误判
        val seqNum = sequence.getAndIncrement().toLong() and 0xFFFFFFFFL
        if (seqNum >= 0x80000000L) {
            notifyDead("发送序号空间耗尽，重连换新会话密钥")
            return
        }
        val sealedLen = 1 + len + Protocol.GCM_NONCE_LEN + Protocol.GCM_TAG_LEN
        val total = Protocol.HEADER_SIZE + sealedLen
        val scratch = txScratch.get()!!
        // 数据面帧（≤1441B）走复用缓冲；控制面长报文（如含注册令牌的身份报文）
        // 可能超出容量，回退到动态分配——这类报文只在握手时发几次，不影响热路径
        val frame = if (total <= scratch.size) scratch else ByteArray(total)
        Protocol.encodeHeaderInto(frame, 0, wireVersion, type, sealedLen, seqNum.toInt())
        TunnelCrypto.gcmSealInto(keyTx, type, data, off, len, frame, 0, frame, Protocol.HEADER_SIZE)
        rawSend(frame, total)
    }

    /** 上行数据面：VpnService 桥接线程调用（tun fd 读到的 IP 包，不复制直接加密发送） */
    fun sendData(buf: ByteArray, off: Int = 0, len: Int = buf.size): Boolean {
        if (!isAlive || len <= 0 || len > Protocol.MAX_DATA_PAYLOAD) return false
        // 只转发 IPv4：tun 上还有系统自己产生的 IPv6 链路本地报文（MLD/NDP 等
        // 48~76 字节控制报文），服务端隧道的 tun 只有 IPv4，塞进去必被逐包拒收
        // （白耗流量 + 刷服务端日志）。本地丢弃，对齐服务端的 IPv4-only 校验。
        if (len < 20 || (buf[off].toInt() and 0xF0) != 0x40) return false
        return runCatching {
            sendEncryptedSeg(Protocol.TYPE_DATA, buf, off, len)
            true
        }.getOrDefault(false)
    }

    /** 隧道是否可用（桥接线程以此判活退出，避免对已死隧道空转） */
    val isAlive: Boolean get() = running.get() && keysReady.get()

    /**
     * 同步发送一帧。[len] 必须显式给出——复用缓冲比实际帧长，
     * 用 `frame.size` 会把尾部残留的旧数据一起发出去（对端 AAD 校验直接失败）。
     */
    private fun rawSend(frame: ByteArray, len: Int = frame.size) {
        if (useTcp) {
            val out = socketTcp?.getOutputStream() ?: throw IOException("TCP 未连接")
            // 整帧原子写（防多线程交错破坏分帧，对齐 C++ m_send_mutex）
            synchronized(out) {
                out.write(frame, 0, len)
                // 不调 flush()：SocketOutputStream 无用户态缓冲，write 即进内核发送队列
            }
        } else {
            val s = socketUdp ?: throw IOException("UDP 未连接")
            s.send(DatagramPacket(frame, 0, len, remoteAddress))
        }
    }

    // ------------------------------------------------------------------
    // 心跳（Connected 后启动）
    // ------------------------------------------------------------------
    fun startHeartbeat() {
        scope.launch {
            // 单协程同时负责「按点发心跳」与「判失联」，按两个到期时刻中更早的那个唤醒。
            // 心跳间隔 10s 而超时 25s，若只睡到心跳点，失联发现会被拖后最多 10s
            // （表现为切网后 35s 才重连）；这里分别算两个 deadline 取最早。
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
                // 下次唤醒：心跳到期 或 失联判定到期，取更早者
                val deadlineRx = if (last != 0L) last + HEARTBEAT_TIMEOUT_MS + 1 else Long.MAX_VALUE
                val wakeAt = minOf(nextHeart, deadlineRx)
                delay((wakeAt - System.currentTimeMillis()).coerceAtLeast(1L))
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

    /**
     * 外部事件：物理网络已断开（由 VpnService 的 ConnectivityManager 回调驱动）。
     *
     * 为什么要这个：只靠心跳超时判失联，网络一断要干等 25s 才发现，
     * 期间 tun 上的包全部塞进黑洞（应用侧表现为"卡住不动"，然后超时重传），
     * 既拖慢体验又白耗射频。收到系统事件后立即判死，上层 1s 后就开始重连。
     *
     * 只在 [running] 时生效，避免已 stop 的会话再回调一次。
     */
    fun onPhysicalNetworkLost() {
        if (!running.get()) return
        notifyDead("物理网络已断开（系统事件）")
    }

    /**
     * 外部事件：物理网络恢复可用。
     *
     * 若此时隧道已死（[deadNotified]），说明上一次判死发生在无网络期间——
     * 上层会话循环会自己退避重连，这里无需额外动作；保留该入口是为了
     * 将来做"网络恢复立即唤醒退避等待"（目前退避最长 30s，可接受）。
     */
    fun onPhysicalNetworkAvailable() {
        // 占位：退避唤醒见 ScholarVpnService 的 retrySignal（暂未接入）
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

/**
 * 下行 IP 包的池化载体。
 *
 * 为什么不直接传 ByteArray：池化复用必须知道"有效长度"。
 * 裸数组无法携带长度，消费方 `output.write(buf)` 会把整块缓冲（含上一次的残留）
 * 都写进 tun，等于往网卡里灌垃圾包。
 *
 * [len] 是可变字段——池化复用时改长度而不是换对象，稳态下零分配。
 * 只在 Channel 单向流转：生产者填完立刻交出去，消费方读完才回收，不存在共享竞态。
 */
class RxPacket(
    /** 缓冲本体，容量固定不小于首次申请长度 */
    val buf: ByteArray,
    /** 本包有效字节数（buf[0, len) 有效） */
    var len: Int,
)
