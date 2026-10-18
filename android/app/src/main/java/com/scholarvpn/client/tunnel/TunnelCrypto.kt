package com.scholarvpn.client.tunnel

import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.math.ec.rfc7748.X25519
import org.bouncycastle.math.ec.rfc8032.Ed25519

/**
 * 隧道加密层（Kotlin 实现，替代 Windows 端的 Crypt.cpp/OpenSSL）。
 *
 * 线格式三条铁律（见 docs/ANDROID_PROTOCOL_SPEC.md §3/§4，与服务端 OpenSSL 实现互操作）：
 *  1. GCM 输出 = nonce(12) || ciphertext || tag(16)，AAD = 12 字节帧头（含密文长度字段）；
 *  2. HKDF：prk = Extract(salt=nonce_c||nonce_s, ikm=X25519 ss)；
 *     key_tx = Expand(prk,"tx",32)，key_rx = Expand(prk,"rx",32)；
 *  3. Ed25519 为 RFC 8032 纯 EdDSA（64 字节签名），签名载荷拼接顺序不得改动。
 */
object TunnelCrypto {
    private val random = SecureRandom()

    /** 加密时承载"内层 type"字节的线程本地暂存（避免热路径每包分配） */
    private val typeScratch: ThreadLocal<ByteArray> = ThreadLocal.withInitial { ByteArray(1) }

    /**
     * GCM nonce 的线程本地暂存（避免每包 new 12 字节）。
     * GCMParameterSpec 构造时会 clone 传入的 iv，所以 init 之后本数组即可安全复用。
     */
    private val nonceScratch: ThreadLocal<ByteArray> =
        ThreadLocal.withInitial { ByteArray(Protocol.GCM_NONCE_LEN) }

    // 每包热路径的密码对象线程本地复用：Cipher.getInstance/Mac.getInstance
    // 涉及 Provider 查找，逐包调用在弱核手机上开销显著（Android 侧主要分配点）
    private val cipherCache: ThreadLocal<Cipher> =
        ThreadLocal.withInitial { Cipher.getInstance("AES/GCM/NoPadding") }
    private val macCache: ThreadLocal<Mac> =
        ThreadLocal.withInitial { Mac.getInstance("HmacSHA256") }

    // ---------- 随机数 ----------

    fun randomBytes(n: Int): ByteArray = ByteArray(n).also { random.nextBytes(it) }

    // ---------- AES-256-GCM（平台 javax.crypto，Conscrypt 硬件 AES）----------

    /**
     * 加密 inner(=type||payload) 并按线格式直写 [output]：
     * output[outOff .. outOff+12) = 随机 nonce，之后 = ciphertext || tag(16)。
     * 零拷贝：type 经线程本地暂存喂给 cipher，payload 直接从 [data] 段读取。
     * @param aadBuf/aadOff AAD = aadBuf 的帧头 12 字节（必须已把 payload_len 更新为密文长度）
     * @return 写入的密文总长（nonce + ct + tag）
     */
    fun gcmSealInto(
        key: ByteArray, type: Byte,
        data: ByteArray?, dataOff: Int, dataLen: Int,
        aadBuf: ByteArray, aadOff: Int,
        output: ByteArray, outOff: Int,
    ): Int {
        require(key.size == 32) { "AES-256 密钥必须 32 字节" }
        // !! 是安全的：withInitial 的 supplier 永不返回 null，
        // 但 Kotlin 把 Java ThreadLocal.get() 视为 platform type，必须显式断言
        val nonce = nonceScratch.get()!!
        random.nextBytes(nonce)
        System.arraycopy(nonce, 0, output, outOff, Protocol.GCM_NONCE_LEN)
        // Cipher 线程本地复用：每包重新 init（换 nonce/密钥），避免逐包 getInstance
        val cipher = cipherCache.get()!!
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(Protocol.GCM_TAG_LEN * 8, nonce))
        cipher.updateAAD(aadBuf, aadOff, Protocol.HEADER_SIZE)
        val scratch = typeScratch.get()!!
        scratch[0] = type
        cipher.update(scratch)
        val written = if (data != null && dataLen > 0) {
            cipher.doFinal(data, dataOff, dataLen, output, outOff + Protocol.GCM_NONCE_LEN)
        } else {
            cipher.doFinal(output, outOff + Protocol.GCM_NONCE_LEN)
        }
        return Protocol.GCM_NONCE_LEN + written
    }

    /**
     * 解密封装的密文段 sealed[srcOff, srcOff+srcLen)（= nonce(12)||ct||tag(16)）。
     * @param aadBuf/aadOff AAD = 帧头 12 字节
     * @return inner 明文（首字节为内层 type，其后为载荷）；tag 校验失败返回 null（静默丢弃语义）
     *
     * 便利包装：内部转调 [gcmOpenInto]，会分配一次输出数组。
     * **收包热路径请直接调 [gcmOpenInto]**，不要用这个。
     */
    fun gcmOpen(
        key: ByteArray, sealed: ByteArray, srcOff: Int, srcLen: Int,
        aadBuf: ByteArray, aadOff: Int,
    ): ByteArray? {
        val plainLen = srcLen - Protocol.GCM_NONCE_LEN - Protocol.GCM_TAG_LEN
        if (plainLen < 0) return null
        val out = ByteArray(plainLen)
        val n = gcmOpenInto(key, sealed, srcOff, srcLen, aadBuf, aadOff, out)
        return if (n < 0) null else out
    }

    /**
     * 零分配解密：把明文写进调用方提供的 [out]，返回明文长度（失败返回 -1）。
     *
     * 为什么要有这个版本：原 [gcmOpen] 每解一个下行包就 `new ByteArray(1400)`，
     * 紧接着 TunnelClient.handleInner 又 copyOfRange 一次——每个数据包产生
     * 约 2.8KB 垃圾。按 10Mbps 下行（约 900 包/秒）算是 2.5MB/s 的分配率，
     * 弱核手机上 GC 会被迫高频运行，表现为后台持续发热。
     *
     * 约束：[out] 由调用方保证独占（TunnelClient 里是单 recv 线程使用的实例字段），
     * 且长度 ≥ srcLen - 28。返回后 [out] 的内容在下一次调用前有效。
     */
    fun gcmOpenInto(
        key: ByteArray, sealed: ByteArray, srcOff: Int, srcLen: Int,
        aadBuf: ByteArray, aadOff: Int,
        out: ByteArray,
    ): Int {
        require(key.size == 32) { "AES-256 密钥必须 32 字节" }
        val plainLen = srcLen - Protocol.GCM_NONCE_LEN - Protocol.GCM_TAG_LEN
        if (plainLen < 0 || out.size < plainLen) return -1
        // nonce 拷到线程本地暂存，避免每包分配
        val nonce = nonceScratch.get()!!
        System.arraycopy(sealed, srcOff, nonce, 0, Protocol.GCM_NONCE_LEN)
        return try {
            val cipher = cipherCache.get()!!
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"),
                GCMParameterSpec(Protocol.GCM_TAG_LEN * 8, nonce))
            cipher.updateAAD(aadBuf, aadOff, Protocol.HEADER_SIZE)
            // 输入 = ct||tag（长度 srcLen-12），输出长度自动扣掉 tag
            cipher.doFinal(sealed, srcOff + Protocol.GCM_NONCE_LEN,
                srcLen - Protocol.GCM_NONCE_LEN, out, 0)
        } catch (_: Exception) {
            -1   // 认证失败：与 C++ 端一致，静默丢弃
        }
    }

    // ---------- HKDF-SHA256（RFC 5869，手写 ~30 行）----------

    fun hkdfExtract(salt: ByteArray, ikm: ByteArray): ByteArray =
        hmacSha256(salt, ikm)

    fun hkdfExpand(prk: ByteArray, info: String, length: Int): ByteArray {
        val okm = ByteArray(length)
        var t = ByteArray(0)
        var generated = 0
        var counter = 1
        while (generated < length) {
            t = hmacSha256(prk, t + info.toByteArray(Charsets.UTF_8) + byteArrayOf(counter.toByte()))
            val n = minOf(t.size, length - generated)
            System.arraycopy(t, 0, okm, generated, n)
            generated += n
            counter++
        }
        return okm
    }

    /**
     * 方向性会话密钥（阶段2）：与 C++ 端 derive_directional_session_keys 完全一致。
     * @return Pair(keyTx, keyRx) —— 客户端发送加密用 keyTx，接收解密用 keyRx
     */
    fun deriveSessionKeys(sharedSecret: ByteArray, nonceC: ByteArray, nonceS: ByteArray): Pair<ByteArray, ByteArray> {
        val prk = hkdfExtract(nonceC + nonceS, sharedSecret)
        val keyTx = hkdfExpand(prk, "tx", 32)
        val keyRx = hkdfExpand(prk, "rx", 32)
        return keyTx to keyRx
    }

    private fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
        val mac = macCache.get()!!
        mac.init(SecretKeySpec(if (key.isEmpty()) ByteArray(32) else key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    // ---------- Ed25519（RFC 8032，纯 EdDSA，64 字节签名）----------

    /** 生成身份密钥对：返回 Pair(privSeed(32), pub(32))。privSeed 需加密存储。 */
    fun generateEd25519KeyPair(): Pair<ByteArray, ByteArray> {
        val priv = Ed25519PrivateKeyParameters(random)
        return priv.encoded to priv.generatePublicKey().encoded
    }

    fun ed25519Sign(privSeed: ByteArray, message: ByteArray): ByteArray {
        val sig = ByteArray(Ed25519.SIGNATURE_SIZE)
        // 纯 Ed25519（RFC 8032，无 context，sigAlgorithm = Algorithm.Ed25519）
        Ed25519PrivateKeyParameters(privSeed, 0)
            .sign(Ed25519.Algorithm.Ed25519, null, message, 0, message.size, sig, 0)
        return sig
    }

    fun ed25519Verify(pub: ByteArray, message: ByteArray, signature: ByteArray): Boolean =
        try {
            Ed25519.verify(signature, 0, pub, 0, message, 0, message.size)
        } catch (_: Exception) {
            false
        }

    /** 由私钥 seed 推导身份公钥（32 字节 raw） */
    fun ed25519PubFromSeed(privSeed: ByteArray): ByteArray =
        Ed25519PrivateKeyParameters(privSeed, 0).generatePublicKey().encoded

    // ---------- X25519（RFC 7748，临时会话密钥）----------

    /** 生成临时 X25519 密钥对：Pair(priv(32), pub(32))，会话结束即弃（前向安全） */
    fun generateX25519KeyPair(): Pair<ByteArray, ByteArray> {
        val priv = X25519PrivateKeyParameters(random)
        return priv.encoded to priv.generatePublicKey().encoded
    }

    /** ECDH：返回 32 字节共享秘密（对端公钥非法/全零输出时抛异常） */
    fun x25519(priv: ByteArray, peerPub: ByteArray): ByteArray {
        val out = ByteArray(32)
        val ok = X25519.calculateAgreement(priv, 0, peerPub, 0, out, 0)
        check(ok) { "X25519 协商得到全零共享秘密（对端公钥非法）" }
        return out
    }
}
