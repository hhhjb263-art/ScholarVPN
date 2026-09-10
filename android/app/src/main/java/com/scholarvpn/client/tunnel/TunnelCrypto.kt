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
    private val typeScratch = ThreadLocal.withInitial { ByteArray(1) }

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
        val nonce = ByteArray(Protocol.GCM_NONCE_LEN)
        random.nextBytes(nonce)
        System.arraycopy(nonce, 0, output, outOff, Protocol.GCM_NONCE_LEN)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(Protocol.GCM_TAG_LEN * 8, nonce))
        cipher.updateAAD(aadBuf, aadOff, Protocol.HEADER_SIZE)
        val scratch = typeScratch.get()
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
     */
    fun gcmOpen(
        key: ByteArray, sealed: ByteArray, srcOff: Int, srcLen: Int,
        aadBuf: ByteArray, aadOff: Int,
    ): ByteArray? {
        require(key.size == 32)
        if (srcLen < Protocol.GCM_NONCE_LEN + Protocol.GCM_TAG_LEN) return null
        val nonce = sealed.copyOfRange(srcOff, srcOff + Protocol.GCM_NONCE_LEN)
        return try {
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(Protocol.GCM_TAG_LEN * 8, nonce))
            cipher.updateAAD(aadBuf, aadOff, Protocol.HEADER_SIZE)
            val out = ByteArray(srcLen - Protocol.GCM_NONCE_LEN - Protocol.GCM_TAG_LEN)
            cipher.doFinal(sealed, srcOff + Protocol.GCM_NONCE_LEN, srcLen - Protocol.GCM_NONCE_LEN, out, 0)
            out
        } catch (_: Exception) {
            null   // 认证失败：与 C++ 端一致，静默丢弃
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
        val mac = Mac.getInstance("HmacSHA256")
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
