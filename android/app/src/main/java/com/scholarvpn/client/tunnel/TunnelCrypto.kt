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

object TunnelCrypto {
    private val random = SecureRandom()

    private val typeScratch: ThreadLocal<ByteArray> = ThreadLocal.withInitial { ByteArray(1) }

    private val nonceScratch: ThreadLocal<ByteArray> =
        ThreadLocal.withInitial { ByteArray(Protocol.GCM_NONCE_LEN) }

    private val cipherCache: ThreadLocal<Cipher> =
        ThreadLocal.withInitial { Cipher.getInstance("AES/GCM/NoPadding") }
    private val macCache: ThreadLocal<Mac> =
        ThreadLocal.withInitial { Mac.getInstance("HmacSHA256") }

    fun randomBytes(n: Int): ByteArray = ByteArray(n).also { random.nextBytes(it) }

    fun gcmSealInto(
        key: ByteArray, type: Byte,
        data: ByteArray?, dataOff: Int, dataLen: Int,
        aadBuf: ByteArray, aadOff: Int,
        output: ByteArray, outOff: Int,
    ): Int {
        require(key.size == 32) { "AES-256 密钥必须 32 字节" }
        val nonce = nonceScratch.get()!!
        random.nextBytes(nonce)
        System.arraycopy(nonce, 0, output, outOff, Protocol.GCM_NONCE_LEN)
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

    fun gcmOpenInto(
        key: ByteArray, sealed: ByteArray, srcOff: Int, srcLen: Int,
        aadBuf: ByteArray, aadOff: Int,
        out: ByteArray,
    ): Int {
        require(key.size == 32) { "AES-256 密钥必须 32 字节" }
        val plainLen = srcLen - Protocol.GCM_NONCE_LEN - Protocol.GCM_TAG_LEN
        if (plainLen < 0 || out.size < plainLen) return -1
        val nonce = nonceScratch.get()!!
        System.arraycopy(sealed, srcOff, nonce, 0, Protocol.GCM_NONCE_LEN)
        return try {
            val cipher = cipherCache.get()!!
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"),
                GCMParameterSpec(Protocol.GCM_TAG_LEN * 8, nonce))
            cipher.updateAAD(aadBuf, aadOff, Protocol.HEADER_SIZE)
            cipher.doFinal(sealed, srcOff + Protocol.GCM_NONCE_LEN,
                srcLen - Protocol.GCM_NONCE_LEN, out, 0)
        } catch (_: Exception) {
            -1
        }
    }

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

    fun generateEd25519KeyPair(): Pair<ByteArray, ByteArray> {
        val priv = Ed25519PrivateKeyParameters(random)
        return priv.encoded to priv.generatePublicKey().encoded
    }

    fun ed25519Sign(privSeed: ByteArray, message: ByteArray): ByteArray {
        val sig = ByteArray(Ed25519.SIGNATURE_SIZE)
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

    fun ed25519PubFromSeed(privSeed: ByteArray): ByteArray =
        Ed25519PrivateKeyParameters(privSeed, 0).generatePublicKey().encoded

    fun generateX25519KeyPair(): Pair<ByteArray, ByteArray> {
        val priv = X25519PrivateKeyParameters(random)
        return priv.encoded to priv.generatePublicKey().encoded
    }

    fun x25519(priv: ByteArray, peerPub: ByteArray): ByteArray {
        val out = ByteArray(32)
        val ok = X25519.calculateAgreement(priv, 0, peerPub, 0, out, 0)
        check(ok) { "X25519 协商得到全零共享秘密（对端公钥非法）" }
        return out
    }
}
