package com.scholarvpn.client.tunnel

import java.io.IOException

/**
 * 隧道线格式常量与帧头编解码。
 *
 * 实现依据：docs/ANDROID_PROTOCOL_SPEC.md（从两端 C++ 代码逐字节提取）。
 * ⚠️ 字节序混合是本协议的关键细节：
 *   - magic 在 C++ 端按 struct 内存拷贝写出（小端）→ 线上字节固定为 4E 50 56 4D；
 *   - payload_len / sequence 按 htons/htonl 写出（大端）。
 */
object Protocol {
    /** Kmagic = 0x4D56504E 的小端字节表示（直接按字节比对，勿用整数读） */
    val MAGIC: ByteArray = byteArrayOf(0x4E, 0x50, 0x56, 0x4D)

    const val VERSION_UDP: Byte = 1   // v_udp
    const val VERSION_TCP: Byte = 2   // v_tcp

    const val HEADER_SIZE = 12
    const val MAX_PAYLOAD_LEN = 1429          // Max_payload_len（密文帧上限）
    const val MAX_DATA_PAYLOAD = 1400         // KMax_data_payload（明文载荷上限，= TUN MTU）

    // GCM 封装开销：nonce(12) + tag(16)
    const val GCM_NONCE_LEN = 12
    const val GCM_TAG_LEN = 16

    // 消息类型（type 字段）
    const val TYPE_DATA: Byte = 2
    const val TYPE_HEART: Byte = 3
    const val TYPE_HEART_RESPONSE: Byte = 4
    const val TYPE_DISCONNECT: Byte = 5
    const val TYPE_AUTH_HELLO: Byte = 8            // C→S 明文 nonce_c(16)
    const val TYPE_AUTH_SERVER_HELLO: Byte = 9     // S→C 明文 112 字节
    const val TYPE_AUTH_CLIENT_HELLO: Byte = 10    // C→S 明文 dh_cli_pub(32)
    const val TYPE_IDENTITY: Byte = 11             // 密文 身份报文
    const val TYPE_IDENTITY_OK: Byte = 12          // 密文 vip(4)+prefix(1)
    const val TYPE_IDENTITY_DENY: Byte = 13        // 密文 reason(1)

    // 密钥就绪后必须加密的类型集合（其余明文类型仅阶段1合法）
    val ENCRYPTED_TYPES: Set<Byte> = setOf(
        TYPE_DATA, TYPE_HEART, TYPE_HEART_RESPONSE,
        TYPE_IDENTITY, TYPE_IDENTITY_OK, TYPE_IDENTITY_DENY, TYPE_DISCONNECT,
    )

    // 阶段1 / 身份报文的固定长度
    const val AUTH_NONCE_LEN = 16
    const val AUTH_DH_PUB_LEN = 32
    const val AUTH_SIG_LEN = 64
    const val SERVER_HELLO_LEN = AUTH_NONCE_LEN + AUTH_DH_PUB_LEN + AUTH_SIG_LEN // 112 = nonce_s(16)+dh_srv_pub(32)+sig(64)

    /** 一条完整的隧道消息（已解密后的抽象；密文阶段由 TunnelCrypto 处理） */
    class Message(val type: Byte, val payload: ByteArray)

    /**
     * 编码帧头到大端/小端混合布局（见类注释）。
     * @param payloadLen 写入帧头的 payload_len 字段（密文场景 = 密文长度）
     */
    fun encodeHeader(version: Byte, type: Byte, payloadLen: Int, sequence: Int): ByteArray {
        require(payloadLen in 0..MAX_PAYLOAD_LEN) { "payload_len 超限: $payloadLen" }
        val head = ByteArray(HEADER_SIZE)
        encodeHeaderInto(head, 0, version, type, payloadLen, sequence)
        return head
    }

    /** 帧头直写 [dst]（热路径免分配：整个密文帧一次分配组装） */
    fun encodeHeaderInto(dst: ByteArray, dstOff: Int, version: Byte, type: Byte, payloadLen: Int, sequence: Int) {
        require(payloadLen in 0..MAX_PAYLOAD_LEN) { "payload_len 超限: $payloadLen" }
        System.arraycopy(MAGIC, 0, dst, dstOff, 4)
        dst[dstOff + 4] = version
        dst[dstOff + 5] = type
        dst[dstOff + 6] = ((payloadLen ushr 8) and 0xFF).toByte()   // 大端（htons）
        dst[dstOff + 7] = (payloadLen and 0xFF).toByte()
        dst[dstOff + 8] = ((sequence ushr 24) and 0xFF).toByte()    // 大端（htonl）
        dst[dstOff + 9] = ((sequence ushr 16) and 0xFF).toByte()
        dst[dstOff + 10] = ((sequence ushr 8) and 0xFF).toByte()
        dst[dstOff + 11] = (sequence and 0xFF).toByte()
    }

    /**
     * 解码帧头。帧头不完整时抛 [TruncatedHeaderException]；
     * magic/版本不匹配或长度超限抛 [IOException]（调用方应断开）。
     */
    fun decodeHeader(buf: ByteArray, offset: Int = 0): Header {
        if (buf.size - offset < HEADER_SIZE) throw TruncatedHeaderException()
        for (i in 0 until 4) {
            if (buf[offset + i] != MAGIC[i]) {
                throw IOException("非法 magic @${offset + i}: ${buf[offset + i]}")
            }
        }
        val version = buf[offset + 4]
        val type = buf[offset + 5]
        val payloadLen = ((buf[offset + 6].toInt() and 0xFF) shl 8) or
            (buf[offset + 7].toInt() and 0xFF)
        if (payloadLen > MAX_PAYLOAD_LEN) {
            throw IOException("帧超长: $payloadLen")
        }
        val sequence = ((buf[offset + 8].toInt() and 0xFF) shl 24) or
            ((buf[offset + 9].toInt() and 0xFF) shl 16) or
            ((buf[offset + 10].toInt() and 0xFF) shl 8) or
            (buf[offset + 11].toInt() and 0xFF)
        return Header(version, type, payloadLen, sequence)
    }

    class Header(val version: Byte, val type: Byte, val payloadLen: Int, val sequence: Int)

    class TruncatedHeaderException : IOException("帧头不完整")

    /**
     * 阶段3身份 payload（被 Ed25519 签名的部分，规格 §4）：
     * nonce_c || nonce_s || dh_cli_pub || dh_srv_pub || sig_cli_pub || id_len || client_id
     */
    fun buildIdentityPayload(
        nonceC: ByteArray,
        nonceS: ByteArray,
        dhCliPub: ByteArray,
        dhSrvPub: ByteArray,
        cliPub: ByteArray,
        clientId: String,
    ): ByteArray {
        val idUtf8 = clientId.toByteArray(Charsets.UTF_8)
        require(idUtf8.size <= 255) { "client_id 过长" }
        require(nonceC.size == AUTH_NONCE_LEN && nonceS.size == AUTH_NONCE_LEN)
        require(dhCliPub.size == AUTH_DH_PUB_LEN && dhSrvPub.size == AUTH_DH_PUB_LEN)
        require(cliPub.size == AUTH_DH_PUB_LEN)
        val payload = ByteArray(AUTH_NONCE_LEN * 2 + AUTH_DH_PUB_LEN * 3 + 1 + idUtf8.size)
        var off = 0
        fun put(src: ByteArray) { System.arraycopy(src, 0, payload, off, src.size); off += src.size }
        put(nonceC); put(nonceS); put(dhCliPub); put(dhSrvPub); put(cliPub)
        payload[off++] = idUtf8.size.toByte()
        put(idUtf8)
        return payload
    }

    /** 阶段3身份报文体：flags(1) | token_len(1) | token | identity_payload | sig_cli(64) */
    fun buildIdentityBody(
        register: Boolean,
        token: ByteArray?,
        identityPayload: ByteArray,
        signature: ByteArray,
    ): ByteArray {
        require(signature.size == AUTH_SIG_LEN)
        val tok = token ?: ByteArray(0)
        require(tok.size <= 255)
        val body = ByteArray(2 + tok.size + identityPayload.size + AUTH_SIG_LEN)
        var p = 0
        body[p++] = if (register) 1 else 0
        body[p++] = tok.size.toByte()
        System.arraycopy(tok, 0, body, p, tok.size); p += tok.size
        System.arraycopy(identityPayload, 0, body, p, identityPayload.size); p += identityPayload.size
        System.arraycopy(signature, 0, body, p, AUTH_SIG_LEN)
        return body
    }
}
