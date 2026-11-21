package com.scholarvpn.client.tunnel

import java.io.IOException

object Protocol {
    val MAGIC: ByteArray = byteArrayOf(0x4E, 0x50, 0x56, 0x4D)

    const val VERSION_UDP: Byte = 1
    const val VERSION_TCP: Byte = 2

    const val HEADER_SIZE = 12
    const val MAX_PAYLOAD_LEN = 1429
    const val MAX_DATA_PAYLOAD = 1400

    const val GCM_NONCE_LEN = 12
    const val GCM_TAG_LEN = 16

    const val TYPE_DATA: Byte = 2
    const val TYPE_HEART: Byte = 3
    const val TYPE_HEART_RESPONSE: Byte = 4
    const val TYPE_DISCONNECT: Byte = 5
    const val TYPE_AUTH_HELLO: Byte = 8
    const val TYPE_AUTH_SERVER_HELLO: Byte = 9
    const val TYPE_AUTH_CLIENT_HELLO: Byte = 10
    const val TYPE_IDENTITY: Byte = 11
    const val TYPE_IDENTITY_OK: Byte = 12
    const val TYPE_IDENTITY_DENY: Byte = 13

    val ENCRYPTED_TYPES: Set<Byte> = setOf(
        TYPE_DATA, TYPE_HEART, TYPE_HEART_RESPONSE,
        TYPE_IDENTITY, TYPE_IDENTITY_OK, TYPE_IDENTITY_DENY, TYPE_DISCONNECT,
    )

    const val AUTH_NONCE_LEN = 16
    const val AUTH_DH_PUB_LEN = 32
    const val AUTH_SIG_LEN = 64
    const val SERVER_HELLO_LEN = AUTH_NONCE_LEN + AUTH_DH_PUB_LEN + AUTH_SIG_LEN

    class Message(val type: Byte, val payload: ByteArray)

    fun encodeHeader(version: Byte, type: Byte, payloadLen: Int, sequence: Int): ByteArray {
        require(payloadLen in 0..MAX_PAYLOAD_LEN) { "payload_len 超限: $payloadLen" }
        val head = ByteArray(HEADER_SIZE)
        encodeHeaderInto(head, 0, version, type, payloadLen, sequence)
        return head
    }

    fun encodeHeaderInto(dst: ByteArray, dstOff: Int, version: Byte, type: Byte, payloadLen: Int, sequence: Int) {
        require(payloadLen in 0..MAX_PAYLOAD_LEN) { "payload_len 超限: $payloadLen" }
        System.arraycopy(MAGIC, 0, dst, dstOff, 4)
        dst[dstOff + 4] = version
        dst[dstOff + 5] = type
        dst[dstOff + 6] = ((payloadLen ushr 8) and 0xFF).toByte()
        dst[dstOff + 7] = (payloadLen and 0xFF).toByte()
        dst[dstOff + 8] = ((sequence ushr 24) and 0xFF).toByte()
        dst[dstOff + 9] = ((sequence ushr 16) and 0xFF).toByte()
        dst[dstOff + 10] = ((sequence ushr 8) and 0xFF).toByte()
        dst[dstOff + 11] = (sequence and 0xFF).toByte()
    }

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
