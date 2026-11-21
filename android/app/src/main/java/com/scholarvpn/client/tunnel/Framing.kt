package com.scholarvpn.client.tunnel

import java.io.IOException

class FrameAssembler(initialCapacity: Int = 8192) {

    private var buf = ByteArray(initialCapacity)
    private var head = 0
    private var have = 0

    private val available: Int get() = have - head

    fun feed(chunk: ByteArray): List<Frame> = feed(chunk, chunk.size)

    fun feed(chunk: ByteArray, chunkLen: Int): List<Frame> {
        ensureCapacity(available + chunkLen)
        System.arraycopy(chunk, 0, buf, head + available, chunkLen)
        have += chunkLen

        val frames = ArrayList<Frame>()
        while (true) {
            if (available < Protocol.HEADER_SIZE) break
            val header = try {
                Protocol.decodeHeader(buf, head)
            } catch (_: Protocol.TruncatedHeaderException) {
                break
            } catch (e: IOException) {
                compact()
                throw InvalidFrameException(e.message ?: "非法帧头")
            }
            val frameLen = Protocol.HEADER_SIZE + header.payloadLen
            if (available < frameLen) break

            frames += Frame(header, buf.copyOfRange(head, head + frameLen))
            head += frameLen
        }
        compact()
        return frames
    }

    private fun compact() {
        if (head == 0) return
        System.arraycopy(buf, head, buf, 0, available)
        have -= head
        head = 0
        if (buf.size > 64 * 1024 && available < 8192) {
            buf = ByteArray(8192)
        }
    }

    private fun ensureCapacity(need: Int) {
        if (buf.size >= need) return
        var cap = buf.size
        while (cap < need) cap = cap shl 1
        buf = buf.copyOf(cap)
    }

    class Frame(val header: Protocol.Header,
                val raw: ByteArray) {
        val payload: ByteArray get() = raw.copyOfRange(Protocol.HEADER_SIZE, raw.size)
    }

    class InvalidFrameException(message: String) : IOException(message)
}
