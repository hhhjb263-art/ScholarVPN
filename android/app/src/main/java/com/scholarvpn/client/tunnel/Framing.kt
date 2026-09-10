package com.scholarvpn.client.tunnel

import java.io.IOException

/**
 * TCP 传输分帧（粘包/半包状态机）。
 *
 * 与 Windows 端 TCP::recv_frame 优化后的语义一致（见 src/tcp.cpp）：
 * 「先吃缓冲」——缓冲里已有的完整帧连续逐帧交付（帧间零等待、零 recv），
 * 缓冲不足才由调用方补一次 socket 读。
 *
 * 性能要点：byte[] 数组 + 头尾游标管理，绝不用 ArrayDeque<Byte> 逐字节装箱
 * （1400 字节/包的热路径装箱开销会显著拖慢吞吐）。
 */
class FrameAssembler(initialCapacity: Int = 8192) {

    private var buf = ByteArray(initialCapacity)
    private var head = 0   // 缓冲中有效数据起始
    private var have = 0   // 有效数据字节数

    private val available: Int get() = have - head

    /**
     * 喂入一段 socket 数据，取出缓冲中所有已凑齐的完整帧。
     * 每帧连帧头一起返回（AAD = 帧头起始字节）。
     */
    fun feed(chunk: ByteArray): List<Frame> = feed(chunk, chunk.size)

    /** 分段版：直接读 [chunk] 的前 [chunkLen] 字节（免 recv 结果复制） */
    fun feed(chunk: ByteArray, chunkLen: Int): List<Frame> {
        ensureCapacity(available + chunkLen)
        System.arraycopy(chunk, 0, buf, head + available, chunkLen)
        have += chunkLen

        val frames = ArrayList<Frame>()
        while (true) {
            if (available < Protocol.HEADER_SIZE) break   // 半包：等下一段
            val header = try {
                Protocol.decodeHeader(buf, head)
            } catch (_: Protocol.TruncatedHeaderException) {
                break   // 理论不可达（上面已检查长度）
            } catch (e: IOException) {
                compact()
                throw InvalidFrameException(e.message ?: "非法帧头")
            }
            val frameLen = Protocol.HEADER_SIZE + header.payloadLen
            if (available < frameLen) break   // 半包：等下一段

            frames += Frame(header, buf.copyOfRange(head, head + frameLen))
            head += frameLen
        }
        compact()
        return frames
    }

    /** 有效数据整体前移（消费过的空间让给后续写入）；缓冲过大时收缩 */
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

    class Frame(val header: Protocol.Header, /** 完整帧字节（帧头+载荷），AAD 取 [0,12) */
                val raw: ByteArray) {
        val payload: ByteArray get() = raw.copyOfRange(Protocol.HEADER_SIZE, raw.size)
    }

    class InvalidFrameException(message: String) : IOException(message)
}
