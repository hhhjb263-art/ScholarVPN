package com.scholarvpn.client.tunnel

class ReplayWindow(private val size: Int = 64) {
    init { require(size in 1..64) { "窗口必须 ≤64（Long 位图）" } }

    private var highest = -1L
    private var window = 0L

    @Synchronized
    fun isStale(seq: Long): Boolean {
        if (highest < 0) return false
        if (seq > highest) return false
        return highest - seq >= size
    }

    @Synchronized
    fun accept(seq: Long): Boolean {
        if (highest < 0) {
            highest = seq
            window = 1L
            return true
        }
        if (seq > highest) {
            val shift = (seq - highest).coerceAtMost(size.toLong()).toInt()
            window = if (shift >= size) 1L else ((window shl shift) or 1L)
            highest = seq
            return true
        }
        val age = highest - seq
        if (age >= size) return false
        val bit = 1L shl age.toInt()
        if (window and bit != 0L) return false
        window = window or bit
        return true
    }
}
