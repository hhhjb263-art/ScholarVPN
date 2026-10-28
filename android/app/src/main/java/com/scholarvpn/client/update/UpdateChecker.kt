package com.scholarvpn.client.update

import java.net.HttpURLConnection
import java.net.URL
import java.io.File
import java.security.MessageDigest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Android 端更新检查——对应桌面端 docs/客户端更新策略.md 的 android 平台字段
 * （android_url / android_sha256 / android_size，latest 为通用字段）。
 *
 * 策略是 Ed25519 签名的静态 ini（https://scholarvpn.homes:8444/update-policy.ini），
 * Android 侧不做 Ed25519 验签（APK 由系统包管理器校验签名，替换安装包
 * 无法通过 Android 的签名一致性检查），只校验 APK 的 SHA-256 与大小。
 */
object UpdateChecker {
    const val POLICY_URL = "https://scholarvpn.homes:8444/update-policy.ini"

    data class Policy(
        val latest: String,
        val url: String,
        val sha256: String,
        val size: Long,
    )

    /** 拉取并解析策略，失败抛异常 */
    suspend fun fetchPolicy(): Policy = withContext(Dispatchers.IO) {
        val kv = parseIni(httpGet(POLICY_URL))
        val url = kv["android_url"]
            ?: throw IllegalStateException("策略缺少 android_url 字段")
        Policy(
            latest = kv["latest"] ?: "",
            url = url,
            sha256 = kv["android_sha256"] ?: "",
            size = kv["android_size"]?.toLongOrNull() ?: 0L,
        )
    }

    /** 数值版本比较：latest > current 才是有新版本（x.y.z 逐段比较） */
    fun isNewer(latest: String, current: String): Boolean {
        val l = latest.split(".").map { it.trim().toIntOrNull() ?: 0 }
        val c = current.split(".").map { it.trim().toIntOrNull() ?: 0 }
        for (i in 0 until maxOf(l.size, c.size)) {
            val a = l.getOrElse(i) { 0 }
            val b = c.getOrElse(i) { 0 }
            if (a != b) return a > b
        }
        return false
    }

    /**
     * 下载 APK 到 dest：流式写盘 + 边下边算 SHA-256，
     * 哈希/大小不符立即删除文件并抛异常（对应桌面端 download_file 语义）
     */
    suspend fun downloadApk(
        url: String,
        expectedSha256: String,
        expectedSize: Long,
        dest: File,
        onProgress: (Int) -> Unit,
    ): File = withContext(Dispatchers.IO) {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.connectTimeout = 5000
        conn.readTimeout = 15000
        conn.instanceFollowRedirects = true
        try {
            if (conn.responseCode !in 200..299) {
                throw IllegalStateException("HTTP ${conn.responseCode}")
            }
            val digest = MessageDigest.getInstance("SHA-256")
            var total = 0L
            dest.outputStream().use { out ->
                conn.inputStream.use { input ->
                    val buf = ByteArray(16 * 1024)
                    while (true) {
                        val n = input.read(buf)
                        if (n <= 0) break
                        out.write(buf, 0, n)
                        digest.update(buf, 0, n)
                        total += n
                        onProgress(
                            if (expectedSize > 0)
                                (total * 100 / expectedSize).toInt().coerceIn(0, 100)
                            else 0
                        )
                    }
                }
            }
            val hex = digest.digest().joinToString("") { "%02x".format(it) }
            if (expectedSha256.isNotEmpty() && !hex.equals(expectedSha256, ignoreCase = true)) {
                throw IllegalStateException("SHA-256 不匹配（包被篡改或传输损坏）")
            }
            if (expectedSize != 0L && total != expectedSize) {
                throw IllegalStateException("文件大小不符（期望 $expectedSize，实际 $total）")
            }
            dest
        } catch (e: Exception) {
            dest.delete()
            throw e
        } finally {
            conn.disconnect()
        }
    }

    private fun httpGet(url: String): String {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.connectTimeout = 5000
        conn.readTimeout = 10000
        try {
            if (conn.responseCode !in 200..299) {
                throw IllegalStateException("HTTP ${conn.responseCode}")
            }
            return conn.inputStream.bufferedReader().use { it.readText() }
        } finally {
            conn.disconnect()
        }
    }

    /** 简易 ini 解析（key = value，# 注释行跳过）——与桌面端 parse_policy 同语义 */
    private fun parseIni(text: String): Map<String, String> =
        text.lineSequence()
            .filter { it.isNotBlank() && !it.trimStart().startsWith("#") && '=' in it }
            .associate {
                val i = it.indexOf('=')
                it.substring(0, i).trim() to it.substring(i + 1).trim()
            }
}
