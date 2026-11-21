package com.scholarvpn.client.update

import com.scholarvpn.client.service.ServiceClient
import com.scholarvpn.client.service.ServiceEndpoints
import java.net.HttpURLConnection
import java.net.URL
import java.io.File
import java.security.MessageDigest
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

object UpdateChecker {
    // 更新清单由后台托管：地址从受管服务地址派生，不再写死
    val POLICY_URL: String =
        ServiceEndpoints.BASE_URL.trimEnd('/') + "/svc/update-policy.ini"

    // 离线发布密钥的公钥，用于校验清单签名（与受管服务密钥是两把不同的钥匙）
    private const val RELEASE_PUB_B64 =
        "MCowBQYDK2VwAyEAc0EJCcbif2w8vPpeutGT+o7bqTFTdOoRSdrDuOJ4xj4="

    data class Policy(
        val latest: String,
        val notes: String,
        val url: String,
        val sha256: String,
        val size: Long,
    )

    suspend fun fetchPolicy(): Policy = withContext(Dispatchers.IO) {
        val bodyBytes = try {
            httpGetBytes(POLICY_URL)
        } catch (e: IllegalStateException) {
            // 后台尚未发布策略：按"无更新"处理，不打扰用户
            if (e.message?.contains("404") == true) {
                return@withContext Policy(latest = "", notes = "", url = "", sha256 = "", size = 0L)
            }
            throw e
        }
        val sig = httpGet(POLICY_URL + ".sig").trim()
        if (!ServiceClient.verifySignature(bodyBytes, sig, RELEASE_PUB_B64)) {
            throw IllegalStateException("更新策略签名验证失败")
        }
        val kv = parseIni(String(bodyBytes, Charsets.UTF_8))
        // 两端共用同一份清单；缺 android_url 只在"确实有新版本"时才算问题
        val url = kv["android_url"] ?: ""
        Policy(
            latest = kv["latest"] ?: "",
            notes = kv["notes"] ?: "",
            url = url,
            sha256 = kv["android_sha256"] ?: "",
            size = kv["android_size"]?.toLongOrNull() ?: 0L,
        )
    }

    fun hasNewPackage(installedSha: String, policySha: String): Boolean {
        return installedSha.isNotEmpty() && policySha.isNotEmpty() &&
               !installedSha.equals(policySha, ignoreCase = true)
    }

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

    private fun httpGetBytes(url: String): ByteArray {
        val conn = URL(url).openConnection() as HttpURLConnection
        conn.connectTimeout = 5000
        conn.readTimeout = 10000
        try {
            if (conn.responseCode !in 200..299) {
                throw IllegalStateException("HTTP ${conn.responseCode}")
            }
            return conn.inputStream.use { it.readBytes() }
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

    private fun parseIni(text: String): Map<String, String> =
        text.lineSequence()
            .filter { it.isNotBlank() && !it.trimStart().startsWith("#") && '=' in it }
            .associate {
                val i = it.indexOf('=')
                it.substring(0, i).trim() to it.substring(i + 1).trim()
            }
}
