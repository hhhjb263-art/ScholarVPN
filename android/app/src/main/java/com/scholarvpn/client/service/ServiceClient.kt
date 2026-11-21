package com.scholarvpn.client.service

import com.scholarvpn.client.tunnel.TunnelCrypto
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.util.Base64

object ServiceEndpoints {
    const val BASE_URL = "https://scholarvpn.homes:8445"

    const val PUB_KEY_B64 = "MCowBQYDK2VwAyEAZqHN3GK6ZO5qp7eRAzkfcA5QQfUMZBFk8vLIPlMJpEQ="
}

data class Credentials(
    val fp: String = "",
    val clientId: String = "",
    val token: String = "",
    val status: String = "",
    val expireAt: Long = 0,
    val quotaBytes: Long = 0,
    val usedBytes: Long = 0,
    val limitKind: String = "",
    val remaining: Long = 0,
    val valid: Boolean = false,
    val error: String = "",
)

data class Verdict(val blocked: Boolean, val reason: String)

data class ManagedServer(val addr: String, val pubkeyB64: String, val remark: String)

class ServiceException(message: String) : Exception(message)

object ServiceClient {

    fun parseCredentials(text: String): Credentials {
        val m = HashMap<String, String>()
        for (line in text.lineSequence()) {
            val t = line.trim()
            if (t.isEmpty() || t.startsWith("#")) continue
            val i = t.indexOf('=')
            if (i <= 0) continue
            m[t.substring(0, i).trim()] = t.substring(i + 1).trim()
        }
        val c = Credentials(
            fp = m["fp"] ?: "",
            clientId = m["client_id"] ?: "",
            token = m["token"] ?: "",
            status = m["status"] ?: "",
            expireAt = m["expire_at"]?.toLongOrNull() ?: 0L,
            quotaBytes = m["quota_bytes"]?.toLongOrNull() ?: 0L,
            usedBytes = m["used_bytes"]?.toLongOrNull() ?: 0L,
            limitKind = m["limit_kind"] ?: "",
            remaining = m["remaining"]?.toLongOrNull() ?: 0L,
        )
        return c.copy(valid = c.clientId.isNotEmpty())
    }

    // 本地准入判定：被拒/吊销/超期/超配额一律拦在连接之前
    fun evaluate(c: Credentials, nowUnix: Long): Verdict {
        if (!c.valid) {
            return Verdict(false, c.error.ifEmpty { "服务状态未知" })
        }
        if (c.status == "rejected") return Verdict(true, "该设备的服务申请已被拒绝，请联系服务方")
        if (c.status == "revoked") return Verdict(true, "该设备的授权已被服务方取消，请联系服务方")
        if (c.limitKind == "days" || c.limitKind == "bytes") {
            if (c.remaining <= 0L) {
                return Verdict(true, "已超出使用范围，请联系管理员")
            }
            return Verdict(false, "")
        }
        if (c.expireAt != 0L && nowUnix >= c.expireAt) {
            return Verdict(true, "已超出使用范围，请联系管理员")
        }
        if (c.quotaBytes != 0L && c.usedBytes >= c.quotaBytes) {
            return Verdict(true, "已超出使用范围，请联系管理员")
        }
        return Verdict(false, "")
    }

    fun verifySignature(body: ByteArray, sigB64: String, pubB64: String): Boolean {
        return runCatching {
            val der = Base64.getDecoder().decode(pubB64)
            val raw = if (der.size == 44 && der[0] == 0x30.toByte()) {
                der.copyOfRange(12, der.size)
            } else der
            if (raw.size != 32) return false
            TunnelCrypto.ed25519Verify(raw, body, Base64.getDecoder().decode(sigB64))
        }.getOrDefault(false)
    }

    fun splitAddr(addr: String): Pair<String, Int>? {
        val i = addr.lastIndexOf(':')
        if (i <= 0) return null
        val host = addr.substring(0, i).trim()
        val port = addr.substring(i + 1).trim().toIntOrNull() ?: return null
        if (host.isEmpty() || port !in 1..65535) return null
        return host to port
    }

    private fun enc(s: String): String =
        URLEncoder.encode(s, "UTF-8")

    private fun httpGet(url: String, timeoutMs: Int): Pair<ByteArray, Map<String, List<String>>> {
        var conn: HttpURLConnection? = null
        try {
            conn = URL(url).openConnection() as HttpURLConnection
            conn.connectTimeout = timeoutMs
            conn.readTimeout = timeoutMs
            conn.instanceFollowRedirects = false
            conn.setRequestProperty("Accept", "text/plain, */*")
            System.getProperty("proxyHost")?.let {   }
            val code = conn.responseCode
            if (code != 200) {
                val err = runCatching { conn.errorStream?.readBytes() }.getOrNull()
                val msg = err?.toString(Charsets.UTF_8)?.lineSequence()?.firstOrNull()
                throw ServiceException("HTTP $code${if (msg.isNullOrBlank()) "" else "：$msg"}")
            }
            return conn.inputStream.readBytes() to conn.headerFields
        } catch (e: ServiceException) {
            throw e
        } catch (e: Exception) {
            throw ServiceException("网络错误：${e.message ?: e.javaClass.simpleName}")
        } finally {
            conn?.disconnect()
        }
    }

    private fun requireSig(headers: Map<String, List<String>>): String {
        val sig = headers.entries.firstOrNull {
            it.key.equals("X-Service-Signature", ignoreCase = true)
        }?.value?.firstOrNull()
        if (sig.isNullOrBlank()) throw ServiceException("响应缺少 X-Service-Signature")
        return sig
    }

    fun registerTrial(
        info: MachineInfo,
        baseUrl: String = ServiceEndpoints.BASE_URL,
        pubB64: String = ServiceEndpoints.PUB_KEY_B64,
        timeoutMs: Int = 8000,
    ): Credentials {
        if (info.fp.length != 64) throw ServiceException("机器指纹不可用，无法申请")
        val q = "fp=${info.fp}&os=${enc(info.os)}&cpu=${enc(info.cpu)}" +
                "&ram=${info.ramMb}&mac=${enc(info.macHash)}" +
                "&brand=${enc(info.brand)}&model=${enc(info.model)}"
        val (body, headers) = httpGet("$baseUrl/trial/register?$q", timeoutMs)
        val sig = requireSig(headers)
        if (!verifySignature(body, sig, pubB64)) throw ServiceException("凭据签名验证失败")
        val c = parseCredentials(body.toString(Charsets.UTF_8))
        if (!c.valid) throw ServiceException("凭据解析失败（缺少 client_id）")
        return c
    }

    fun fetchStatus(
        fp: String,
        baseUrl: String = ServiceEndpoints.BASE_URL,
        pubB64: String = ServiceEndpoints.PUB_KEY_B64,
        timeoutMs: Int = 8000,
    ): Credentials {
        if (fp.length != 64) throw ServiceException("机器指纹不可用")
        val (body, headers) = httpGet("$baseUrl/trial/status?fp=$fp", timeoutMs)
        val sig = requireSig(headers)
        if (!verifySignature(body, sig, pubB64)) throw ServiceException("凭据签名验证失败")
        val c = parseCredentials(body.toString(Charsets.UTF_8))
        if (!c.valid) throw ServiceException("凭据解析失败（缺少 client_id）")
        return c
    }

    // 拉取受管服务器列表并验签；服务端增删节点后客户端下次同步即生效
    fun fetchServerList(
        fp: String,
        baseUrl: String = ServiceEndpoints.BASE_URL,
        pubB64: String = ServiceEndpoints.PUB_KEY_B64,
        timeoutMs: Int = 8000,
    ): List<ManagedServer> {
        if (fp.length != 64) throw ServiceException("机器指纹不可用")
        val (body, _) = httpGet("$baseUrl/svc/server-list.ini?fp=$fp", timeoutMs)
        val (sigBody, _) = httpGet("$baseUrl/svc/server-list.ini.sig?fp=$fp", timeoutMs)
        val sig = sigBody.toString(Charsets.UTF_8).trim()
        if (!verifySignature(body, sig, pubB64)) throw ServiceException("服务器列表签名验证失败")

        val out = ArrayList<ManagedServer>()
        val items = HashMap<Int, MutableMap<String, String>>()
        for (line in body.toString(Charsets.UTF_8).lineSequence()) {
            val t = line.trim()
            if (t.isEmpty() || t.startsWith("#")) continue
            val m = Regex("^(server|pubkey|remark)(\\d+)\\s*=\\s*(.+)$").find(t) ?: continue
            items.getOrPut(m.groupValues[2].toInt()) { mutableMapOf() }[m.groupValues[1]] = m.groupValues[3]
        }
        for (idx in items.keys.sorted()) {
            val it = items[idx] ?: continue
            val addr = it["server"] ?: continue
            val pub = it["pubkey"] ?: continue
            out.add(ManagedServer(addr, pub, it["remark"] ?: ""))
        }
        if (out.isEmpty()) throw ServiceException("服务器列表为空")
        return out
    }
}
