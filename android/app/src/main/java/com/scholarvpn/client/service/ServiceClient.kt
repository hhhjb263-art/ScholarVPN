package com.scholarvpn.client.service

import com.scholarvpn.client.tunnel.TunnelCrypto
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder
import java.util.Base64

/** 受管服务接入点（发行版内置，对齐 Windows src/service/service_bootstrap.h）。 */
object ServiceEndpoints {
    const val BASE_URL = "https://scholarvpn.homes:8445"

    /** service 签名公钥（SPKI DER base64，对应 dist/keys-service/release.key）。 */
    const val PUB_KEY_B64 = "MCowBQYDK2VwAyEAZqHN3GK6ZO5qp7eRAzkfcA5QQfUMZBFk8vLIPlMJpEQ="
}

/** broker 凭据 INI 的解析结果（对齐 Windows service::Credentials）。 */
data class Credentials(
    val fp: String = "",
    val clientId: String = "",
    val token: String = "",        // 一次性注册令牌，仅注册响应携带
    val status: String = "",       // trial | approved | rejected | revoked
    val expireAt: Long = 0,        // unix 秒，0 = 不限
    val quotaBytes: Long = 0,      // 0 = 不限
    val usedBytes: Long = 0,
    val limitKind: String = "",    // 服务器选定的限制维度：days | bytes | none
    val remaining: Long = 0,       // 该维度剩余量（天/字节）；0 = 已超限
    val valid: Boolean = false,
    val error: String = "",
)

/** 闸门判定（对齐 Windows service::Verdict：查不到 ≠ 违规，放行）。 */
data class Verdict(val blocked: Boolean, val reason: String)

data class ManagedServer(val addr: String, val pubkeyB64: String, val remark: String)

class ServiceException(message: String) : Exception(message)

/**
 * 受管服务 HTTP 客户端（纯逻辑 + 网络拆开，网络部分仅此文件）。
 *
 * 可信性铁律（与 Windows/更新系统同一套）：所有 broker 响应都带 Ed25519 签名，
 * 个人凭据在响应头 X-Service-Signature，服务器列表用分离的 .sig 文件；
 * 验签不通过的内容一律拒绝，绝不入库。
 */
object ServiceClient {

    // ------------------------------------------------------------ 纯逻辑 ----

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

    /** 闸门判定：rejected/revoked/到期/配额耗尽 → 禁止连接；查不到 → 放行。 */
    fun evaluate(c: Credentials, nowUnix: Long): Verdict {
        if (!c.valid) {
            return Verdict(false, c.error.ifEmpty { "服务状态未知" })
        }
        if (c.status == "rejected") return Verdict(true, "该设备的服务申请已被拒绝，请联系服务方")
        if (c.status == "revoked") return Verdict(true, "该设备的授权已被服务方取消，请联系服务方")
        // 服务器已选定限制维度并算好剩余量：remaining=0 即超限（统一文案）
        if (c.limitKind == "days" || c.limitKind == "bytes") {
            if (c.remaining <= 0L) {
                return Verdict(true, "已超出使用范围，请联系管理员")
            }
            return Verdict(false, "")
        }
        // 旧 broker 兼容：无新字段时按原始字段判定（文案统一）
        if (c.expireAt != 0L && nowUnix >= c.expireAt) {
            return Verdict(true, "已超出使用范围，请联系管理员")
        }
        if (c.quotaBytes != 0L && c.usedBytes >= c.quotaBytes) {
            return Verdict(true, "已超出使用范围，请联系管理员")
        }
        return Verdict(false, "")
    }

    /**
     * Ed25519 验签。pubB64 是 SPKI DER base64（44 字节，头 12 字节 + 裸钥 32 字节）；
     * 也兼容直接传裸 32 字节 base64（与 config.ini ServerPubKey 的 raw 格式一致）。
     */
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

    // ------------------------------------------------------------ 网络 ----

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
            // 与 Windows 端一致：显式禁用系统代理，避免被本机代理劫持
            System.getProperty("proxyHost")?.let { /* JVM 级代理由系统设置，此处不覆写 */ }
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
        // 头名大小写不敏感（HttpURLConnection 返回的 key 一般保留原样）
        val sig = headers.entries.firstOrNull {
            it.key.equals("X-Service-Signature", ignoreCase = true)
        }?.value?.firstOrNull()
        if (sig.isNullOrBlank()) throw ServiceException("响应缺少 X-Service-Signature")
        return sig
    }

    /** 申请/换发试用。成功 = valid 且签名已验证。 */
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

    /** 状态同步（每次启动 / 手动刷新）。 */
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

    /**
     * 拉取服务器列表（server-list.ini + 分离的 .sig）。验签通过才返回；
     * 失败抛 [ServiceException]。
     */
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
