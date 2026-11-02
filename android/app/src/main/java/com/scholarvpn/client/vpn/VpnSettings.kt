package com.scholarvpn.client.vpn

import android.content.Context
import android.util.Base64
import com.scholarvpn.client.service.Credentials
import com.scholarvpn.client.service.ServiceClient
import org.json.JSONArray
import org.json.JSONObject

/**
 * 一台服务器（一张卡片）的配置
 */
data class ServerEntry(
    var name: String = "",          // 显示名（空=用 IP）
    var ip: String = "",
    var port: Int = 51820,
    var useTcp: Boolean = false,    // false=UDP（默认）
    var clientId: String = "user",
    var registerToken: String = "", // 一次性注册令牌（空=登录模式）
    var serverPubKey: String = "",  // 服务器公钥（raw base64 或 PEM 原文）
    var managed: Boolean = false,   // 受管下发（服务方列表），刷新时整体替换
)

/** 隧道连接所需的运行时配置（由 [VpnSettings] 从条目派生） */
data class ServerConfig(
    val ip: String,
    val port: Int,
    val useTcp: Boolean,
    val clientId: String,
    val registerToken: ByteArray?,
    val serverPubKey: ByteArray,
)

/**
 * 服务器列表存储（SharedPreferences + JSON 数组）。
 * 旧版单服务器字段（server_ip/...）首次读取时自动迁移为第一张卡片。
 * TODO(M3)：迁移到 DataStore。
 */
class VpnSettings(context: Context) {

    private val appContext = context.applicationContext
    private val prefs = context.getSharedPreferences("scholarvpn", Context.MODE_PRIVATE)

    // ---- 受管服务状态（对齐 Windows config.ini [Service] 段） ----

    data class ServiceState(
        val fp: String = "",
        val clientId: String = "",
        val token: String = "",       // 一次性注册令牌（隧道握手用，成功后由 clearRegisterToken 消费）
        val status: String = "",
        val expireAt: Long = 0,
        val quotaBytes: Long = 0,
        val usedBytes: Long = 0,
        val limitKind: String = "",   // 服务器选定的限制维度：days | bytes | none
        val remaining: Long = 0,      // 该维度剩余量；0 = 已超限
    )

    fun loadServiceState(): ServiceState? {
        val fp = prefs.getString("svc_fp", null) ?: return null
        val cid = prefs.getString("svc_client_id", null) ?: return null
        return ServiceState(
            fp = fp,
            clientId = cid,
            token = prefs.getString("svc_token", "") ?: "",
            status = prefs.getString("svc_status", "") ?: "",
            expireAt = prefs.getLong("svc_expire_at", 0),
            quotaBytes = prefs.getLong("svc_quota", 0),
            usedBytes = prefs.getLong("svc_used", 0),
        )
    }

    fun saveServiceState(s: ServiceState) {
        prefs.edit()
            .putString("svc_fp", s.fp)
            .putString("svc_client_id", s.clientId)
            .putString("svc_token", s.token)
            .putString("svc_status", s.status)
            .putLong("svc_expire_at", s.expireAt)
            .putLong("svc_quota", s.quotaBytes)
            .putLong("svc_used", s.usedBytes)
            .apply()
    }

    /** 把凭据里的最新用量/状态刷回本地（保留 fp/clientId/token）。 */
    fun updateServiceUsage(s: Credentials) {
        val cur = loadServiceState() ?: return
        saveServiceState(
            cur.copy(status = s.status, expireAt = s.expireAt,
                     quotaBytes = s.quotaBytes, usedBytes = s.usedBytes)
        )
    }

    // ---- 服务器列表 ----

    fun loadServers(): MutableList<ServerEntry> {
        val list = mutableListOf<ServerEntry>()
        val json = prefs.getString("servers_json", null)
        if (json != null) {
            val arr = JSONArray(json)
            for (i in 0 until arr.length()) {
                val o = arr.getJSONObject(i)
                list += ServerEntry(
                    name = o.optString("name"),
                    ip = o.optString("ip"),
                    port = o.optInt("port", 51820),
                    useTcp = o.optBoolean("tcp", false),
                    clientId = o.optString("clientId", "user"),
                    registerToken = o.optString("token"),
                    serverPubKey = o.optString("pub"),
                    managed = o.optBoolean("managed", false),
                )
            }
            return list
        }
        // 旧版单服务器迁移（保留联调期间已保存的配置）
        val legacyIp = prefs.getString("server_ip", null)
        if (!legacyIp.isNullOrBlank()) {
            list += ServerEntry(
                name = "",
                ip = legacyIp.trim(),
                port = prefs.getInt("server_port", 51820),
                useTcp = prefs.getBoolean("use_tcp", false),
                clientId = prefs.getString("client_id", "user") ?: "user",
                registerToken = prefs.getString("register_token", "") ?: "",
                serverPubKey = prefs.getString("server_pub_key", "") ?: "",
            )
            saveServers(list)
            setActiveIndex(0)
        }
        return list
    }

    fun saveServers(servers: List<ServerEntry>) {
        val arr = JSONArray()
        for (s in servers) {
            arr.put(JSONObject()
                .put("name", s.name)
                .put("ip", s.ip)
                .put("port", s.port)
                .put("tcp", s.useTcp)
                .put("clientId", s.clientId)
                .put("token", s.registerToken)
                .put("pub", s.serverPubKey)
                .put("managed", s.managed))
        }
        prefs.edit().putString("servers_json", arr.toString()).apply()
    }

    // ---- 当前选中的卡片 ----

    fun activeIndex(): Int = prefs.getInt("active_index", 0)
    fun setActiveIndex(index: Int) {
        prefs.edit().putInt("active_index", index).apply()
    }

    /** 当前选中卡片的运行时配置（供隧道连接） */
    fun activeConfig(): ServerConfig? {
        val servers = loadServers()
        if (servers.isEmpty()) return null
        val idx = activeIndex().coerceIn(0, servers.size - 1)
        val s = servers[idx]
        // 令牌按原始文本发送（64 位十六进制字符本身，对齐 C++ 客户端：
        // 服务端用它和 register_tokens.txt 的行做字符串比对）
        val tokenText = s.registerToken.trim()
        return ServerConfig(
            ip = s.ip.trim(),
            port = s.port,
            useTcp = s.useTcp,
            clientId = s.clientId.ifBlank { "user" },
            registerToken = if (tokenText.isEmpty()) null else tokenText.toByteArray(Charsets.UTF_8),
            serverPubKey = parseServerPubKey(s.serverPubKey),
        )
    }

    /** 注册成功后清空当前卡片的令牌：下次连接自动登录模式（对齐 C++ 端行为） */
    fun clearRegisterToken() {
        val idx = activeIndex()
        val servers = loadServers()
        if (idx in servers.indices) {
            servers[idx].registerToken = ""
            saveServers(servers)
        }
    }

    /**
     * 受管卡片整体替换（对齐 Windows QtWidgetsClass::apply_managed_servers）：
     * 保留用户自建卡片；旧受管卡片整体删除；按服务方下发的列表重建。
     * 受管卡片默认 TCP——移动网络对非标端口的 UDP 国际方向 QoS 丢弃严重
     * （握手通、数据全死，2026-11-01 实测），用户可在编辑页自切。
     *
     * @return 新增卡片数（0 = 服务方列表为空，不动作）
     */
    fun applyManagedServers(
        servers: List<Pair<String, String>>,
        clientId: String,
        token: String,
    ): Int {
        if (servers.isEmpty()) return 0
        val cur = loadServers()
        val kept = cur.filterNot { it.managed }.toMutableList()
        var added = 0
        for ((addr, pub) in servers) {
            val split = ServiceClient.splitAddr(addr) ?: continue
            kept += ServerEntry(
                name = "",
                ip = split.first,
                port = split.second,
                useTcp = true,
                clientId = clientId,
                registerToken = token,
                serverPubKey = pub,
                managed = true,
            )
            added++
        }
        if (kept.size != cur.size || added > 0) saveServers(kept)
        if (added > 0) setActiveIndex(0)   // 卡片集合变了，选中项回到第一张
        return added
    }

    /**
     * 服务器公钥解析：接受两种格式（对应服务端 server_sig.pub 的两种呈现）——
     *  1) raw 32 字节的 base64（44 字符）
     *  2) SPKI PEM 完整文本或其 base64 正文（解码后 44 字节 DER，末 32 字节即公钥）
     */
    private fun parseServerPubKey(input: String): ByteArray {
        val trimmed = input.trim()
        require(trimmed.isNotEmpty()) {
            "未配置服务器公钥：请把服务端 server_sig.pub 内容粘贴到该服务器卡片"
        }
        // PEM：去掉头尾行，只留 base64 正文
        val b64 = trimmed.lines()
            .filter { it.isNotBlank() && !it.startsWith("-----") }
            .joinToString("")
        val der = Base64.decode(b64, Base64.NO_WRAP or Base64.DEFAULT)
        return when {
            der.size == 32 -> der   // raw 公钥 base64
            // Ed25519 SPKI DER：12 字节固定前缀 302a300506032b6570032100 + 32 字节公钥
            der.size == 44 && der[0] == 0x30.toByte() -> der.copyOfRange(12, 44)
            else -> throw IllegalArgumentException(
                "服务器公钥格式无法识别（解码后 ${der.size} 字节，需 raw base64 或 PEM）")
        }
    }
}
