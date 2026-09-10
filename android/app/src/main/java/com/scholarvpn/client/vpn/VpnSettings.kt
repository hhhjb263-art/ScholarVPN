package com.scholarvpn.client.vpn

import android.content.Context
import android.util.Base64
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

    private val prefs = context.getSharedPreferences("scholarvpn", Context.MODE_PRIVATE)

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
                .put("pub", s.serverPubKey))
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
