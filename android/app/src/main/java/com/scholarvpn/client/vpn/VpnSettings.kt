package com.scholarvpn.client.vpn

import android.content.Context
import android.util.Base64
import com.scholarvpn.client.service.Credentials
import com.scholarvpn.client.service.ServiceClient
import org.json.JSONArray
import org.json.JSONObject

data class ServerEntry(
    var name: String = "",
    var ip: String = "",
    var port: Int = 51820,
    var useTcp: Boolean = false,
    var clientId: String = "user",
    var registerToken: String = "",
    var serverPubKey: String = "",
    var intranetSubnets: String = "",
    var managed: Boolean = false,
)

data class ServerConfig(
    val ip: String,
    val port: Int,
    val useTcp: Boolean,
    val clientId: String,
    val registerToken: ByteArray?,
    val serverPubKey: ByteArray,
    val intranetSubnets: String,
    val managed: Boolean,
)

class VpnSettings(context: Context) {

    private val appContext = context.applicationContext
    private val prefs = context.getSharedPreferences("scholarvpn", Context.MODE_PRIVATE)

    data class ServiceState(
        val fp: String = "",
        val clientId: String = "",
        val token: String = "",
        val status: String = "",
        val expireAt: Long = 0,
        val quotaBytes: Long = 0,
        val usedBytes: Long = 0,
        val limitKind: String = "",
        val remaining: Long = 0,
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

    fun updateServiceUsage(s: Credentials) {
        val cur = loadServiceState() ?: return
        saveServiceState(
            cur.copy(status = s.status, expireAt = s.expireAt,
                     quotaBytes = s.quotaBytes, usedBytes = s.usedBytes)
        )
    }

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
                    intranetSubnets = o.optString("subnets"),
                    managed = o.optBoolean("managed", false),
                )
            }
            return list
        }
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
                .put("subnets", s.intranetSubnets)
                .put("managed", s.managed))
        }
        prefs.edit().putString("servers_json", arr.toString()).apply()
    }

    fun activeIndex(): Int = prefs.getInt("active_index", 0)
    fun setActiveIndex(index: Int) {
        prefs.edit().putInt("active_index", index).apply()
    }

    fun activeConfig(): ServerConfig? {
        val servers = loadServers()
        if (servers.isEmpty()) return null
        val idx = activeIndex().coerceIn(0, servers.size - 1)
        val s = servers[idx]
        val tokenText = s.registerToken.trim()
        return ServerConfig(
            ip = s.ip.trim(),
            port = s.port,
            useTcp = s.useTcp,
            clientId = s.clientId.ifBlank { "user" },
            registerToken = if (tokenText.isEmpty()) null else tokenText.toByteArray(Charsets.UTF_8),
            serverPubKey = parseServerPubKey(s.serverPubKey),
            intranetSubnets = s.intranetSubnets,
            managed = s.managed,
        )
    }

    fun clearRegisterToken() {
        val idx = activeIndex()
        val servers = loadServers()
        if (idx in servers.indices) {
            servers[idx].registerToken = ""
            saveServers(servers)
        }
    }

    // 用服务端下发的列表重建受管卡片，手工添加的条目保留不受影响
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
        if (added > 0) setActiveIndex(0)
        return added
    }

    private fun parseServerPubKey(input: String): ByteArray {
        val trimmed = input.trim()
        require(trimmed.isNotEmpty()) {
            "未配置服务器公钥：请把服务端 server_sig.pub 内容粘贴到该服务器卡片"
        }
        val b64 = trimmed.lines()
            .filter { it.isNotBlank() && !it.startsWith("-----") }
            .joinToString("")
        val der = Base64.decode(b64, Base64.NO_WRAP or Base64.DEFAULT)
        return when {
            der.size == 32 -> der
            der.size == 44 && der[0] == 0x30.toByte() -> der.copyOfRange(12, 44)
            else -> throw IllegalArgumentException(
                "服务器公钥格式无法识别（解码后 ${der.size} 字节，需 raw base64 或 PEM）")
        }
    }
}
