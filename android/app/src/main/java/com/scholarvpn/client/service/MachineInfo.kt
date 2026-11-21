package com.scholarvpn.client.service

import android.app.ActivityManager
import android.content.Context
import android.os.Build
import android.provider.Settings
import java.security.MessageDigest
import java.util.UUID

data class MachineInfo(
    val fp: String,
    val machineId: String,
    val os: String,
    val cpu: String,
    val ramMb: Long,
    val macHash: String,
    val brand: String = "",
    val model: String = "",
)

object MachineId {
    private const val SALT = "ScholarVPN-Service-v1"
    private const val FALLBACK_PREFS = "scholarvpn_machine"
    private const val FALLBACK_KEY = "machine_id"

    fun fingerprintOf(machineId: String): String {
        if (machineId.isEmpty()) return ""
        return sha256Hex(SALT + "|" + machineId)
    }

    fun sha256Hex(s: String): String =
        MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

    fun collect(context: Context): MachineInfo {
        var mid = runCatching {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
        }.getOrNull() ?: ""

        if (mid.isBlank()) {
            val prefs = context.getSharedPreferences(FALLBACK_PREFS, Context.MODE_PRIVATE)
            mid = prefs.getString(FALLBACK_KEY, null) ?: UUID.randomUUID().toString().also {
                prefs.edit().putString(FALLBACK_KEY, it).apply()
            }
        }

        val abi = Build.SUPPORTED_ABIS.firstOrNull() ?: ""
        val os = "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT}) $abi".trim()
        val cpu = if (Build.HARDWARE.isBlank()) abi else "${Build.HARDWARE} / $abi"
        val ramMb = runCatching {
            val am = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            val mi = ActivityManager.MemoryInfo()
            am.getMemoryInfo(mi)
            mi.totalMem / (1024L * 1024L)
        }.getOrDefault(0L)

        return MachineInfo(
            fp = fingerprintOf(mid),
            machineId = mid,
            os = os,
            cpu = cpu,
            brand = Build.MANUFACTURER.trim(),
            model = Build.MODEL.trim(),
            ramMb = ramMb,
            macHash = "",
        )
    }
}
