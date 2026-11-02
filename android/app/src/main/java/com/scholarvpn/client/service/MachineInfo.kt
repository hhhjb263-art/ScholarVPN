package com.scholarvpn.client.service

import android.app.ActivityManager
import android.content.Context
import android.os.Build
import android.provider.Settings
import java.security.MessageDigest
import java.util.UUID

/**
 * 机器指纹（受管服务试用模式）——对齐 Windows 端 src/service/machine_id.cpp。
 *
 * 隐私最小化设计（docs/受管服务与试用授权方案.md 2.2）：
 *  - 指纹 = SHA-256("ScholarVPN-Service-v1" | 系统级设备标识)，【只含设备标识】。
 *    os/cpu/ram 只是后台人工核对的展示字段，【绝不参与指纹】——v1 混入后
 *    网卡切换/系统补丁都会让同一台机器变成"新设备"（2026-10-31 教训）。
 *  - Android 的"系统级设备标识"取 ANDROID_ID：随「签名钥 + 设备 + 用户」稳定，
 *    与 Windows MachineGuid 语义最接近（恢复出厂/重装才换）。
 *    极端情况读不到时退化为随机 UUID 落盘（仍稳定，但换机即新设备）。
 *  - 不采集：主机名、用户名、序列号、软件列表、任何用户行为数据。
 */
data class MachineInfo(
    val fp: String,          // 64 位小写 hex 指纹
    val machineId: String,   // ANDROID_ID / UUID 原文
    val os: String,          // 展示用，不参与指纹
    val cpu: String,
    val ramMb: Long,
    val macHash: String,     // Android 上不采集（权限敏感），留空
    val brand: String = "",  // 设备品牌（如 vivo），仅后台展示核对，不参与指纹
    val model: String = "",  // 设备型号，同上
)

object MachineId {
    private const val SALT = "ScholarVPN-Service-v1"
    private const val FALLBACK_PREFS = "scholarvpn_machine"
    private const val FALLBACK_KEY = "machine_id"

    /** 纯函数：由系统级设备标识计算指纹（与 C++ fingerprint_of 逐字节一致）。 */
    fun fingerprintOf(machineId: String): String {
        if (machineId.isEmpty()) return ""
        return sha256Hex(SALT + "|" + machineId)
    }

    fun sha256Hex(s: String): String =
        MessageDigest.getInstance("SHA-256").digest(s.toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }

    /** 采集本机信息并计算指纹。采集失败的字段留空/置 0，整体仍成功。 */
    fun collect(context: Context): MachineInfo {
        var mid = runCatching {
            Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
        }.getOrNull() ?: ""

        if (mid.isBlank()) {
            // ANDROID_ID 读不到（极少数定制系统）：随机 UUID 落盘兜底。
            // 不用固定常量——否则所有读失败的设备会共用同一个"身份"。
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
