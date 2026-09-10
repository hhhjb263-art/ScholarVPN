package com.scholarvpn.client.vpn

import android.content.Context
import android.util.Log
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey

/**
 * 客户端身份密钥存储（对应 Windows 端 client.id.enc 的 DPAPI 方案）：
 * Ed25519 私钥 seed 存 EncryptedSharedPreferences，
 * 其加密密钥由 Android Keystore 硬件后备（AES256-GCM），绑定本机。
 * 公钥可由 seed 推导（ed25519PubFromSeed），无需单独存储。
 */
class IdentityStore(context: Context) {

    private val prefs by lazy {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
        EncryptedSharedPreferences.create(
            context,
            "scholarvpn_secure",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
        )
    }

    companion object {
        private const val KEY_IDENTITY_SEED = "identity_priv_seed_b64"
        private val TAG = IdentityStore::class.java.simpleName
    }

    /** 取客户端 Ed25519 私钥 seed（32 字节）；首次调用自动生成并落盘 */
    fun getOrCreateIdentitySeed(): ByteArray {
        prefs.getString(KEY_IDENTITY_SEED, null)?.let { existing ->
            return android.util.Base64.decode(existing, android.util.Base64.NO_WRAP)
        }
        val seed = com.scholarvpn.client.tunnel.TunnelCrypto.randomBytes(32)
        prefs.edit()
            .putString(KEY_IDENTITY_SEED, android.util.Base64.encodeToString(seed, android.util.Base64.NO_WRAP))
            .apply()
        Log.i(TAG, "首次运行：已生成客户端身份密钥（Keystore 加密存储）")
        return seed
    }

    /** 客户端身份公钥（32 字节 raw，交给服务端管理员登记进 registered_clients.txt） */
    fun getIdentityPub(): ByteArray =
        com.scholarvpn.client.tunnel.TunnelCrypto.ed25519PubFromSeed(getOrCreateIdentitySeed())
}
