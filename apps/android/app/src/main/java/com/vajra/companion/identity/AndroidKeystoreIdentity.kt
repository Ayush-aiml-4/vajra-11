package com.vajra.companion.identity

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import org.json.JSONObject
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec

/**
 * ECDSA P-256 key in AndroidKeystore (non-exportable private key).
 * Public SPKI PEM + sha256 fingerprint match server expectations.
 */
class AndroidKeystoreIdentity(private val context: Context) {

    companion object {
        const val KEY_ALIAS = "vajra_device_identity_v1"
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
        private const val PREFS = "vajra_identity_meta"
    }

    enum class KeystoreSecurityLevel {
        STRONGBOX,
        TEE,
        SOFTWARE,
        UNKNOWN
    }

    data class PublicIdentity(
        val publicKeyPem: String,
        val fingerprint: String,
        val keyAlgorithm: String = "ECDSA_P256",
        val hardwareBacked: Boolean = false,
        val securityLevel: KeystoreSecurityLevel = KeystoreSecurityLevel.UNKNOWN
    )

    fun getDetailedSecurityLevel(): KeystoreSecurityLevel {
        return try {
            val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
            val entry = ks.getEntry(KEY_ALIAS, null) as? KeyStore.PrivateKeyEntry ?: return KeystoreSecurityLevel.UNKNOWN
            val factory = java.security.KeyFactory.getInstance(entry.privateKey.algorithm, ANDROID_KEYSTORE)
            val keyInfo = factory.getKeySpec(entry.privateKey, android.security.keystore.KeyInfo::class.java)
            if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
                when (keyInfo.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> KeystoreSecurityLevel.STRONGBOX
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> KeystoreSecurityLevel.TEE
                    KeyProperties.SECURITY_LEVEL_SOFTWARE -> KeystoreSecurityLevel.SOFTWARE
                    else -> KeystoreSecurityLevel.UNKNOWN
                }
            } else {
                @Suppress("DEPRECATION")
                if (keyInfo.isInsideSecureHardware) KeystoreSecurityLevel.TEE else KeystoreSecurityLevel.SOFTWARE
            }
        } catch (_: Exception) {
            KeystoreSecurityLevel.UNKNOWN
        }
    }

    fun isHardwareBacked(): Boolean {
        val level = getDetailedSecurityLevel()
        return level == KeystoreSecurityLevel.STRONGBOX || level == KeystoreSecurityLevel.TEE
    }

    fun hasKey(): Boolean {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return ks.containsAlias(KEY_ALIAS)
    }

    fun ensureKey(): PublicIdentity {
        if (!hasKey()) {
            generateKey()
        }
        return exportPublicIdentity()
    }

    /**
     * Generates a fresh ECDSA P-256 keypair in AndroidKeyStore during (re-)enrollment
     * so a previously revoked key fingerprint is never reused on a new enrollment token.
     */
    fun rotateKey(): PublicIdentity {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (ks.containsAlias(KEY_ALIAS)) {
            ks.deleteEntry(KEY_ALIAS)
        }
        generateKey()
        return exportPublicIdentity()
    }

    fun getPrivateKey(): PrivateKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val entry = ks.getEntry(KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
        return entry.privateKey
    }

    fun exportPublicIdentity(): PublicIdentity {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val entry = ks.getEntry(KEY_ALIAS, null) as KeyStore.PrivateKeyEntry
        val cert = entry.certificate as X509Certificate
        // Certificate public key encoding is SPKI-compatible for EC
        val spki = cert.publicKey.encoded
        val pem = toPem("PUBLIC KEY", spki)
        val fp = "sha256:" + MessageDigest.getInstance("SHA-256").digest(spki)
            .joinToString("") { "%02x".format(it) }
        val level = getDetailedSecurityLevel()
        return PublicIdentity(
            publicKeyPem = pem,
            fingerprint = fp,
            hardwareBacked = level == KeystoreSecurityLevel.STRONGBOX || level == KeystoreSecurityLevel.TEE,
            securityLevel = level
        )
    }

    fun deleteKey() {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        if (ks.containsAlias(KEY_ALIAS)) ks.deleteEntry(KEY_ALIAS)
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().clear().apply()
    }

    fun saveMeta(deviceId: String, serverBaseUrl: String, lifecycleState: String) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putString("deviceId", deviceId)
            .putString("serverBaseUrl", serverBaseUrl.trimEnd('/'))
            .putString("lifecycleState", lifecycleState)
            .putLong("updatedAt", System.currentTimeMillis())
            .apply()
    }

    fun loadMeta(): JSONObject? {
        val p = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val deviceId = p.getString("deviceId", null) ?: return null
        return JSONObject().apply {
            put("deviceId", deviceId)
            put("serverBaseUrl", p.getString("serverBaseUrl", "") ?: "")
            put("lifecycleState", p.getString("lifecycleState", "UNREGISTERED") ?: "UNREGISTERED")
            put("lastHeartbeatAt", p.getLong("lastHeartbeatAt", 0L))
            put("updatedAt", p.getLong("updatedAt", 0L))
        }
    }

    fun setLastHeartbeatAt(epochMs: Long) {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit()
            .putLong("lastHeartbeatAt", epochMs)
            .apply()
    }

    fun getLastHeartbeatAt(): Long =
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getLong("lastHeartbeatAt", 0L)

    private fun generateKey() {
        val kpg = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEYSTORE
        )
        val spec = KeyGenParameterSpec.Builder(
            KEY_ALIAS,
            KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY
        )
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false)
            .build()
        kpg.initialize(spec)
        kpg.generateKeyPair()
    }

    private fun toPem(label: String, der: ByteArray): String {
        val b64 = Base64.encodeToString(der, Base64.NO_WRAP)
        val lines = b64.chunked(64).joinToString("\n")
        return "-----BEGIN $label-----\n$lines\n-----END $label-----\n"
    }
}
