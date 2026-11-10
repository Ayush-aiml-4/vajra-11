package com.vajra.companion.crypto

import java.security.MessageDigest
import java.security.Signature
import java.security.PrivateKey
import java.time.Instant
import java.util.UUID
import java.util.Base64

/**
 * Plane-2 + enrollment signing compatible with packages/security device-identity.ts
 * and apps/windows-agent DeviceRequestSigner.
 *
 * Device auth transcript:
 * VAJRA-DEVICE-AUTH-V1|METHOD|path|deviceId|timestampIso|nonce|sha256hex(body)
 *
 * Enrollment PoP:
 * VAJRA-ENROLL-V1|deviceId|TOKEN_UPPER|challengeNonce|fingerprint|timestamp|clientNonce
 */
object DeviceRequestSigner {

    fun sha256Hex(data: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(data)
        return digest.joinToString("") { "%02x".format(it) }
    }

    fun bodySha256Hex(bodyJson: String?): String {
        val payload = canonicalJson(if (bodyJson.isNullOrEmpty()) "{}" else bodyJson)
        return sha256Hex(payload.toByteArray(Charsets.UTF_8))
    }

    fun buildDeviceAuthTranscript(
        method: String,
        path: String,
        deviceId: String,
        timestampIso: String,
        nonce: String,
        bodyJson: String?
    ): String {
        val hash = bodySha256Hex(bodyJson)
        return listOf(
            "VAJRA-DEVICE-AUTH-V1",
            method.trim().uppercase(),
            path.trim(),
            deviceId.trim(),
            timestampIso.trim(),
            nonce.trim(),
            hash
        ).joinToString("|")
    }

    fun buildEnrollmentTranscript(
        deviceId: String,
        enrollmentToken: String,
        challengeNonce: String,
        publicKeyFingerprint: String,
        timestampIso: String,
        clientNonce: String
    ): String = listOf(
        "VAJRA-ENROLL-V1",
        deviceId.trim(),
        enrollmentToken.trim().uppercase(),
        challengeNonce.trim(),
        publicKeyFingerprint.trim(),
        timestampIso.trim(),
        clientNonce.trim()
    ).joinToString("|")

    /** ECDSA P-256 with SHA-256 — matches Node crypto.sign('sha256', ...) for ECDSA_P256 */
    fun signEcdsaSha256(privateKey: PrivateKey, transcript: String): String {
        val sig = Signature.getInstance("SHA256withECDSA")
        sig.initSign(privateKey)
        sig.update(transcript.toByteArray(Charsets.UTF_8))
        return Base64.getEncoder().encodeToString(sig.sign())
    }

    fun newNonce(): String {
        val bytes = ByteArray(24)
        java.security.SecureRandom().nextBytes(bytes)
        return bytes.joinToString("") { "%02x".format(it) }
    }

    fun utcTimestampIso(): String = Instant.now().toString()

    /**
     * Recursive key-sorted JSON matching packages/security canonicalJsonSerialize.
     * Call on the exact JSON string before hashing so server req.body re-serialization matches.
     */
    fun canonicalJson(json: String?): String {
        if (json.isNullOrBlank()) return "{}"
        val trimmed = json.trim()
        return try {
            when {
                trimmed.startsWith("{") -> canonicalObject(org.json.JSONObject(trimmed))
                trimmed.startsWith("[") -> canonicalArray(org.json.JSONArray(trimmed))
                else -> trimmed
            }
        } catch (_: Exception) {
            trimmed
        }
    }

    private fun canonicalObject(obj: org.json.JSONObject): String {
        val keys = mutableListOf<String>()
        val iter = obj.keys()
        while (iter.hasNext()) {
            keys.add(iter.next())
        }
        keys.sort()
        val parts = keys.map { key ->
            val encKey = org.json.JSONObject.quote(key)
            val value = obj.get(key)
            "$encKey:${canonicalValue(value)}"
        }
        return "{${parts.joinToString(",")}}"
    }

    private fun canonicalArray(arr: org.json.JSONArray): String {
        val parts = (0 until arr.length()).map { canonicalValue(arr.get(it)) }
        return "[${parts.joinToString(",")}]"
    }

    private fun canonicalValue(value: Any?): String = when (value) {
        null, org.json.JSONObject.NULL -> "null"
        is org.json.JSONObject -> canonicalObject(value)
        is org.json.JSONArray -> canonicalArray(value)
        is String -> org.json.JSONObject.quote(value)
        is Number -> {
            // Match JSON number encoding without scientific notation surprises when possible
            val d = value.toDouble()
            if (d % 1.0 == 0.0 && value is Int) value.toString() else value.toString()
        }
        is Boolean -> value.toString()
        else -> org.json.JSONObject.quote(value.toString())
    }

}
