package com.vajra.companion.network

import com.vajra.companion.crypto.DeviceRequestSigner
import com.vajra.companion.identity.AndroidKeystoreIdentity
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/**
 * Plane-2 client. Uses system TLS trust store — no custom TrustManager.
 * Server base URL comes from local settings only, never from remote commands.
 */
class VajraApiClient(
    private val identity: AndroidKeystoreIdentity,
    timeoutSeconds: Long = 30,
    private val baseUrlProvider: () -> String,
) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(timeoutSeconds, TimeUnit.SECONDS)
        .readTimeout(timeoutSeconds, TimeUnit.SECONDS)
        .writeTimeout(timeoutSeconds, TimeUnit.SECONDS)
        .build()

    private val jsonMedia = "application/json; charset=utf-8".toMediaType()

    fun enrollmentSubmit(body: JSONObject): Response {
        val url = baseUrlProvider().trimEnd('/') + "/api/devices/enrollment/submit"
        val req = Request.Builder()
            .url(url)
            .post(body.toString().toRequestBody(jsonMedia))
            .header("Accept", "application/json")
            .build()
        return client.newCall(req).execute()
    }

    fun sendSigned(method: String, path: String, bodyJson: String?): Response {
        val meta = identity.loadMeta()
            ?: throw IllegalStateException("Device not enrolled")
        val deviceId = meta.getString("deviceId")
        val base = meta.optString("serverBaseUrl").ifBlank { baseUrlProvider() }.trimEnd('/')
        val normalizedPath = if (path.startsWith("/")) path else "/$path"
        val body = if (bodyJson.isNullOrEmpty()) "{}" else bodyJson
        val timestamp = DeviceRequestSigner.utcTimestampIso()
        val nonce = DeviceRequestSigner.newNonce()
        val transcript = DeviceRequestSigner.buildDeviceAuthTranscript(
            method, normalizedPath, deviceId, timestamp, nonce, body
        )
        val signature = DeviceRequestSigner.signEcdsaSha256(identity.getPrivateKey(), transcript)

        val builder = Request.Builder()
            .url(base + normalizedPath)
            .header("Accept", "application/json")
            .header("X-Vajra-Device-Id", deviceId)
            .header("X-Vajra-Timestamp", timestamp)
            .header("X-Vajra-Nonce", nonce)
            .header("X-Vajra-Signature", signature)

        when (method.uppercase()) {
            "GET" -> builder.get()
            "POST" -> builder.post(body.toRequestBody(jsonMedia))
            else -> throw IllegalArgumentException("Unsupported method $method")
        }

        return client.newCall(builder.build()).execute()
    }

    fun heartbeat(payload: JSONObject): Response =
        sendSigned("POST", "/api/devices/${deviceId()}/heartbeat", payload.toString())

    fun pendingCommands(): Response =
        sendSigned("GET", "/api/devices/${deviceId()}/commands/pending", null)

    fun acknowledge(commandId: String): Response =
        sendSigned("POST", "/api/devices/${deviceId()}/commands/$commandId/acknowledge", "{}")

    fun commandResult(commandId: String, result: JSONObject): Response =
        sendSigned("POST", "/api/devices/${deviceId()}/commands/$commandId/result", result.toString())

    fun submitEvent(evt: JSONObject): Response =
        sendSigned("POST", "/api/devices/${deviceId()}/events", evt.toString())

    private fun deviceId(): String =
        identity.loadMeta()?.getString("deviceId")
            ?: throw IllegalStateException("No deviceId")
}
