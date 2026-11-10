package com.vajra.companion

import android.os.BatteryManager
import com.vajra.companion.commands.CommandCapabilityMatrix
import com.vajra.companion.crypto.DeviceRequestSigner
import com.vajra.companion.work.HeartbeatWorker
import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.HttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.nio.ByteBuffer
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.spec.ECGenParameterSpec
import java.time.Instant
import java.util.Base64
import java.util.UUID
import java.util.concurrent.TimeUnit
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Live HTTP + PostgreSQL end-to-end verification of the Android companion cryptographic protocol,
 * enrollment, Plane-2 OkHttp request signing, Android battery telemetry persistence & history,
 * REQUEST_DEVICE_STATUS + RING_DEVICE command lifecycle, replay/tamper/timestamp defenses,
 * and permanent revocation against the real VAJRA server.
 *
 * Activated when VAJRA_LIVE_API_URL is set (mandatory when VAJRA_REQUIRE_LIVE_E2E=1).
 */
class LiveServerAndroidE2ETest {

    private val jsonMedia = "application/json; charset=utf-8".toMediaType()

    @Test
    fun androidCompanion_fullLifecycleAgainstLivePostgreSqlServer() {
        val baseUrl = System.getenv("VAJRA_LIVE_API_URL")?.trim()?.trimEnd('/')
        val requireLive = System.getenv("VAJRA_REQUIRE_LIVE_E2E") == "1"

        if (baseUrl.isNullOrBlank()) {
            assertFalse("VAJRA_REQUIRE_LIVE_E2E=1 set without VAJRA_LIVE_API_URL", requireLive)
            return
        }

        val cookieStore = mutableMapOf<String, Cookie>()
        val client = OkHttpClient.Builder()
            .connectTimeout(30, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .cookieJar(object : CookieJar {
                override fun saveFromResponse(url: HttpUrl, cookies: List<Cookie>) {
                    for (c in cookies) {
                        cookieStore[c.name] = c
                    }
                }

                override fun loadForRequest(url: HttpUrl): List<Cookie> =
                    cookieStore.values.filter { it.expiresAt > System.currentTimeMillis() && it.value.isNotEmpty() }
            })
            .build()

        // 1. Verify live PostgreSQL readiness
        client.newCall(Request.Builder().url("$baseUrl/api/ready").get().build()).execute().use { res ->
            assertEquals(200, res.code)
            val doc = JSONObject(res.body!!.string())
            assertEquals(
                "postgresql",
                doc.getJSONObject("checks").getJSONObject("identityStore").getString("backend")
            )
        }

        // 2. Register disposable owner account
        val suffix = UUID.randomUUID().toString().replace("-", "").take(10)
        val regBody = JSONObject()
            .put("email", "android-e2e-$suffix@vajra.test")
            .put("displayName", "Android Companion E2E Verifier")
            .put("password", "Correct-Horse-Battery-99!Staple")

        val csrfToken: String
        postJson(client, "$baseUrl/api/auth/register", regBody, null).use { res ->
            assertEquals(201, res.code)
            val doc = JSONObject(res.body!!.string())
            csrfToken = doc.getString("csrfToken")
            assertTrue(csrfToken.isNotBlank())
        }

        // 3. Enable TOTP MFA for step-up protected RING_DEVICE and DEVICE_REVOKE
        val totpSecretBase32: String
        postJson(client, "$baseUrl/api/auth/mfa/setup", JSONObject(), csrfToken).use { res ->
            assertEquals(200, res.code)
            totpSecretBase32 = JSONObject(res.body!!.string()).getString("secretBase32")
        }
        postJson(
            client,
            "$baseUrl/api/auth/mfa/verify",
            JSONObject().put("code", computeTotpCode(totpSecretBase32)),
            csrfToken
        ).use { res ->
            assertEquals(200, res.code)
        }

        // 4. Plane-1 initiate ANDROID device enrollment
        val deviceId: String
        val enrollmentToken: String
        val challengeNonce: String
        postJson(
            client,
            "$baseUrl/api/devices/enrollment/initiate",
            JSONObject()
                .put("name", "Pixel 8 Pro E2E")
                .put("deviceType", "ANDROID")
                .put("osVersion", "Android 14"),
            csrfToken
        ).use { res ->
            assertEquals(201, res.code)
            val doc = JSONObject(res.body!!.string())
            deviceId = doc.getJSONObject("device").getString("id")
            val enrollObj = doc.getJSONObject("enrollment")
            enrollmentToken = enrollObj.getString("enrollmentToken")
            challengeNonce = enrollObj.getString("challengeNonce")
        }

        // 5. Generate real JCA ECDSA P-256 keypair (secp256r1) and submit signed PoP
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val kp = kpg.generateKeyPair()
        val spkiDer = kp.public.encoded
        val fingerprint = "sha256:" + MessageDigest.getInstance("SHA-256")
            .digest(spkiDer)
            .joinToString("") { "%02x".format(it) }
        val publicKeyPem = toPem("PUBLIC KEY", spkiDer)

        val enrollTs = DeviceRequestSigner.utcTimestampIso()
        val clientNonce = DeviceRequestSigner.newNonce()
        val enrollTranscript = DeviceRequestSigner.buildEnrollmentTranscript(
            deviceId, enrollmentToken, challengeNonce, fingerprint, enrollTs, clientNonce
        )
        val enrollSig = DeviceRequestSigner.signEcdsaSha256(kp.private, enrollTranscript)

        postJson(
            client,
            "$baseUrl/api/devices/enrollment/submit",
            JSONObject()
                .put("enrollmentToken", enrollmentToken)
                .put("publicKeyPem", publicKeyPem)
                .put("keyAlgorithm", "ECDSA_P256")
                .put("signatureBase64", enrollSig)
                .put("timestampIso", enrollTs)
                .put("clientNonce", clientNonce),
            null
        ).use { res ->
            assertEquals(200, res.code)
            assertEquals(
                "KEY_SUBMITTED_AWAITING_OWNER_CONFIRMATION",
                JSONObject(res.body!!.string()).getString("status")
            )
        }

        // 6. Plane-2 heartbeat BEFORE owner confirmation must fail with 403 DEVICE_NOT_TRUSTED
        val initialHb = HeartbeatWorker.buildHeartbeatPayload(
            osRelease = "14",
            level = 2,
            scale = 3,
            status = BatteryManager.BATTERY_STATUS_CHARGING,
            hasBatteryIntent = true
        )
        sendPlane2(client, baseUrl, "POST", "/api/devices/$deviceId/heartbeat", deviceId, kp.private, initialHb.toString()).use { res ->
            assertEquals(403, res.code)
            assertEquals("DEVICE_NOT_TRUSTED", errorCode(res))
        }

        // 7. Owner confirms enrollment -> TRUSTED
        postJson(
            client,
            "$baseUrl/api/devices/$deviceId/enrollment/confirm",
            JSONObject().put("publicKeyFingerprint", fingerprint),
            csrfToken
        ).use { res ->
            assertEquals(200, res.code)
            assertEquals(
                "TRUSTED",
                JSONObject(res.body!!.string()).getJSONObject("device").getString("lifecycleState")
            )
        }

        // 8. Send real signed Android heartbeats (67% charging, then 64% discharging, then unknown battery null)
        val fixedNonce = DeviceRequestSigner.newNonce()
        val fixedTs = DeviceRequestSigner.utcTimestampIso()
        sendPlane2(
            client,
            baseUrl,
            "POST",
            "/api/devices/$deviceId/heartbeat",
            deviceId,
            kp.private,
            initialHb.toString(),
            overrideTs = fixedTs,
            overrideNonce = fixedNonce
        ).use { res ->
            assertEquals(200, res.code)
            val hb = JSONObject(res.body!!.string()).getJSONObject("heartbeat")
            assertEquals(67, hb.getInt("batteryLevel"))
            assertEquals(true, hb.getBoolean("charging"))
        }

        val secondHb = HeartbeatWorker.buildHeartbeatPayload(
            osRelease = "14",
            level = 64,
            scale = 100,
            status = BatteryManager.BATTERY_STATUS_DISCHARGING,
            hasBatteryIntent = true
        )
        sendPlane2(client, baseUrl, "POST", "/api/devices/$deviceId/heartbeat", deviceId, kp.private, secondHb.toString()).use { res ->
            assertEquals(200, res.code)
            val hb = JSONObject(res.body!!.string()).getJSONObject("heartbeat")
            assertEquals(64, hb.getInt("batteryLevel"))
            assertEquals(false, hb.getBoolean("charging"))
        }

        // Verify GET /api/devices/:id/battery-history reflects persisted PostgreSQL readings
        client.newCall(Request.Builder().url("$baseUrl/api/devices/$deviceId/battery-history").get().build()).execute().use { res ->
            assertEquals(200, res.code)
            val hist = JSONObject(res.body!!.string())
            assertEquals(64, hist.getInt("currentLevel"))
            assertEquals(false, hist.getBoolean("charging"))
            assertTrue(hist.getBoolean("hasTelemetry"))
            val readings = hist.getJSONArray("readings")
            assertEquals(2, readings.length())
            assertEquals(67, readings.getJSONObject(0).getInt("batteryLevel"))
            assertEquals(true, readings.getJSONObject(0).getBoolean("charging"))
            assertEquals(64, readings.getJSONObject(1).getInt("batteryLevel"))
            assertEquals(false, readings.getJSONObject(1).getBoolean("charging"))
        }

        // Heartbeat with missing battery intent omits batteryLevel & charging -> stored as null
        val noBatteryHb = HeartbeatWorker.buildHeartbeatPayload(
            osRelease = "14",
            level = -1,
            scale = -1,
            status = -1,
            hasBatteryIntent = false
        )
        sendPlane2(client, baseUrl, "POST", "/api/devices/$deviceId/heartbeat", deviceId, kp.private, noBatteryHb.toString()).use { res ->
            assertEquals(200, res.code)
            val hb = JSONObject(res.body!!.string()).getJSONObject("heartbeat")
            assertTrue(hb.isNull("batteryLevel"))
            assertTrue(hb.isNull("charging"))
        }

        // 9. Security negative checks: replay nonce (409), stale timestamp (401), tampered body (401)
        sendPlane2(
            client,
            baseUrl,
            "POST",
            "/api/devices/$deviceId/heartbeat",
            deviceId,
            kp.private,
            initialHb.toString(),
            overrideTs = fixedTs,
            overrideNonce = fixedNonce
        ).use { res ->
            assertEquals(409, res.code)
            assertEquals("DEVICE_NONCE_REPLAYED", errorCode(res))
        }

        sendPlane2(
            client,
            baseUrl,
            "POST",
            "/api/devices/$deviceId/heartbeat",
            deviceId,
            kp.private,
            secondHb.toString(),
            overrideTs = Instant.now().minusSeconds(300).toString()
        ).use { res ->
            assertEquals(401, res.code)
            assertEquals("DEVICE_TIMESTAMP_EXPIRED", errorCode(res))
        }

        sendPlane2(
            client,
            baseUrl,
            "POST",
            "/api/devices/$deviceId/heartbeat",
            deviceId,
            kp.private,
            secondHb.toString(),
            tamperedWireBody = """{"connectivityStatus":"OFFLINE","batteryLevel":1}"""
        ).use { res ->
            assertEquals(401, res.code)
            assertEquals("INVALID_DEVICE_SIGNATURE", errorCode(res))
        }

        // 10. Unsupported command rejected without being queued (400 UNSUPPORTED_DEVICE_ACTION)
        postJson(
            client,
            "$baseUrl/api/devices/$deviceId/commands",
            JSONObject().put("actionType", "INSTALL_APK"),
            csrfToken
        ).use { res ->
            assertEquals(400, res.code)
            assertEquals("UNSUPPORTED_DEVICE_ACTION", errorCode(res))
        }

        // 11. Queue REQUEST_DEVICE_STATUS + step-up RING_DEVICE -> poll -> ack -> complete
        val statusCmdId: String
        postJson(
            client,
            "$baseUrl/api/devices/$deviceId/commands",
            JSONObject().put("actionType", CommandCapabilityMatrix.REQUEST_DEVICE_STATUS),
            csrfToken
        ).use { res ->
            assertEquals(201, res.code)
            statusCmdId = JSONObject(res.body!!.string()).getJSONObject("command").getString("id")
        }

        postJson(
            client,
            "$baseUrl/api/auth/step-up",
            JSONObject()
                .put("actionScope", "SENSITIVE_COMMAND")
                .put("totpCode", computeTotpCode(totpSecretBase32)),
            csrfToken
        ).use { res ->
            assertEquals(200, res.code)
        }

        val ringCmdId: String
        postJson(
            client,
            "$baseUrl/api/devices/$deviceId/commands",
            JSONObject().put("actionType", CommandCapabilityMatrix.RING_DEVICE),
            csrfToken
        ).use { res ->
            assertEquals(201, res.code)
            ringCmdId = JSONObject(res.body!!.string()).getJSONObject("command").getString("id")
        }

        sendPlane2(client, baseUrl, "GET", "/api/devices/$deviceId/commands/pending", deviceId, kp.private, null).use { res ->
            assertEquals(200, res.code)
            val cmds = JSONObject(res.body!!.string()).getJSONArray("commands")
            assertEquals(2, cmds.length())
        }

        for ((cmdId, action) in listOf(
            statusCmdId to CommandCapabilityMatrix.REQUEST_DEVICE_STATUS,
            ringCmdId to CommandCapabilityMatrix.RING_DEVICE
        )) {
            assertTrue(CommandCapabilityMatrix.isExecutableOnAndroid(action))
            sendPlane2(client, baseUrl, "POST", "/api/devices/$deviceId/commands/$cmdId/acknowledge", deviceId, kp.private, "{}").use { res ->
                assertEquals(200, res.code)
            }
            val resultJson = JSONObject()
                .put("status", "COMPLETED")
                .put("safeMessage", "Executed $action on Android companion.")
                .put("resultMetadata", JSONObject().put("agentVersion", "0.1.0-android"))
            sendPlane2(client, baseUrl, "POST", "/api/devices/$deviceId/commands/$cmdId/result", deviceId, kp.private, resultJson.toString()).use { res ->
                assertEquals(200, res.code)
                assertEquals("COMPLETED", JSONObject(res.body!!.string()).getJSONObject("command").getString("status"))
            }
        }

        // 12. Step-up DEVICE_REVOKE -> permanent revocation -> Plane-2 rejected (403 DEVICE_REVOKED)
        postJson(
            client,
            "$baseUrl/api/auth/step-up",
            JSONObject()
                .put("actionScope", "DEVICE_REVOKE")
                .put("totpCode", computeTotpCode(totpSecretBase32)),
            csrfToken
        ).use { res ->
            assertEquals(200, res.code)
        }

        postJson(
            client,
            "$baseUrl/api/devices/$deviceId/revoke",
            JSONObject().put("reason", "ANDROID_E2E_VERIFICATION_COMPLETE"),
            csrfToken
        ).use { res ->
            assertEquals(200, res.code)
            assertEquals(
                "REVOKED",
                JSONObject(res.body!!.string()).getJSONObject("device").getString("lifecycleState")
            )
        }

        sendPlane2(client, baseUrl, "POST", "/api/devices/$deviceId/heartbeat", deviceId, kp.private, secondHb.toString()).use { res ->
            assertEquals(403, res.code)
            assertEquals("DEVICE_REVOKED", errorCode(res))
        }

        // 13. Verify PostgreSQL audit hash chain
        client.newCall(Request.Builder().url("$baseUrl/api/audit").get().build()).execute().use { res ->
            assertEquals(200, res.code)
            val doc = JSONObject(res.body!!.string())
            assertTrue(doc.getJSONObject("chainVerification").getBoolean("valid"))
        }
    }

    private fun postJson(client: OkHttpClient, url: String, body: JSONObject, csrf: String?): Response {
        val builder = Request.Builder()
            .url(url)
            .post(body.toString().toRequestBody(jsonMedia))
            .header("Accept", "application/json")
        if (!csrf.isNullOrBlank()) {
            builder.header("X-CSRF-Token", csrf)
        }
        return client.newCall(builder.build()).execute()
    }

    private fun sendPlane2(
        client: OkHttpClient,
        baseUrl: String,
        method: String,
        path: String,
        deviceId: String,
        privateKey: PrivateKey,
        bodyJson: String?,
        overrideTs: String? = null,
        overrideNonce: String? = null,
        tamperedWireBody: String? = null
    ): Response {
        val canonicalBody = DeviceRequestSigner.canonicalJson(bodyJson)
        val ts = overrideTs ?: DeviceRequestSigner.utcTimestampIso()
        val nonce = overrideNonce ?: DeviceRequestSigner.newNonce()
        val transcript = DeviceRequestSigner.buildDeviceAuthTranscript(
            method = method,
            path = path,
            deviceId = deviceId,
            timestampIso = ts,
            nonce = nonce,
            bodyJson = canonicalBody
        )
        val sig = DeviceRequestSigner.signEcdsaSha256(privateKey, transcript)
        val builder = Request.Builder()
            .url(baseUrl + path)
            .header("Accept", "application/json")
            .header("X-Vajra-Device-Id", deviceId)
            .header("X-Vajra-Timestamp", ts)
            .header("X-Vajra-Nonce", nonce)
            .header("X-Vajra-Signature", sig)

        if (method.uppercase() == "GET") {
            builder.get()
        } else {
            builder.post((tamperedWireBody ?: canonicalBody).toRequestBody(jsonMedia))
        }
        return client.newCall(builder.build()).execute()
    }

    private fun errorCode(res: Response): String =
        JSONObject(res.body!!.string()).getJSONObject("error").getString("code")

    private fun toPem(label: String, der: ByteArray): String {
        val b64 = Base64.getEncoder().encodeToString(der)
        val lines = b64.chunked(64).joinToString("\n")
        return "-----BEGIN $label-----\n$lines\n-----END $label-----\n"
    }

    private fun computeTotpCode(secretBase32: String): String {
        val keyBytes = base32Decode(secretBase32)
        val counter = Instant.now().epochSecond / 30L
        val counterBytes = ByteBuffer.allocate(8).putLong(counter).array()
        val mac = Mac.getInstance("HmacSHA1")
        mac.init(SecretKeySpec(keyBytes, "HmacSHA1"))
        val hash = mac.doFinal(counterBytes)
        val offset = hash[hash.size - 1].toInt() and 0x0F
        val binary = ((hash[offset].toInt() and 0x7F) shl 24) or
            ((hash[offset + 1].toInt() and 0xFF) shl 16) or
            ((hash[offset + 2].toInt() and 0xFF) shl 8) or
            (hash[offset + 3].toInt() and 0xFF)
        return "%06d".format(binary % 1_000_000)
    }

    private fun base32Decode(input: String): ByteArray {
        val alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
        val cleaned = input.trim().trimEnd('=').uppercase()
        val out = ArrayList<Byte>()
        var buffer = 0
        var bitsLeft = 0
        for (ch in cleaned) {
            val idx = alphabet.indexOf(ch)
            if (idx < 0) continue
            buffer = (buffer shl 5) or idx
            bitsLeft += 5
            if (bitsLeft >= 8) {
                bitsLeft -= 8
                out.add(((buffer shr bitsLeft) and 0xFF).toByte())
            }
        }
        return out.toByteArray()
    }
}
