package com.vajra.companion.crypto

import android.os.BatteryManager
import com.vajra.companion.commands.CommandCapabilityMatrix
import com.vajra.companion.work.HeartbeatWorker
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

class DeviceRequestSignerTest {

    @Test
    fun bodyHash_emptyUsesObjectLiteral() {
        val a = DeviceRequestSigner.bodySha256Hex(null)
        val b = DeviceRequestSigner.bodySha256Hex("{}")
        assertEquals(a, b)
        assertEquals(64, a.length)
        assertEquals(
            "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a",
            a
        )
    }

    @Test
    fun deviceAuthTranscript_matchesServerOrder() {
        val t = DeviceRequestSigner.buildDeviceAuthTranscript(
            method = "post",
            path = "/api/devices/abc/heartbeat",
            deviceId = "abc",
            timestampIso = "2026-01-01T00:00:00.000Z",
            nonce = "n".repeat(32),
            bodyJson = """{"connectivityStatus":"ONLINE"}"""
        )
        assertTrue(t.startsWith("VAJRA-DEVICE-AUTH-V1|POST|/api/devices/abc/heartbeat|abc|"))
        assertTrue(t.contains("|${"n".repeat(32)}|"))
        val parts = t.split("|")
        assertEquals(7, parts.size)
    }

    @Test
    fun enrollmentTranscript_uppercasesToken() {
        val t = DeviceRequestSigner.buildEnrollmentTranscript(
            deviceId = "dev-1",
            enrollmentToken = "ab12cd",
            challengeNonce = "challenge",
            publicKeyFingerprint = "sha256:deadbeef",
            timestampIso = "2026-01-01T00:00:00.000Z",
            clientNonce = "clientnoncevalue12"
        )
        assertTrue(t.startsWith("VAJRA-ENROLL-V1|dev-1|AB12CD|challenge|"))
    }

    @Test
    fun canonicalJson_sortsKeys() {
        val h1 = DeviceRequestSigner.bodySha256Hex("""{"b":1,"a":2}""")
        val h2 = DeviceRequestSigner.bodySha256Hex("""{"a":2,"b":1}""")
        assertEquals(h1, h2)
        assertEquals(64, h1.length)
        val canonA = DeviceRequestSigner.canonicalJson("""{"b":1,"a":2}""")
        val canonB = DeviceRequestSigner.canonicalJson("""{"a":2,"b":1}""")
        assertEquals(canonA, canonB)
        assertEquals("""{"a":2,"b":1}""", canonA)
    }

    @Test
    fun signEcdsaSha256_producesRfc3279DerSignature() {
        val kpg = KeyPairGenerator.getInstance("EC")
        kpg.initialize(ECGenParameterSpec("secp256r1"))
        val kp = kpg.generateKeyPair()

        val transcript = DeviceRequestSigner.buildDeviceAuthTranscript(
            method = "POST",
            path = "/api/devices/dev-123/heartbeat",
            deviceId = "dev-123",
            timestampIso = DeviceRequestSigner.utcTimestampIso(),
            nonce = DeviceRequestSigner.newNonce(),
            bodyJson = """{"connectivityStatus":"ONLINE","batteryLevel":82,"charging":true}"""
        )
        val sigBase64 = DeviceRequestSigner.signEcdsaSha256(kp.private, transcript)
        val sigBytes = Base64.getDecoder().decode(sigBase64)
        assertEquals(0x30.toByte(), sigBytes[0])

        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(kp.public)
        verifier.update(transcript.toByteArray(Charsets.UTF_8))
        assertTrue(verifier.verify(sigBytes))
    }

    @Test
    fun heartbeatPayload_roundsBatteryAndOmitsUnknownCharging() {
        // 2/3 = 66.666% -> rounds to 67%
        val chargingPayload = HeartbeatWorker.buildHeartbeatPayload(
            osRelease = "14",
            level = 2,
            scale = 3,
            status = BatteryManager.BATTERY_STATUS_CHARGING,
            hasBatteryIntent = true
        )
        assertEquals(67, chargingPayload.getInt("batteryLevel"))
        assertEquals(true, chargingPayload.getBoolean("charging"))
        assertEquals("ANDROID", chargingPayload.getString("platform"))

        // Discharging reports charging = false
        val dischargingPayload = HeartbeatWorker.buildHeartbeatPayload(
            osRelease = "14",
            level = 64,
            scale = 100,
            status = BatteryManager.BATTERY_STATUS_DISCHARGING,
            hasBatteryIntent = true
        )
        assertEquals(64, dischargingPayload.getInt("batteryLevel"))
        assertEquals(false, dischargingPayload.getBoolean("charging"))

        // Missing sticky battery intent must omit BOTH batteryLevel and charging (never false)
        val missingIntentPayload = HeartbeatWorker.buildHeartbeatPayload(
            osRelease = "14",
            level = -1,
            scale = -1,
            status = -1,
            hasBatteryIntent = false
        )
        assertFalse(missingIntentPayload.has("batteryLevel"))
        assertFalse(missingIntentPayload.has("charging"))

        // BATTERY_STATUS_UNKNOWN must omit charging while preserving valid batteryLevel
        val unknownStatusPayload = HeartbeatWorker.buildHeartbeatPayload(
            osRelease = "14",
            level = 55,
            scale = 100,
            status = BatteryManager.BATTERY_STATUS_UNKNOWN,
            hasBatteryIntent = true
        )
        assertEquals(55, unknownStatusPayload.getInt("batteryLevel"))
        assertFalse(unknownStatusPayload.has("charging"))
    }

    @Test
    fun commandMatrix_statusAndRingExecutable_locationAndUnknownNot() {
        assertTrue(CommandCapabilityMatrix.isExecutableOnAndroid(CommandCapabilityMatrix.REQUEST_DEVICE_STATUS))
        assertTrue(CommandCapabilityMatrix.isExecutableOnAndroid(CommandCapabilityMatrix.RING_DEVICE))
        assertFalse(CommandCapabilityMatrix.isExecutableOnAndroid(CommandCapabilityMatrix.REQUEST_LOCATION))
        assertFalse(CommandCapabilityMatrix.isExecutableOnAndroid(CommandCapabilityMatrix.ENABLE_LOST_MODE))
        assertFalse(CommandCapabilityMatrix.isKnown("RUN_SHELL"))
    }

    @Test
    fun pairingBundle_parsesConsoleJsonAndRejectsIncomplete() {
        val parsed = com.vajra.companion.ui.EnrollmentActivity.parsePairingBundleJson(
            """
            {
              "version": 1,
              "origin": "https://guard.vajra.example/",
              "deviceId": "dev-android-99",
              "enrollmentToken": "VJR-TOKEN-99",
              "challengeNonce": "abcdef0123456789"
            }
            """.trimIndent()
        )
        org.junit.Assert.assertNotNull(parsed)
        assertEquals("https://guard.vajra.example", parsed!!.serverUrl)
        assertEquals("VJR-TOKEN-99", parsed.enrollmentToken)
        assertEquals("dev-android-99", parsed.deviceId)
        assertEquals("abcdef0123456789", parsed.challengeNonce)

        val missing = com.vajra.companion.ui.EnrollmentActivity.parsePairingBundleJson("""{"deviceId":"only"}""")
        org.junit.Assert.assertNull(missing)
    }
}
