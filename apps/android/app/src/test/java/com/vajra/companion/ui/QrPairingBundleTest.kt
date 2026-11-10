package com.vajra.companion.ui

import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import com.vajra.companion.qr.QrCodeFrameDecoder
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import java.nio.ByteBuffer
import java.time.Instant

/**
 * Focused unit tests for:
 * 1. QR pairing bundle JSON validation and rejection of malformed or expired payloads.
 * 2. ZXing luminance extraction, rowStride/pixelStride handling, rotation, and decoding.
 */
class QrPairingBundleTest {

    @Test
    fun parsePairingBundle_acceptsValidPayload() {
        val futureExpiry = Instant.now().plusSeconds(600).toString()
        val json = JSONObject()
            .put("protocol", "VAJRA_ENROLL_V1")
            .put("serverUrl", "https://vajra.security.example.com")
            .put("deviceId", "dev-uuid-12345678-abcd")
            .put("enrollmentToken", "tok_valid_test_token_1234567890")
            .put("challengeNonce", "nonce_abc1234567890def")
            .put("expiresAt", futureExpiry)
            .toString()

        val parsed = EnrollmentActivity.parsePairingBundleJson(json)
        assertNotNull(parsed)
        assertEquals("https://vajra.security.example.com", parsed?.serverUrl)
        assertEquals("dev-uuid-12345678-abcd", parsed?.deviceId)
        assertEquals("tok_valid_test_token_1234567890", parsed?.enrollmentToken)
        assertEquals("nonce_abc1234567890def", parsed?.challengeNonce)
    }

    @Test
    fun parsePairingBundle_acceptsLoopbackHttp() {
        val loopbacks = listOf(
            "http://10.0.2.2:3000",
            "http://127.0.0.1:3000",
            "http://localhost:3000"
        )
        for (url in loopbacks) {
            val json = JSONObject()
                .put("protocol", "VAJRA_ENROLL_V1")
                .put("serverUrl", url)
                .put("deviceId", "dev-1")
                .put("enrollmentToken", "tok-1")
                .put("challengeNonce", "nonce-1")
                .toString()

            val parsed = EnrollmentActivity.parsePairingBundleJson(json)
            assertNotNull("Loopback URL $url must be accepted in debug/local mode", parsed)
            assertEquals(url, parsed?.serverUrl)
        }
    }

    @Test
    fun parsePairingBundle_rejectsExpiredPayload() {
        val pastExpiry = Instant.now().minusSeconds(60).toString()
        val json = JSONObject()
            .put("protocol", "VAJRA_ENROLL_V1")
            .put("serverUrl", "https://vajra.example.com")
            .put("deviceId", "dev-1")
            .put("enrollmentToken", "tok-1")
            .put("challengeNonce", "nonce-1")
            .put("expiresAt", pastExpiry)
            .toString()

        val parsed = EnrollmentActivity.parsePairingBundleJson(json)
        assertNull("Expired QR payload must be rejected", parsed)
    }

    @Test
    fun parsePairingBundle_rejectsMalformedExpiryDate() {
        val json = JSONObject()
            .put("protocol", "VAJRA_ENROLL_V1")
            .put("serverUrl", "https://vajra.example.com")
            .put("deviceId", "dev-1")
            .put("enrollmentToken", "tok-1")
            .put("challengeNonce", "nonce-1")
            .put("expiresAt", "not-a-valid-iso-date-string")
            .toString()

        val parsed = EnrollmentActivity.parsePairingBundleJson(json)
        assertNull("Malformed expiresAt must be rejected", parsed)
    }

    @Test
    fun parsePairingBundle_rejectsUnencryptedRemoteHttp() {
        val json = JSONObject()
            .put("protocol", "VAJRA_ENROLL_V1")
            .put("serverUrl", "http://remote.untrusted.com") // Remote HTTP without HTTPS
            .put("deviceId", "dev-1")
            .put("enrollmentToken", "tok-1")
            .put("challengeNonce", "nonce-1")
            .toString()

        val parsed = EnrollmentActivity.parsePairingBundleJson(json)
        assertNull("Remote plain HTTP URL must be rejected", parsed)
    }

    @Test
    fun parsePairingBundle_rejectsMismatchedProtocol() {
        val json = JSONObject()
            .put("protocol", "MALICIOUS_PROTOCOL_V99")
            .put("serverUrl", "https://vajra.example.com")
            .put("deviceId", "dev-1")
            .put("enrollmentToken", "tok-1")
            .put("challengeNonce", "nonce-1")
            .toString()

        val parsed = EnrollmentActivity.parsePairingBundleJson(json)
        assertNull("Non-VAJRA_ENROLL_V1 protocol must be rejected", parsed)
    }

    @Test
    fun parsePairingBundle_rejectsMissingFields() {
        val missingToken = JSONObject()
            .put("protocol", "VAJRA_ENROLL_V1")
            .put("serverUrl", "https://vajra.example.com")
            .put("deviceId", "dev-1")
            .put("challengeNonce", "nonce-1")
            .toString()
        assertNull(EnrollmentActivity.parsePairingBundleJson(missingToken))

        val missingDevice = JSONObject()
            .put("protocol", "VAJRA_ENROLL_V1")
            .put("serverUrl", "https://vajra.example.com")
            .put("enrollmentToken", "tok-1")
            .put("challengeNonce", "nonce-1")
            .toString()
        assertNull(EnrollmentActivity.parsePairingBundleJson(missingDevice))

        val missingNonce = JSONObject()
            .put("protocol", "VAJRA_ENROLL_V1")
            .put("serverUrl", "https://vajra.example.com")
            .put("deviceId", "dev-1")
            .put("enrollmentToken", "tok-1")
            .toString()
        assertNull(EnrollmentActivity.parsePairingBundleJson(missingNonce))
    }

    @Test
    fun parsePairingBundle_rejectsCorruptedString() {
        assertNull(EnrollmentActivity.parsePairingBundleJson("not-even-json"))
        assertNull(EnrollmentActivity.parsePairingBundleJson("{ broken: json {"))
        assertNull(EnrollmentActivity.parsePairingBundleJson(""))
    }

    @Test
    fun qrCodeFrameDecoder_extractsLuminanceWithRowAndPixelStride() {
        val width = 4
        val height = 3
        val rowStride = 8 // rowStride > width
        val pixelStride = 2 // pixelStride > 1

        val buffer = ByteBuffer.allocate(rowStride * height)
        // Fill buffer: row 0 has values at col*2, etc.
        for (r in 0 until height) {
            for (c in 0 until width) {
                buffer.put(r * rowStride + c * pixelStride, (r * 10 + c).toByte())
            }
        }

        val extracted = QrCodeFrameDecoder.extractLuminance(buffer, width, height, rowStride, pixelStride)
        assertEquals(width * height, extracted.size)
        // Verify extracted values match (r * 10 + c)
        for (r in 0 until height) {
            for (c in 0 until width) {
                assertEquals((r * 10 + c).toByte(), extracted[r * width + c])
            }
        }
    }

    @Test
    fun qrCodeFrameDecoder_decodesGeneratedQrCodeWithRotation() {
        val expectedPayload = JSONObject()
            .put("protocol", "VAJRA_ENROLL_V1")
            .put("serverUrl", "https://demo.vajra.dev")
            .put("deviceId", "550e8400-e29b-41d4-a716-446655440000")
            .put("enrollmentToken", "token_999888777666")
            .put("challengeNonce", "nonce_111222333444")
            .put("expiresAt", Instant.now().plusSeconds(300).toString())
            .toString()

        // Generate synthetic QR BitMatrix using ZXing
        val qrWriter = QRCodeWriter()
        val bitMatrix = qrWriter.encode(expectedPayload, BarcodeFormat.QR_CODE, 200, 200)
        val width = bitMatrix.width
        val height = bitMatrix.height

        // Convert BitMatrix to Y luminance array (black = 0, white = 255)
        val yData = ByteArray(width * height)
        for (y in 0 until height) {
            for (x in 0 until width) {
                yData[y * width + x] = if (bitMatrix.get(x, y)) 0.toByte() else 255.toByte()
            }
        }

        val decoder = QrCodeFrameDecoder()

        // Test unrotated decoding
        val decoded0 = decoder.decodeLuminance(yData, width, height, 0)
        assertNotNull("Unrotated QR code must be decoded", decoded0)
        val parsed0 = EnrollmentActivity.parsePairingBundleJson(decoded0!!)
        assertNotNull(parsed0)
        assertEquals("550e8400-e29b-41d4-a716-446655440000", parsed0?.deviceId)

        // Test 90-degree sensor orientation decoding
        val decoded90 = decoder.decodeLuminance(yData, width, height, 90)
        assertNotNull("90-degree oriented QR code must be decoded", decoded90)
        val parsed90 = EnrollmentActivity.parsePairingBundleJson(decoded90!!)
        assertNotNull(parsed90)
        assertEquals("token_999888777666", parsed90?.enrollmentToken)
    }
}
