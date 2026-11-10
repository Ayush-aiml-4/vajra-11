package com.vajra.companion.ui

import android.Manifest
import android.annotation.SuppressLint
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.SurfaceTexture
import android.hardware.camera2.CameraCaptureSession
import android.hardware.camera2.CameraCharacteristics
import android.hardware.camera2.CameraDevice
import android.hardware.camera2.CameraManager
import android.hardware.camera2.CaptureRequest
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.HandlerThread
import android.view.Surface
import android.view.TextureView
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.RelativeLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.vajra.companion.BuildConfig
import com.vajra.companion.R
import com.vajra.companion.crypto.DeviceRequestSigner
import com.vajra.companion.identity.AndroidKeystoreIdentity
import com.vajra.companion.network.VajraApiClient
import com.vajra.companion.work.CommandPollWorker
import com.vajra.companion.work.HeartbeatWorker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit

class EnrollmentActivity : AppCompatActivity() {

    data class ParsedPairingBundle(
        val serverUrl: String?,
        val enrollmentToken: String,
        val deviceId: String,
        val challengeNonce: String
    )

    private var activeBundle: ParsedPairingBundle? = null
    private var isPollingApproval = false

    // Camera2 in-app viewfinder and frame decoder resources
    private var cameraDevice: CameraDevice? = null
    private var captureSession: CameraCaptureSession? = null
    private var imageReader: android.media.ImageReader? = null
    private var backgroundThread: HandlerThread? = null
    private var backgroundHandler: Handler? = null
    private val isQrProcessed = java.util.concurrent.atomic.AtomicBoolean(false)
    private val qrDecoder = com.vajra.companion.qr.QrCodeFrameDecoder()

    private val barcodeScanLauncher =
        registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { res ->
            if (res.resultCode == RESULT_OK && res.data != null) {
                val contents = res.data?.getStringExtra("SCAN_RESULT")
                if (!contents.isNullOrBlank()) {
                    val parsed = parsePairingBundleJson(contents)
                    if (parsed != null) {
                        onBundleReadyCallback?.invoke(parsed)
                    } else {
                        findViewById<TextView>(R.id.txtEnrollResult)?.text = getString(R.string.bundle_invalid)
                    }
                }
            }
        }

    private val requestCameraPermissionLauncher =
        registerForActivityResult(ActivityResultContracts.RequestPermission()) { isGranted ->
            val layoutDenied = findViewById<LinearLayout>(R.id.layoutCameraDenied)
            if (isGranted) {
                layoutDenied?.visibility = View.GONE
                startInAppCameraScanner()
            } else {
                layoutDenied?.visibility = View.VISIBLE
                findViewById<TextView>(R.id.txtEnrollResult)?.text =
                    getString(R.string.camera_denied_desc)
                findViewById<LinearLayout>(R.id.layoutManualFields)?.visibility = View.VISIBLE
            }
        }

    private var onBundleReadyCallback: ((ParsedPairingBundle) -> Unit)? = null

    private fun startInAppCameraScanner() {
        val layoutCameraContainer = findViewById<RelativeLayout>(R.id.layoutCameraContainer)
        val textureView = findViewById<TextureView>(R.id.viewfinderTexture)

        isQrProcessed.set(false)
        layoutCameraContainer?.visibility = View.VISIBLE

        if (textureView != null) {
            if (textureView.isAvailable) {
                openCamera(textureView.surfaceTexture!!)
            } else {
                textureView.surfaceTextureListener = object : TextureView.SurfaceTextureListener {
                    override fun onSurfaceTextureAvailable(surface: SurfaceTexture, width: Int, height: Int) {
                        openCamera(surface)
                    }
                    override fun onSurfaceTextureSizeChanged(surface: SurfaceTexture, width: Int, height: Int) {}
                    override fun onSurfaceTextureDestroyed(surface: SurfaceTexture): Boolean {
                        closeCamera()
                        return true
                    }
                    override fun onSurfaceTextureUpdated(surface: SurfaceTexture) {}
                }
            }
        }
    }

    @SuppressLint("MissingPermission")
    private fun openCamera(surfaceTexture: SurfaceTexture) {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) {
            return
        }

        startBackgroundThread()
        val manager = getSystemService(Context.CAMERA_SERVICE) as CameraManager
        try {
            val cameraId = manager.cameraIdList.firstOrNull { id ->
                val chars = manager.getCameraCharacteristics(id)
                chars.get(CameraCharacteristics.LENS_FACING) == CameraCharacteristics.LENS_FACING_BACK
            } ?: manager.cameraIdList.firstOrNull() ?: return

            val characteristics = manager.getCameraCharacteristics(cameraId)
            val streamMap = characteristics.get(CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP)
            val sensorOrientation = characteristics.get(CameraCharacteristics.SENSOR_ORIENTATION) ?: 90

            // Select optimal YUV_420_888 resolution for QR analysis (approx 1280x720 or 640x480)
            val yuvSizes = streamMap?.getOutputSizes(android.graphics.ImageFormat.YUV_420_888) ?: emptyArray()
            val analysisSize = yuvSizes.firstOrNull { it.width <= 1280 && it.height <= 720 && it.width >= 640 }
                ?: yuvSizes.firstOrNull { it.width <= 1920 && it.height <= 1080 }
                ?: android.util.Size(640, 480)

            imageReader?.close()
            val reader = android.media.ImageReader.newInstance(
                analysisSize.width,
                analysisSize.height,
                android.graphics.ImageFormat.YUV_420_888,
                2
            )
            imageReader = reader

            reader.setOnImageAvailableListener({ ir ->
                val image = ir.acquireLatestImage() ?: return@setOnImageAvailableListener
                try {
                    if (isQrProcessed.get()) {
                        return@setOnImageAvailableListener
                    }

                    val decodedText = qrDecoder.decodeImage(image, sensorOrientation)
                    if (!decodedText.isNullOrBlank()) {
                        if (isQrProcessed.compareAndSet(false, true)) {
                            runOnUiThread {
                                val parsed = parsePairingBundleJson(decodedText)
                                if (parsed != null) {
                                    onBundleReadyCallback?.invoke(parsed)
                                } else {
                                    // Malformed or invalid payload: allow re-scan after notifying
                                    isQrProcessed.set(false)
                                    findViewById<TextView>(R.id.txtEnrollResult)?.text =
                                        getString(R.string.bundle_invalid)
                                }
                            }
                        }
                    }
                } catch (_: Exception) {
                    // Ignore transient per-frame decode errors
                } finally {
                    image.close()
                }
            }, backgroundHandler)

            manager.openCamera(cameraId, object : CameraDevice.StateCallback() {
                override fun onOpened(camera: CameraDevice) {
                    cameraDevice = camera
                    startCameraPreview(camera, surfaceTexture)
                }

                override fun onDisconnected(camera: CameraDevice) {
                    closeCamera()
                }

                override fun onError(camera: CameraDevice, error: Int) {
                    closeCamera()
                }
            }, backgroundHandler)
        } catch (_: Exception) {
            // Camera hardware open exception handled gracefully
        }
    }

    private fun startCameraPreview(camera: CameraDevice, surfaceTexture: SurfaceTexture) {
        try {
            val previewSurface = Surface(surfaceTexture)
            val readerSurface = imageReader?.surface
            val surfaces = listOfNotNull(previewSurface, readerSurface)

            val previewRequestBuilder = camera.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply {
                addTarget(previewSurface)
                if (readerSurface != null) {
                    addTarget(readerSurface)
                }
                set(
                    CaptureRequest.CONTROL_AF_MODE,
                    CaptureRequest.CONTROL_AF_MODE_CONTINUOUS_PICTURE
                )
            }

            @Suppress("DEPRECATION")
            camera.createCaptureSession(surfaces, object : CameraCaptureSession.StateCallback() {
                override fun onConfigured(session: CameraCaptureSession) {
                    if (cameraDevice == null) return
                    captureSession = session
                    try {
                        session.setRepeatingRequest(previewRequestBuilder.build(), null, backgroundHandler)
                    } catch (_: Exception) {
                        // ignore session error
                    }
                }

                override fun onConfigureFailed(session: CameraCaptureSession) {}
            }, backgroundHandler)
        } catch (_: Exception) {
            // ignore preview setup error
        }
    }

    private fun closeCamera() {
        try {
            captureSession?.stopRepeating()
        } catch (_: Exception) {}
        try {
            captureSession?.close()
            captureSession = null
        } catch (_: Exception) {}

        try {
            imageReader?.close()
            imageReader = null
        } catch (_: Exception) {}

        try {
            cameraDevice?.close()
            cameraDevice = null
        } catch (_: Exception) {}

        stopBackgroundThread()
    }

    private fun startBackgroundThread() {
        if (backgroundThread == null) {
            backgroundThread = HandlerThread("VajraCameraBackground").apply { start() }
            backgroundHandler = Handler(backgroundThread!!.looper)
        }
    }

    private fun stopBackgroundThread() {
        backgroundThread?.quitSafely()
        try {
            backgroundThread?.join(500)
            backgroundThread = null
            backgroundHandler = null
        } catch (_: Exception) {
            // ignore
        }
    }

    companion object {
        fun parsePairingBundleJson(rawJson: String): ParsedPairingBundle? {
            return try {
                val obj = JSONObject(rawJson.trim())

                // Reject if protocol does not match VAJRA_ENROLL_V1
                val protocol = obj.optString("protocol").trim()
                if (protocol.isNotEmpty() && protocol != "VAJRA_ENROLL_V1") {
                    return null
                }

                val token = obj.optString("enrollmentToken").trim()
                    .ifEmpty { obj.optString("token").trim() }
                val deviceId = obj.optString("deviceId").trim()
                val challengeNonce = obj.optString("challengeNonce").trim()
                if (token.isEmpty() || deviceId.isEmpty() || challengeNonce.isEmpty()) {
                    return null
                }

                // Reject expired or malformed QR expiration payload
                val expiresAtStr = obj.optString("expiresAt").trim()
                if (expiresAtStr.isNotEmpty()) {
                    try {
                        val parsedEpoch = java.time.Instant.parse(expiresAtStr).toEpochMilli()
                        if (parsedEpoch <= System.currentTimeMillis()) {
                            return null // Expired QR payload
                        }
                    } catch (_: Exception) {
                        return null // Malformed expiration date
                    }
                }

                val rawOrigin = obj.optString("serverUrl").trim()
                    .ifEmpty { obj.optString("origin").trim() }
                    .ifEmpty { obj.optString("serverBaseUrl").trim() }
                    .ifEmpty { obj.optString("server").trim() }
                    .trimEnd('/')

                val origin = rawOrigin.takeIf { it.startsWith("http://") || it.startsWith("https://") }
                    ?: return null

                // Enforce HTTPS for non-loopback endpoints
                val isLoopback = origin.contains("10.0.2.2") ||
                    origin.contains("localhost") ||
                    origin.contains("127.0.0.1")
                if (!isLoopback && !origin.startsWith("https://")) {
                    return null
                }

                ParsedPairingBundle(
                    serverUrl = origin,
                    enrollmentToken = token,
                    deviceId = deviceId,
                    challengeNonce = challengeNonce
                )
            } catch (_: Exception) {
                null
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_enrollment)

        val prefs = getSharedPreferences("vajra_settings", MODE_PRIVATE)
        val defaultServer = prefs.getString("serverBaseUrl", getString(R.string.default_server_url))
            ?: getString(R.string.default_server_url)

        // Views
        val stepTab1 = findViewById<TextView>(R.id.stepTab1)
        val stepTab2 = findViewById<TextView>(R.id.stepTab2)
        val stepTab3 = findViewById<TextView>(R.id.stepTab3)
        val stepTab4 = findViewById<TextView>(R.id.stepTab4)

        val layoutStepScan = findViewById<LinearLayout>(R.id.layoutStepScan)
        val layoutStepPasscode = findViewById<LinearLayout>(R.id.layoutStepPasscode)
        val layoutStepAwaitingApproval = findViewById<LinearLayout>(R.id.layoutStepAwaitingApproval)
        val layoutStepConnected = findViewById<LinearLayout>(R.id.layoutStepConnected)
        val layoutManualFields = findViewById<LinearLayout>(R.id.layoutManualFields)
        val layoutCameraContainer = findViewById<RelativeLayout>(R.id.layoutCameraContainer)

        val btnScanQr = findViewById<Button>(R.id.btnScanQr)
        val btnRetryCamera = findViewById<Button>(R.id.btnRetryCamera)
        val btnPasteBundle = findViewById<Button>(R.id.btnPasteBundle)
        val btnToggleManual = findViewById<TextView>(R.id.btnToggleManual)
        val btnManualContinue = findViewById<Button>(R.id.btnManualContinue)

        val inputServerUrl = findViewById<EditText>(R.id.inputServerUrl)
        val inputToken = findViewById<EditText>(R.id.inputToken)
        val inputDeviceId = findViewById<EditText>(R.id.inputDeviceId)
        val inputChallenge = findViewById<EditText>(R.id.inputChallenge)

        val txtScannedTarget = findViewById<TextView>(R.id.txtScannedTarget)
        val inputPasscode = findViewById<EditText>(R.id.inputPasscode)
        val btnSubmitEnroll = findViewById<Button>(R.id.btnSubmitEnroll)
        val txtFingerprintSummary = findViewById<TextView>(R.id.txtFingerprintSummary)
        val progressAwaiting = findViewById<ProgressBar>(R.id.progressAwaiting)
        val txtAwaitingTitle = findViewById<TextView>(R.id.txtAwaitingTitle)
        val txtAwaitingDesc = findViewById<TextView>(R.id.txtAwaitingDesc)
        val btnRestartPairing = findViewById<Button>(R.id.btnRestartPairing)
        val btnDone = findViewById<Button>(R.id.btnDone)
        val result = findViewById<TextView>(R.id.txtEnrollResult)

        inputServerUrl.setText(defaultServer)

        fun updateStepVisuals(step: Int) {
            stepTab1.setTextColor(if (step >= 1) 0xFFC8A66A.toInt() else 0xFF646A74.toInt())
            stepTab2.setTextColor(if (step >= 2) 0xFFC8A66A.toInt() else 0xFF646A74.toInt())
            stepTab3.setTextColor(if (step >= 3) 0xFFC8A66A.toInt() else 0xFF646A74.toInt())
            stepTab4.setTextColor(if (step >= 4) 0xFF75B798.toInt() else 0xFF646A74.toInt())

            if (step == 3) {
                progressAwaiting?.visibility = View.VISIBLE
                txtAwaitingTitle?.text = getString(R.string.step_awaiting_title)
                txtAwaitingDesc?.text = getString(R.string.step_awaiting_desc)
                btnRestartPairing?.visibility = View.GONE
            }

            layoutStepScan.visibility = if (step == 1) View.VISIBLE else View.GONE
            layoutStepPasscode.visibility = if (step == 2) View.VISIBLE else View.GONE
            layoutStepAwaitingApproval.visibility = if (step == 3) View.VISIBLE else View.GONE
            layoutStepConnected.visibility = if (step == 4) View.VISIBLE else View.GONE
        }

        btnRestartPairing?.setOnClickListener {
            isPollingApproval = false
            activeBundle = null
            result.text = ""
            updateStepVisuals(1)
        }

        fun onBundleReady(bundle: ParsedPairingBundle) {
            closeCamera()
            layoutCameraContainer?.visibility = View.GONE
            activeBundle = bundle
            val targetUrl = bundle.serverUrl ?: defaultServer
            prefs.edit().putString("serverBaseUrl", targetUrl).apply()

            txtScannedTarget.text = "Target Device: ${bundle.deviceId.take(8)}... · Server: $targetUrl"
            result.text = ""
            updateStepVisuals(2)
            inputPasscode.requestFocus()
        }
        onBundleReadyCallback = ::onBundleReady

        btnToggleManual.setOnClickListener {
            layoutManualFields.visibility = if (layoutManualFields.visibility == View.VISIBLE) {
                View.GONE
            } else {
                View.VISIBLE
            }
        }

        btnPasteBundle.setOnClickListener {
            val clipboard = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
            val clipText = clipboard?.primaryClip?.getItemAt(0)?.coerceToText(this)?.toString()?.trim().orEmpty()
            if (clipText.isEmpty()) {
                result.text = getString(R.string.bundle_empty_clipboard)
                return@setOnClickListener
            }
            val parsed = parsePairingBundleJson(clipText)
            if (parsed == null) {
                result.text = getString(R.string.bundle_invalid)
                return@setOnClickListener
            }
            onBundleReady(parsed)
        }

        btnScanQr.setOnClickListener {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED) {
                startInAppCameraScanner()
            } else {
                requestCameraPermissionLauncher.launch(Manifest.permission.CAMERA)
            }
        }

        btnRetryCamera?.setOnClickListener {
            requestCameraPermissionLauncher.launch(Manifest.permission.CAMERA)
        }

        btnManualContinue.setOnClickListener {
            val configuredUrl = inputServerUrl.text.toString().trim().trimEnd('/')
            val t = inputToken.text.toString().trim()
            val d = inputDeviceId.text.toString().trim()
            val c = inputChallenge.text.toString().trim()

            if (t.isEmpty() || d.isEmpty() || c.isEmpty()) {
                result.text = getString(R.string.enroll_fields_required)
                return@setOnClickListener
            }

            val bundle = ParsedPairingBundle(
                serverUrl = configuredUrl.ifBlank { defaultServer },
                enrollmentToken = t,
                deviceId = d,
                challengeNonce = c
            )
            onBundleReady(bundle)
        }

        btnSubmitEnroll.setOnClickListener {
            val bundle = activeBundle
            if (bundle == null) {
                result.text = "Pairing challenge missing. Please scan QR code first."
                updateStepVisuals(1)
                return@setOnClickListener
            }

            val passcode = inputPasscode.text.toString().replace("\\s+".toRegex(), "").trim()
            if (passcode.length < 6) {
                result.text = "Please enter the full 6-digit verification passcode shown on screen."
                return@setOnClickListener
            }

            val targetServer = bundle.serverUrl ?: defaultServer
            btnSubmitEnroll.isEnabled = false
            result.text = getString(R.string.enroll_submitting)

            lifecycleScope.launch {
                val outcome = withContext(Dispatchers.IO) {
                    executeEnrollmentSubmission(targetServer, bundle, passcode)
                }

                btnSubmitEnroll.isEnabled = true
                if (outcome.success) {
                    result.text = ""
                    txtFingerprintSummary.text = "Key fingerprint: ${outcome.fingerprint?.take(18)}..."
                    updateStepVisuals(3)
                    startPollingApproval(targetServer, bundle.deviceId) {
                        updateStepVisuals(4)
                        lifecycleScope.launch {
                            delay(2000)
                            if (!isFinishing && !isDestroyed) {
                                val intent = Intent(this@EnrollmentActivity, MainActivity::class.java).apply {
                                    flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_NEW_TASK
                                }
                                startActivity(intent)
                                finish()
                            }
                        }
                    }
                } else {
                    result.text = outcome.errorMessage ?: "Enrollment submission failed."
                }
            }
        }

        btnDone.setOnClickListener {
            val intent = Intent(this, MainActivity::class.java).apply {
                flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_NEW_TASK
            }
            startActivity(intent)
            finish()
        }
    }

    override fun onPause() {
        super.onPause()
        closeCamera()
    }

    override fun onDestroy() {
        super.onDestroy()
        closeCamera()
    }

    private data class EnrollmentOutcome(
        val success: Boolean,
        val fingerprint: String? = null,
        val errorMessage: String? = null
    )

    private fun executeEnrollmentSubmission(
        baseUrl: String,
        bundle: ParsedPairingBundle,
        passcode: String
    ): EnrollmentOutcome {
        return try {
            val identity = AndroidKeystoreIdentity(this)
            val pub = identity.rotateKey()

            val timestamp = DeviceRequestSigner.utcTimestampIso()
            val clientNonce = DeviceRequestSigner.newNonce()
            val transcript = DeviceRequestSigner.buildEnrollmentTranscript(
                bundle.deviceId, bundle.enrollmentToken, bundle.challengeNonce, pub.fingerprint, timestamp, clientNonce
            )
            val signature = DeviceRequestSigner.signEcdsaSha256(identity.getPrivateKey(), transcript)

            val deviceModel = "${Build.MANUFACTURER} ${Build.MODEL}".trim()
            val osVersion = "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})"
            val agentVersion = BuildConfig.VERSION_NAME

            val body = JSONObject()
                .put("enrollmentToken", bundle.enrollmentToken)
                .put("verificationPasscode", passcode)
                .put("publicKeyPem", pub.publicKeyPem)
                .put("keyAlgorithm", "ECDSA_P256")
                .put("signatureBase64", signature)
                .put("timestampIso", timestamp)
                .put("clientNonce", clientNonce)
                .put("deviceName", deviceModel)
                .put("osVersion", osVersion)
                .put("agentVersion", agentVersion)
                .put("hardwareBacked", pub.hardwareBacked)

            val api = VajraApiClient(identity) { baseUrl }
            api.enrollmentSubmit(body).use { res ->
                val respStr = res.body?.string().orEmpty()
                if (!res.isSuccessful) {
                    val errMsg = try {
                        val errObj = JSONObject(respStr)
                        errObj.optJSONObject("error")?.optString("message") ?: "HTTP ${res.code}"
                    } catch (_: Exception) {
                        "HTTP ${res.code}"
                    }
                    return EnrollmentOutcome(success = false, errorMessage = errMsg)
                }

                identity.saveMeta(bundle.deviceId, baseUrl, "ENROLLMENT_PENDING")
                HeartbeatWorker.schedule(this)
                CommandPollWorker.schedule(this)

                EnrollmentOutcome(success = true, fingerprint = pub.fingerprint)
            }
        } catch (e: Exception) {
            EnrollmentOutcome(success = false, errorMessage = e.message ?: e.javaClass.simpleName)
        }
    }

    private fun startPollingApproval(
        baseUrl: String,
        deviceId: String,
        onConnected: () -> Unit
    ) {
        if (isPollingApproval) return
        isPollingApproval = true

        val progressAwaiting = findViewById<ProgressBar>(R.id.progressAwaiting)
        val txtAwaitingTitle = findViewById<TextView>(R.id.txtAwaitingTitle)
        val txtAwaitingDesc = findViewById<TextView>(R.id.txtAwaitingDesc)
        val btnRestartPairing = findViewById<Button>(R.id.btnRestartPairing)

        val client = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(10, TimeUnit.SECONDS)
            .build()

        lifecycleScope.launch(Dispatchers.IO) {
            val url = "${baseUrl.trimEnd('/')}/api/devices/$deviceId/enrollment/status"
            var attempts = 0
            var consecutiveNetworkErrors = 0
            while (isActive && attempts < 120) { // Poll for up to 5 minutes
                delay(2500)
                attempts++
                try {
                    val req = Request.Builder()
                        .url(url)
                        .header("Accept", "application/json")
                        .build()

                    client.newCall(req).execute().use { res ->
                        consecutiveNetworkErrors = 0
                        if (res.isSuccessful) {
                            val json = JSONObject(res.body?.string().orEmpty())
                            val status = json.optString("status")
                            val lifecycleState = json.optString("lifecycleState")
                            if (status == "CONNECTED" || lifecycleState == "TRUSTED") {
                                val resolvedState = if (lifecycleState.isNotBlank()) lifecycleState else "TRUSTED"
                                val identity = AndroidKeystoreIdentity(this@EnrollmentActivity)
                                identity.saveMeta(deviceId, baseUrl, resolvedState)

                                // Enqueue immediate one-time heartbeat & command sync
                                HeartbeatWorker.enqueueImmediate(this@EnrollmentActivity)
                                CommandPollWorker.enqueueImmediate(this@EnrollmentActivity)
                                HeartbeatWorker.schedule(this@EnrollmentActivity)
                                CommandPollWorker.schedule(this@EnrollmentActivity)

                                withContext(Dispatchers.Main) {
                                    isPollingApproval = false
                                    onConnected()
                                }
                                return@launch
                            } else if (status == "REVOKED" || lifecycleState == "REVOKED" || status == "REJECTED") {
                                withContext(Dispatchers.Main) {
                                    isPollingApproval = false
                                    progressAwaiting?.visibility = View.GONE
                                    txtAwaitingTitle?.text = getString(R.string.step_rejected_title)
                                    txtAwaitingDesc?.text = getString(R.string.step_rejected_desc)
                                    btnRestartPairing?.visibility = View.VISIBLE
                                }
                                return@launch
                            }
                        } else if (res.code == 410) {
                            withContext(Dispatchers.Main) {
                                isPollingApproval = false
                                progressAwaiting?.visibility = View.GONE
                                txtAwaitingTitle?.text = getString(R.string.step_expired_title)
                                txtAwaitingDesc?.text = getString(R.string.step_expired_desc)
                                btnRestartPairing?.visibility = View.VISIBLE
                            }
                            return@launch
                        }
                    }
                } catch (_: Exception) {
                    consecutiveNetworkErrors++
                    if (consecutiveNetworkErrors >= 3) {
                        withContext(Dispatchers.Main) {
                            txtAwaitingDesc?.text = "Connecting to server (attempt $attempts)... Please ensure the server is reachable."
                        }
                    }
                }
            }
            if (isActive) {
                withContext(Dispatchers.Main) {
                    isPollingApproval = false
                    progressAwaiting?.visibility = View.GONE
                    txtAwaitingTitle?.text = "Approval Pending Timeout"
                    txtAwaitingDesc?.text = "Authorization request timed out. Please check the VAJRA console and tap Restart Pairing."
                    btnRestartPairing?.visibility = View.VISIBLE
                }
            }
        }
    }
}
