package com.vajra.companion.ui

import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.vajra.companion.R
import com.vajra.companion.identity.AndroidKeystoreIdentity
import com.vajra.companion.work.CommandPollWorker
import com.vajra.companion.work.HeartbeatWorker
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.text.DateFormat
import java.util.Date
import java.util.concurrent.TimeUnit

class MainActivity : AppCompatActivity() {

    private lateinit var identity: AndroidKeystoreIdentity

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        identity = AndroidKeystoreIdentity(this)

        // Onboarding actions
        findViewById<Button>(R.id.btnConnectDevice)?.setOnClickListener {
            startActivity(Intent(this, EnrollmentActivity::class.java))
        }

        // Dashboard actions
        findViewById<Button>(R.id.btnRefreshStatus)?.setOnClickListener {
            refresh()
        }

        findViewById<Button>(R.id.btnDisconnect)?.setOnClickListener {
            showDisconnectConfirmationDialog()
        }

        // Global links
        findViewById<TextView>(R.id.btnPrivacyLink)?.setOnClickListener {
            startActivity(Intent(this, PrivacyActivity::class.java))
        }

        findViewById<TextView>(R.id.btnSettingsLink)?.setOnClickListener {
            startActivity(Intent(this, SettingsActivity::class.java))
        }
    }

    override fun onResume() {
        super.onResume()
        refresh()
        if (identity.loadMeta() != null) {
            HeartbeatWorker.schedule(this)
            CommandPollWorker.schedule(this)
        }
    }

    private fun refresh() {
        val layoutOnboarding = findViewById<LinearLayout>(R.id.layoutOnboarding)
        val layoutDashboard = findViewById<LinearLayout>(R.id.layoutDashboard)
        val badgeStatus = findViewById<TextView>(R.id.badgeStatus)

        val meta = identity.loadMeta()
        if (meta == null) {
            layoutOnboarding?.visibility = View.VISIBLE
            layoutDashboard?.visibility = View.GONE
            badgeStatus?.text = "Not Enrolled"
            badgeStatus?.setTextColor(0xFF9499A3.toInt())
            badgeStatus?.setBackgroundColor(0xFF161B22.toInt())
            return
        }

        layoutOnboarding?.visibility = View.GONE
        layoutDashboard?.visibility = View.VISIBLE

        val lifecycle = meta.optString("lifecycleState", "UNKNOWN")
        val deviceId = meta.optString("deviceId", "")
        val baseUrl = meta.optString("serverBaseUrl", "")

        renderStatusBadge(lifecycle, isLiveVerified = false)
        if (deviceId.isNotBlank() && baseUrl.isNotBlank()) {
            syncStatusWithServer(deviceId, baseUrl)
        }

        val deviceModel = "${Build.MANUFACTURER} ${Build.MODEL} (Android ${Build.VERSION.RELEASE})".trim()
        findViewById<TextView>(R.id.txtDeviceModel)?.text = deviceModel

        // Keystore Trust Level
        val txtKeystoreTrust = findViewById<TextView>(R.id.txtKeystoreTrust)
        val secLevel = identity.getDetailedSecurityLevel()
        when (secLevel) {
            AndroidKeystoreIdentity.KeystoreSecurityLevel.STRONGBOX -> {
                txtKeystoreTrust?.text = "StrongBox Keymaster (Dedicated Hardware HSM)"
                txtKeystoreTrust?.setTextColor(0xFF75B798.toInt())
            }
            AndroidKeystoreIdentity.KeystoreSecurityLevel.TEE -> {
                txtKeystoreTrust?.text = "Hardware Keystore (TEE Hardware-Backed)"
                txtKeystoreTrust?.setTextColor(0xFF75B798.toInt())
            }
            AndroidKeystoreIdentity.KeystoreSecurityLevel.SOFTWARE -> {
                txtKeystoreTrust?.text = "Software Keystore (Cryptographic Key)"
                txtKeystoreTrust?.setTextColor(0xFFC8A66A.toInt())
            }
            else -> {
                txtKeystoreTrust?.text = "Cryptographic Keystore"
                txtKeystoreTrust?.setTextColor(0xFF9499A3.toInt())
            }
        }

        if (identity.hasKey()) {
            val pub = identity.exportPublicIdentity()
            findViewById<TextView>(R.id.txtFingerprint)?.text = "Key: ${pub.fingerprint}"
        }

        findViewById<TextView>(R.id.txtServerUrl)?.text = "Mesh Server: ${meta.optString("serverBaseUrl")}"

        val lastHb = identity.getLastHeartbeatAt()
        val hbText = when {
            lastHb <= 0L -> getString(R.string.heartbeat_never)
            System.currentTimeMillis() - lastHb < 20 * 60 * 1000L ->
                "Last Heartbeat: ${DateFormat.getDateTimeInstance().format(Date(lastHb))} (Online)"
            System.currentTimeMillis() - lastHb < 60 * 60 * 1000L ->
                "Last Heartbeat: ${DateFormat.getDateTimeInstance().format(Date(lastHb))} (Stale)"
            else ->
                "Last Heartbeat: ${DateFormat.getDateTimeInstance().format(Date(lastHb))} (Offline)"
        }
        findViewById<TextView>(R.id.txtHeartbeatStatus)?.text = hbText
    }

    private fun showDisconnectConfirmationDialog() {
        AlertDialog.Builder(this)
            .setTitle(getString(R.string.disconnect_title))
            .setMessage(getString(R.string.disconnect_message))
            .setPositiveButton(getString(R.string.disconnect_confirm)) { _, _ ->
                identity.deleteKey()
                refresh()
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    private fun syncStatusWithServer(deviceId: String, baseUrl: String) {
        val client = OkHttpClient.Builder()
            .connectTimeout(5, TimeUnit.SECONDS)
            .readTimeout(5, TimeUnit.SECONDS)
            .build()

        lifecycleScope.launch(Dispatchers.IO) {
            val url = "${baseUrl.trimEnd('/')}/api/devices/$deviceId/enrollment/status"
            try {
                val req = Request.Builder()
                    .url(url)
                    .header("Accept", "application/json")
                    .build()

                client.newCall(req).execute().use { res ->
                    if (res.isSuccessful) {
                        val json = JSONObject(res.body?.string().orEmpty())
                        val status = json.optString("status")
                        val lifecycleState = json.optString("lifecycleState")
                        val resolvedState = if (status == "CONNECTED" || lifecycleState == "TRUSTED") {
                            "TRUSTED"
                        } else if (lifecycleState.isNotBlank()) {
                            lifecycleState
                        } else {
                            "UNKNOWN"
                        }
                        identity.saveMeta(deviceId, baseUrl, resolvedState)
                        withContext(Dispatchers.Main) {
                            renderStatusBadge(resolvedState, isLiveVerified = true)
                        }
                    } else {
                        withContext(Dispatchers.Main) {
                            val cached = identity.loadMeta()?.optString("lifecycleState", "UNKNOWN") ?: "UNKNOWN"
                            renderStatusBadge(cached, isLiveVerified = false)
                        }
                    }
                }
            } catch (_: Exception) {
                withContext(Dispatchers.Main) {
                    val cached = identity.loadMeta()?.optString("lifecycleState", "UNKNOWN") ?: "UNKNOWN"
                    renderStatusBadge(cached, isLiveVerified = false)
                }
            }
        }
    }

    private fun renderStatusBadge(lifecycle: String, isLiveVerified: Boolean) {
        val badgeStatus = findViewById<TextView>(R.id.badgeStatus) ?: return
        when (lifecycle) {
            "ACTIVE", "TRUSTED" -> {
                badgeStatus.text = if (isLiveVerified) "● PROTECTED (Verified)" else "● PROTECTED (Stale/Offline)"
                badgeStatus.setTextColor(if (isLiveVerified) 0xFF75B798.toInt() else 0xFF9499A3.toInt())
                badgeStatus.setBackgroundColor(if (isLiveVerified) 0xFF101D16.toInt() else 0xFF161B22.toInt())
            }
            "ENROLLMENT_PENDING" -> {
                badgeStatus.text = if (isLiveVerified) "● PENDING APPROVAL" else "● PENDING (Stale/Offline)"
                badgeStatus.setTextColor(0xFFC8A66A.toInt())
                badgeStatus.setBackgroundColor(0xFF1F1A12.toInt())
            }
            "REVOKED", "DECOMMISSIONED" -> {
                badgeStatus.text = "● REVOKED"
                badgeStatus.setTextColor(0xFFF85149.toInt())
                badgeStatus.setBackgroundColor(0xFF211214.toInt())
            }
            else -> {
                badgeStatus.text = "● $lifecycle"
                badgeStatus.setTextColor(0xFF9499A3.toInt())
                badgeStatus.setBackgroundColor(0xFF161B22.toInt())
            }
        }
    }
}
