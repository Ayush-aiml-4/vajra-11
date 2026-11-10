package com.vajra.companion.work

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import android.os.Build
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.vajra.companion.identity.AndroidKeystoreIdentity
import com.vajra.companion.network.VajraApiClient
import org.json.JSONObject
import java.util.concurrent.TimeUnit
import kotlin.math.roundToInt

class HeartbeatWorker(
    appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        val identity = AndroidKeystoreIdentity(applicationContext)
        val meta = identity.loadMeta() ?: return Result.success()
        val state = meta.optString("lifecycleState", "")
        if (state in listOf("REVOKED", "DECOMMISSIONED", "COMPROMISED", "UNREGISTERED")) {
            return Result.success()
        }

        val prefs = applicationContext.getSharedPreferences("vajra_settings", Context.MODE_PRIVATE)
        val baseUrl = prefs.getString("serverBaseUrl", null)
            ?: meta.optString("serverBaseUrl")

        val api = VajraApiClient(identity) { baseUrl }

        // Query battery level and charging state via BatteryManager
        val batteryIntent = applicationContext.registerReceiver(
            null,
            IntentFilter(Intent.ACTION_BATTERY_CHANGED)
        )
        val level = batteryIntent?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
        val scale = batteryIntent?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
        val status = batteryIntent?.getIntExtra(BatteryManager.EXTRA_STATUS, -1) ?: -1

        return try {
            val payload = buildHeartbeatPayload(
                osRelease = Build.VERSION.RELEASE ?: "unknown",
                level = level,
                scale = scale,
                status = status,
                hasBatteryIntent = batteryIntent != null
            )

            api.heartbeat(payload).use { res ->
                if (res.isSuccessful) {
                    identity.setLastHeartbeatAt(System.currentTimeMillis())
                    if (state == "ENROLLMENT_PENDING" || state == "TRUSTED" || state == "OFFLINE" || state == "ACTIVE") {
                        identity.saveMeta(
                            meta.getString("deviceId"),
                            baseUrl,
                            "ACTIVE"
                        )
                    }
                    Result.success()
                } else if (res.code == 401 || res.code == 403) {
                    val errBody = res.body?.string().orEmpty()
                    if (
                        (state == "ACTIVE" || state == "TRUSTED" || state == "OFFLINE") &&
                        (errBody.contains("REVOKED") || errBody.contains("DECOMMISSIONED") || errBody.contains("DEVICE_CREDENTIAL_INACTIVE"))
                    ) {
                        identity.saveMeta(
                            meta.getString("deviceId"),
                            baseUrl,
                            "REVOKED"
                        )
                    }
                    Result.failure()
                } else {
                    Result.retry()
                }
            }
        } catch (_: Exception) {
            Result.retry()
        }
    }

    companion object {
        const val UNIQUE = "vajra_heartbeat"
        private const val STATUS_UNKNOWN = BatteryManager.BATTERY_STATUS_UNKNOWN
        private const val STATUS_CHARGING = BatteryManager.BATTERY_STATUS_CHARGING
        private const val STATUS_FULL = BatteryManager.BATTERY_STATUS_FULL

        /**
         * Builds the signed Android heartbeat JSON payload.
         * Rounds battery percentage to nearest integer in [0, 100] and omits both
         * `batteryLevel` and `charging` when battery telemetry is unavailable/unknown,
         * preventing false `charging: false` telemetry in PostgreSQL.
         */
        fun buildHeartbeatPayload(
            osRelease: String,
            level: Int,
            scale: Int,
            status: Int,
            hasBatteryIntent: Boolean = true
        ): JSONObject {
            val batteryPct: Int? = if (hasBatteryIntent && level >= 0 && scale > 0) {
                ((level.toDouble() / scale.toDouble()) * 100.0).roundToInt().coerceIn(0, 100)
            } else {
                null
            }

            val charging: Boolean? = if (
                batteryPct != null &&
                status != -1 &&
                status != STATUS_UNKNOWN
            ) {
                status == STATUS_CHARGING || status == STATUS_FULL
            } else {
                null
            }

            val payload = JSONObject()
                .put("connectivityStatus", "ONLINE")
                .put("agentVersion", "0.1.0-android")
                .put("osVersion", "Android $osRelease")
                .put("platform", "ANDROID")

            if (batteryPct != null) {
                payload.put("batteryLevel", batteryPct)
            }
            if (charging != null) {
                payload.put("charging", charging)
            }
            return payload
        }

        fun schedule(context: Context) {
            // OS minimum periodic interval is 15 minutes
            val req = PeriodicWorkRequestBuilder<HeartbeatWorker>(15, TimeUnit.MINUTES)
                .build()
            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                UNIQUE,
                ExistingPeriodicWorkPolicy.KEEP,
                req
            )
        }

        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(UNIQUE)
        }
    }
}
