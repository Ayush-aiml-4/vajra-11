package com.vajra.companion.work

import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import android.media.AudioAttributes
import android.media.RingtoneManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.vajra.companion.commands.CommandCapabilityMatrix
import com.vajra.companion.identity.AndroidKeystoreIdentity
import com.vajra.companion.network.VajraApiClient
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.TimeUnit

class CommandPollWorker(
    appContext: Context,
    params: WorkerParameters
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        val identity = AndroidKeystoreIdentity(applicationContext)
        val meta = identity.loadMeta() ?: return Result.success()
        val prefs = applicationContext.getSharedPreferences("vajra_settings", Context.MODE_PRIVATE)
        val baseUrl = prefs.getString("serverBaseUrl", null)
            ?: meta.optString("serverBaseUrl")
        val api = VajraApiClient(identity) { baseUrl }
        val processed = applicationContext.getSharedPreferences("vajra_cmd_processed", Context.MODE_PRIVATE)

        return try {
            api.pendingCommands().use { res ->
                if (!res.isSuccessful) return Result.retry()
                val body = res.body?.string().orEmpty()
                val root = JSONObject(body)
                val commands: JSONArray = when {
                    root.has("commands") -> root.getJSONArray("commands")
                    root.has("pendingCommands") -> root.getJSONArray("pendingCommands")
                    else -> JSONArray()
                }
                for (i in 0 until commands.length()) {
                    val cmd = commands.getJSONObject(i)
                    val id = cmd.optString("id")
                    val action = cmd.optString("actionType")
                    if (id.isBlank() || action.isBlank()) continue
                    if (processed.getBoolean(id, false)) continue

                    try {
                        api.acknowledge(id).close()
                    } catch (_: Exception) { /* continue */ }

                    val (status, message, metadata) = execute(action)
                    val result = JSONObject()
                        .put("status", status)
                        .put("safeMessage", message)
                    if (metadata != null) result.put("resultMetadata", metadata)

                    api.commandResult(id, result).close()
                    processed.edit().putBoolean(id, true).apply()
                }
                Result.success()
            }
        } catch (_: Exception) {
            Result.retry()
        }
    }

    private fun execute(action: String): Triple<String, String, JSONObject?> {
        if (!CommandCapabilityMatrix.isKnown(action)) {
            return Triple("FAILED", "Unknown action type rejected.", null)
        }
        if (!CommandCapabilityMatrix.isExecutableOnAndroid(action)) {
            return Triple("FAILED", CommandCapabilityMatrix.unsupportedReason(action), null)
        }
        return when (action) {
            CommandCapabilityMatrix.REQUEST_DEVICE_STATUS -> {
                val meta = JSONObject()
                    .put("agentVersion", "0.1.0-android")
                    .put("osVersion", "Android ${Build.VERSION.RELEASE}")
                    .put("sdkInt", Build.VERSION.SDK_INT)
                    .put("model", Build.MODEL)
                    .put("manufacturer", Build.MANUFACTURER)
                Triple("COMPLETED", "Android companion status report completed.", meta)
            }
            CommandCapabilityMatrix.RING_DEVICE -> {
                ringDevice()
                Triple("COMPLETED", "Ring notification played on device.", null)
            }
            else -> Triple("FAILED", CommandCapabilityMatrix.unsupportedReason(action), null)
        }
    }

    private fun ringDevice() {
        val channelId = "vajra_ring"
        val nm = applicationContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                channelId,
                "VAJRA Ring",
                NotificationManager.IMPORTANCE_HIGH
            ).apply {
                description = "Owner-requested device ring from VAJRA console"
                setSound(
                    RingtoneManager.getDefaultUri(RingtoneManager.TYPE_ALARM),
                    AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_ALARM)
                        .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                        .build()
                )
            }
            nm.createNotificationChannel(channel)
        }
        val notification = NotificationCompat.Builder(applicationContext, channelId)
            .setSmallIcon(android.R.drawable.ic_lock_idle_alarm)
            .setContentTitle("VAJRA — Find my device")
            .setContentText("Your VAJRA account requested this phone to ring.")
            .setPriority(NotificationCompat.PRIORITY_HIGH)
            .setCategory(NotificationCompat.CATEGORY_ALARM)
            .setAutoCancel(true)
            .build()
        nm.notify(1001, notification)
        try {
            val ringtone = RingtoneManager.getRingtone(
                applicationContext,
                RingtoneManager.getDefaultUri(RingtoneManager.TYPE_ALARM)
            )
            ringtone?.play()
        } catch (_: Exception) { /* notification is enough */ }
    }

    companion object {
        const val UNIQUE = "vajra_command_poll"

        fun schedule(context: Context) {
            val req = PeriodicWorkRequestBuilder<CommandPollWorker>(15, TimeUnit.MINUTES).build()
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
