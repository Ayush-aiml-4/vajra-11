package com.vajra.companion.ui

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import com.vajra.companion.R
import com.vajra.companion.identity.AndroidKeystoreIdentity
import com.vajra.companion.work.CommandPollWorker
import com.vajra.companion.work.HeartbeatWorker

class SettingsActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        val input = findViewById<EditText>(R.id.inputServerUrl)
        val prefs = getSharedPreferences("vajra_settings", MODE_PRIVATE)
        input.setText(
            prefs.getString("serverBaseUrl", getString(R.string.default_server_url))
        )

        findViewById<Button>(R.id.btnSaveServer).setOnClickListener {
            val url = input.text.toString().trim().trimEnd('/')
            if (!url.startsWith("http://") && !url.startsWith("https://")) {
                Toast.makeText(this, R.string.invalid_server_url, Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            prefs.edit().putString("serverBaseUrl", url).apply()
            val identity = AndroidKeystoreIdentity(this)
            identity.loadMeta()?.let { meta ->
                identity.saveMeta(
                    meta.getString("deviceId"),
                    url,
                    meta.optString("lifecycleState", "ENROLLMENT_PENDING")
                )
            }
            Toast.makeText(this, R.string.saved, Toast.LENGTH_SHORT).show()
        }

        findViewById<Button>(R.id.btnDisconnect).setOnClickListener {
            AlertDialog.Builder(this)
                .setTitle(R.string.disconnect_title)
                .setMessage(R.string.disconnect_message)
                .setPositiveButton(R.string.disconnect_confirm) { _, _ ->
                    HeartbeatWorker.cancel(this)
                    CommandPollWorker.cancel(this)
                    AndroidKeystoreIdentity(this).deleteKey()
                    getSharedPreferences("vajra_cmd_processed", MODE_PRIVATE).edit().clear().apply()
                    Toast.makeText(this, R.string.disconnected, Toast.LENGTH_SHORT).show()
                    finish()
                }
                .setNegativeButton(android.R.string.cancel, null)
                .show()
        }
    }
}
