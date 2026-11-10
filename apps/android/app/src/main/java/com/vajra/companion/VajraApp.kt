package com.vajra.companion

import android.app.Application
import com.vajra.companion.identity.AndroidKeystoreIdentity
import com.vajra.companion.work.CommandPollWorker
import com.vajra.companion.work.HeartbeatWorker

class VajraApp : Application() {
    override fun onCreate() {
        super.onCreate()
        if (AndroidKeystoreIdentity(this).loadMeta() != null) {
            HeartbeatWorker.schedule(this)
            CommandPollWorker.schedule(this)
        }
    }
}
