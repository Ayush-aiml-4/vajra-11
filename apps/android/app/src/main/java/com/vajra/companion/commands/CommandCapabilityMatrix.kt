package com.vajra.companion.commands

/**
 * Mirrors backend allowlist; only safe local handlers are executable.
 */
object CommandCapabilityMatrix {
    const val REQUEST_DEVICE_STATUS = "REQUEST_DEVICE_STATUS"
    const val REQUEST_LOCATION = "REQUEST_LOCATION"
    const val RING_DEVICE = "RING_DEVICE"
    const val DISPLAY_RECOVERY_MESSAGE = "DISPLAY_RECOVERY_MESSAGE"
    const val ENABLE_LOST_MODE = "ENABLE_LOST_MODE"
    const val DISABLE_LOST_MODE = "DISABLE_LOST_MODE"

    fun isKnown(action: String): Boolean = action in setOf(
        REQUEST_DEVICE_STATUS, REQUEST_LOCATION, RING_DEVICE,
        DISPLAY_RECOVERY_MESSAGE, ENABLE_LOST_MODE, DISABLE_LOST_MODE
    )

    fun isExecutableOnAndroid(action: String): Boolean = when (action) {
        REQUEST_DEVICE_STATUS -> true
        RING_DEVICE -> true // high-priority notification + optional alarm stream — user-visible
        else -> false
    }

    fun unsupportedReason(action: String): String = when (action) {
        REQUEST_LOCATION ->
            "Location is deferred: requires explicit ACCESS_FINE_LOCATION consent and is not implemented in this phase."
        DISPLAY_RECOVERY_MESSAGE ->
            "Full-screen recovery UI not implemented; use native lock screen."
        ENABLE_LOST_MODE, DISABLE_LOST_MODE ->
            "Lost Mode is primarily server-side lifecycle; Android lock-screen replacement is not claimed."
        else -> "Action not supported by this Android companion version."
    }
}
