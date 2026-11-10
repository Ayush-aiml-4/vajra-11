# VAJRA — Android Platform Security & Permission Specification

**Target Directory:** `apps/android`  
**Target Technology:** Native Kotlin Android Application  
**Document Status:** Prompt 0015 companion foundation `IMPLEMENTED` in `apps/android` (field validation pending)  
**Related Documents:** `docs/product/PRD.md`, `docs/security/device-enrollment.md`, `docs/security/remote-command-security.md`

---

## 1. Supported Android Versions & Cryptographic Identity

- **Minimum Supported SDK:** `API Level 29 (Android 10)` — ensures modern scoped storage, background location permission granularity (`ACCESS_BACKGROUND_LOCATION`), and reliable hardware-backed Keystore APIs.
- **Target SDK:** `API Level 34 / 35 (Android 14 / 15)` — complies with strict foreground service types (`FOREGROUND_SERVICE_LOCATION`, `FOREGROUND_SERVICE_SYSTEM_EXEMPTED` / `SPECIAL_USE` where permitted) and explicit `USE_FULL_SCREEN_INTENT` governance.
- **Hardware-Backed Keystore (`AndroidKeyStore`):**
  - During enrollment, the app generates an `ECDSA P-256` (or `Ed25519`) keypair inside the `AndroidKeyStore` provider, preferring **StrongBox Keymaster** when supported by the device SoC and falling back to **TEE (Trusted Execution Environment)**.
  - The private key is non-exportable: even if the app's sandbox storage is read, raw private key bytes cannot be extracted.

---

## 2. Permission Architecture (Required vs. Optional)

VAJRA never attempts to bypass Android runtime permissions. Every permission is requested transparently with an in-app explanation of why it is needed and what happens if the user declines it.

### 2.1 Core Required Manifest Permissions (Baseline Heartbeat & Ringing)

| Android Permission | Protection Level | Why VAJRA Needs It | Behavior if Denied / Unavailable |
| :--- | :--- | :--- | :--- |
| `INTERNET` & `ACCESS_NETWORK_STATE` | Normal | Transmit signed heartbeats, security posture summaries, and command receipts over TLS 1.3 to `vajra-api`. | Standard install-time permission. |
| `POST_NOTIFICATIONS` (Android 13+) | Runtime | Display security alerts, persistent Lost Mode recovery notifications, and "Stop Ringing" controls. | User cannot see local alert banners or lockscreen notification cards; app displays an onboarding banner guiding the user to enable notifications. |
| `FOREGROUND_SERVICE` | Normal | Run visible, user-transparent foreground execution when processing an active `RING_PHONE` or `LOST_MODE` session. | Standard manifest declaration. |
| `WAKE_LOCK` & `VIBRATE` | Normal | Temporarily wake the CPU/screen and vibrate the handset when an authenticated `RING_PHONE` command arrives. | Standard install-time permission. |
| `RECEIVE_BOOT_COMPLETED` | Normal | Reschedule periodic signed heartbeat `WorkManager` jobs and restore Lost Mode state if the phone reboots while lost. | Standard install-time permission. |

### 2.2 Optional / Feature-Specific Permissions (`VAJRA Locate` & `VAJRA Recover`)

| Android Permission | Feature Enabled | Why VAJRA Needs It | Graceful Degradation if Denied |
| :--- | :--- | :--- | :--- |
| `ACCESS_COARSE_LOCATION` & `ACCESS_FINE_LOCATION` | `VAJRA Locate` (Foreground) | Obtain GPS / Wi-Fi fused coordinates when the user tests location in the app. | `PermissionState` is reported as `DENIED`; `VAJRA Locate` cannot report device GPS coordinates. |
| `ACCESS_BACKGROUND_LOCATION` | `VAJRA Locate` (Unattended Lost Device) | Allow the owner to request the phone's location from the Web Console (`REQUEST_LOCATION` / `ENABLE_LOST_MODE`) when the phone is misplaced and not actively open in the foreground. | Reported as `GRANTED_FOREGROUND_ONLY`; unattended remote location requests return `OS_PERMISSION_DENIED` with instructions. |
| `USE_FULL_SCREEN_INTENT` (Android 14+) | Custom Recovery Screen & `RING_PHONE` UI | Launch the high-priority `RecoveryActivity` or "Phone Ringing" card over the locked screen when the display wakes. | Falls back to a standard high-priority notification (`PARTIAL_SUCCESS_NOTIFICATION_ONLY`). |
| `ACCESS_NOTIFICATION_POLICY` (Optional) | Audible Ring in DND | Allow `RING_PHONE` to play audible sound on `STREAM_ALARM` even if Do Not Disturb is active. | Plays on `STREAM_ALARM` within current OS DND constraints and reports `COMPLETED_WITH_OS_AUDIO_RESTRICTION`. |

### 2.3 Permissions VAJRA Will NEVER Request
VAJRA strictly prohibits requesting or declaring:
- ❌ `RECORD_AUDIO` (No microphone access)
- ❌ `CAMERA` (No camera capture—except optionally via system QR scanner intent during enrollment if user chooses QR pairing)
- ❌ `READ_SMS`, `SEND_SMS`, `RECEIVE_SMS`, `READ_CALL_LOG`, `READ_CONTACTS`
- ❌ `READ_EXTERNAL_STORAGE` / `MANAGE_EXTERNAL_STORAGE` (No access to user photos, videos, or documents)
- ❌ `BIND_ACCESSIBILITY_SERVICE` (Never abuses Accessibility APIs for keylogging, screen scraping, or auto-clicking permission dialogs)

---

## 3. Foreground, Background & Battery Optimization Limitations

Modern Android versions (Android 10–15) enforce strict background execution limits (Doze mode, App Standby Buckets, and Phantom Process killers):

1. **Routine Heartbeats (`WorkManager`):**
   - Periodic background heartbeats use Android `WorkManager` (`PeriodicWorkRequest`, minimum OS interval 15 minutes). During deep Doze mode (when the phone is stationary and unplugged), Android defers `WorkManager` jobs into maintenance windows.
   - Consequently, the VAJRA Backend Watchdog uses an adaptive heartbeat window for Android devices (e.g., marking an Android device `OFFLINE` only after missed check-ins + unacknowledged high-priority wake push, rather than assuming a 60-second desktop cadence).
2. **Immediate Remote Commands (High-Priority Push Wakeup):**
   - Because an offline or Dozing Android phone does not keep a constant TCP socket open, time-sensitive commands (`RING_PHONE`, `ENABLE_LOST_MODE`, `REQUEST_LOCATION`) use a high-priority wake notification (FCM High Priority data message containing only the `commandId` wakeup hint) that grants the app a brief OS execution window to fetch and verify the signed command from `vajra-api`.
3. **Battery Optimization Guidance:**
   - OEM-specific aggressive battery savers (e.g., Xiaomi MIUI, Samsung OneUI sleeping apps, OnePlus) can delay background wakeups. The Android app includes a diagnostic screen that checks `PowerManager.isIgnoringBatteryOptimizations` and explains how the user can optionally mark VAJRA as *"Unrestricted"* in Android Battery Settings if they want reliable lost-device recovery.

---

## 4. Play Protect, Sandbox & Lost-Device OS Boundaries

1. **Google Play Protect & Play Integrity Compliance:**
   - Because VAJRA never uses hidden reflection, dynamic code loading (`UPLOAD_EXECUTABLE` is banned), root exploits, or Accessibility abuse, it remains 100% compliant with Google Play Protect policies.
   - Where available, the app can use the **Play Integrity API** to attest device integrity (`MEETS_DEVICE_INTEGRITY` / `MEETS_STRONG_INTEGRITY`) in its signed posture report.
2. **Lockscreen & Lost-Device Limitations:**
   - A third-party Android app cannot replace the system Keyguard lockscreen, cannot change the user's device PIN/password (deprecated in modern Android for regular apps), and cannot prevent a thief from holding the hardware power button to turn off the phone.
   - VAJRA's **Custom Recovery Screen** uses `Activity.setShowWhenLocked(true)` + `setTurnScreenOn(true)` launched via a high-priority notification/full-screen intent so a finder can view the owner's recovery contact info (`RecoveryProfile`) over the locked Keyguard without accessing the user's personal apps.
   - VAJRA explicitly recommends keeping Android's built-in **Find My Device** enabled alongside VAJRA for firmware-level lock/erase capabilities.
