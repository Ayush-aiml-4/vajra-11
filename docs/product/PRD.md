# VAJRA — Product Requirements Document (PRD)

**Product Title:** VAJRA — Intelligent Digital Security  
**Meaning:** Vajra (वज्र) represents strength, protection, and resilience.  
**Product Category:** Personal Cross-Device Security & Recovery Platform  
**Document Status:** Master Product Specification (Prompt 0002 — `SPECIFICATION` / `PLANNED`)  
**Current Implementation Status:** Foundation (`IMPLEMENTED`: `/api/health`, Web Console Shell, Shared Types; `MOCKED`: Dashboard Demo Telemetry; `PLANNED`: All live device monitoring, location, recovery, ThreatCheck, and risk modules)

---

## 1. Executive Summary & Core Purpose

**VAJRA — Intelligent Digital Security** is a personal security platform that connects a user's trusted **Windows** and **Android** devices to a secure web console (`React 19 + TypeScript + Vite` frontend backed by `Express + TypeScript`).

> **Ethical & Legal Mandate:**  
> **VAJRA is designed to protect devices owned or explicitly authorized by the user.**  
> It is a transparent, permission-aware, and auditable personal security platform—never stealth spyware, covert surveillance software, or an offensive hacking tool.

### 1.1 Six Major Responsibilities

1. **Protect** — Establish hardware-backed cryptographic device identity (`Device ID + Public Key + Proof`), least-privilege agent boundaries, and continuous posture verification across the user's personal endpoints.
2. **Detect** — Collect permitted, high-signal security telemetry from Windows and Android endpoints without collecting private user content, passwords, or keystrokes.
3. **Alert** — Surface deduplicated, prioritized security and tamper notifications with clear severity levels (`INFO` through `CRITICAL`) and an auditable acknowledgement workflow.
4. **Locate** — Provide transparent, permission-gated device location tracking with explicit source (`GPS`, `NETWORK`, `WINDOWS_LOCATION`, `IP_APPROXIMATE`) and accuracy attribution.
5. **Recover** — Empower the user to locate a misplaced device, trigger an authenticated audible ring on their phone (`RING_PHONE`), and activate Lost Mode with a privacy-preserving Custom Recovery Screen (`ENABLE_LOST_MODE` / `DISPLAY_RECOVERY_MESSAGE`) within OS boundaries.
6. **Analyze Threats** — Inspect suspicious URLs and domains through **ThreatCheck** (`ThreatIntelProvider` abstraction) and compute explainable, deterministic risk assessments via the **VAJRA Risk Engine**.

---

## 2. Target Users & Supported Platforms

- **Primary User:** An individual managing their own personal laptops/PCs and smartphones from a unified security console.
- **Active Web & API Stack (`IMPLEMENTED` Foundation):**
  - **Web Console:** React 19 + TypeScript + Tailwind CSS v4 + Vite
  - **Backend API:** Node.js + Express + TypeScript (`vajra-api`)
  - **Database (Planned for Prompt 0003):** PostgreSQL + Prisma ORM
- **Endpoint Platforms (`PLANNED`):**
  - **Windows Agent:** C# / .NET 8+ Windows Service (`Windows 10 22H2+` and `Windows 11`)
  - **Android Application:** Native Kotlin Android App (`Android 10 / API 29+`, targeting `Android 14/15`)

---

## 3. Product Module Specifications

### Module 1 — VAJRA Guard (Device Security Monitoring)

**Status:** `PLANNED` (Mock preview cards currently rendered in Web Console)

VAJRA Guard monitors the security health, configuration posture, and availability of enrolled Windows and Android devices using documented operating system APIs.

#### 3.1.1 Windows Monitoring Scope (`apps/windows-agent`)
- **Legitimate Security Telemetry Collected (`PLANNED`):**
  - **Authentication & Session Posture:** Interactive logon success (`LOGIN_SUCCESS`) and logon failure (`LOGIN_FAILURE`) metadata (Event IDs 4624/4625 logon type, timestamp, and account domain/alias—never passwords), plus workstation lock (`DEVICE_LOCKED`) and unlock (`DEVICE_UNLOCKED`) transitions (Event IDs 4800/4801).
  - **Device Online/Offline State:** Periodic cryptographically signed heartbeats (`DEVICE_ONLINE`, `DEVICE_OFFLINE`).
  - **Security Configuration Changes:** Windows Defender Antivirus operational posture, real-time protection state, Windows Firewall profile state, and BitLocker drive encryption status (`SECURITY_CONFIGURATION_CHANGED`).
  - **Selected USB/Hardware Events:** External USB mass-storage or HID device arrival notifications (`USB_DEVICE_DETECTED`) for physical tamper awareness.
  - **Network Posture Changes:** Network profile transitions (e.g., Public vs. Private network, new default gateway/SSID hash) (`NETWORK_CHANGED`).
  - **Security-Agent Health:** Service startup, graceful shutdown, and unexpected termination detection (`SECURITY_AGENT_STOPPED`).
- **Explicitly Prohibited on Windows (Never Collected):**
  - Plaintext passwords, password hashes, or credential material
  - Keystrokes or clipboard contents
  - Private message, email, or browser history contents
  - Arbitrary user file contents or documents
  - Hidden screenshots or covert screen recordings
  - Hidden webcam footage or microphone audio recordings

#### 3.1.2 Android Monitoring Scope (`apps/android`)
- **Legitimate Security Telemetry Collected (`PLANNED`):**
  - **Device Online/Offline State:** Signed periodic heartbeats via Android `WorkManager` / foreground service when active.
  - **Battery & Power State:** Battery percentage and charging state (`BatteryManager`) to contextualize offline events or last-known location before battery depletion.
  - **Network Connectivity State:** Active transport type (`WIFI`, `CELLULAR`, `VPN`, `NONE` via `ConnectivityManager`) without inspecting packet payloads.
  - **Device & App Security State (Where Permitted):** Device keyguard/screen-lock presence (`KeyguardManager.isDeviceSecure`), biometric/PIN enrollment status, Google Play Protect / Play Integrity API attestation status, and developer options / ADB debugging state (`Settings.Global.ADB_ENABLED`).
  - **Location (When Explicitly Authorized):** Foreground or background location coordinates strictly when the user has granted Android runtime location permissions.
- **Android OS Restrictions & Transparency:**
  - Android strictly sandboxes third-party applications. VAJRA cannot read other apps' private storage, cannot read SMS/call logs, cannot monitor system-wide logins of other apps, and cannot silently enable permissions. If a user revokes a permission in Android Settings, the app immediately reports `PermissionState = DENIED` and degrades gracefully.

---

### Module 2 — VAJRA Locate (Permission-Aware Device Location)

**Status:** `PLANNED`

VAJRA Locate enables the user to view the current or last known location of their enrolled devices when explicitly permitted by the user and supported by the operating system.

#### 3.2.1 Core Location Data Model
Every location record captured or displayed by VAJRA must explicitly define four mandatory attributes:

1. **`LocationSource`**:
   - `ANDROID_FUSED_GPS` — High-accuracy GNSS/GPS + Wi-Fi/Cell fused location on Android.
   - `ANDROID_NETWORK` — Cell tower / Wi-Fi positioning on Android when GPS is unavailable indoors.
   - `WINDOWS_LOCATION_API` — Windows Location Service (`Windows.Devices.Geolocation`) using Wi-Fi triangulation or built-in GNSS.
   - `IP_APPROXIMATE` — Coarse city/region-level estimation derived from the public egress IP address when OS location services are disabled or unsupported.
2. **`LocationAccuracy`**:
   - Numeric radius in meters (`accuracyMeters: number`) paired with a semantic accuracy tier:
     - `PRECISE` ($\le 50\text{m}$)
     - `MODERATE` ($51\text{m}\text{–}500\text{m}$)
     - `COARSE` ($> 500\text{m}$)
     - `APPROXIMATE_IP` (City/Region level; radius $\ge 5,000\text{m}$ or unspecified)
3. **`Timestamp`**:
   - `capturedAt` (ISO-8601 UTC timestamp when the coordinate was measured on the device) and `receivedAt` (server ingestion timestamp). Stale coordinates are explicitly labeled as **Last Known Location** with elapsed time.
4. **`PermissionState`**:
   - `GRANTED_BACKGROUND` — OS permits background location retrieval (required for unattended lost-device lookup on Android).
   - `GRANTED_FOREGROUND_ONLY` — OS permits location only while the VAJRA app is open on screen.
   - `DENIED` — User has not granted or has revoked OS location permission.
   - `OS_DISABLED` — System-wide location services are turned off at the OS level.

#### 3.2.2 Strict Truthfulness Invariant for IP-Derived Location
> **Mandatory Rule:** VAJRA must **never** represent `IP_APPROXIMATE` location as GPS-level or street-level accuracy. When only IP-derived location is available (common on desktop Windows PCs without Wi-Fi/GPS hardware or when OS location permission is denied), the Web Console must display a prominent **"Approximate Network/IP Location (City/Region Level Only — Not GPS)"** notice and refuse to plot a misleading pinpoint street marker.

#### 3.2.3 Behavior When Location Permission Is Unavailable
When `PermissionState` is `DENIED`, `GRANTED_FOREGROUND_ONLY` (during a background request), or `OS_DISABLED`:
1. The device agent does **not** attempt any workaround or undocumented side-channel to infer physical coordinates.
2. The device returns a signed `CommandResult` or status update with `PermissionState` and the most recent cached `LocationRecord` (if one exists prior to revocation and has not expired).
3. The Web Console explains which OS setting is blocking live location and provides instructions for re-enabling it once the device is recovered.

---

### Module 3 — VAJRA Recover (Lost-Device Protection & Phone Recovery)

**Status:** `PLANNED`

VAJRA Recover provides legitimate, non-destructive recovery tools for misplaced or lost personal devices.

#### 3.3.1 Phone Recovery Capabilities
Where Android OS permissions and device state allow, VAJRA Recover supports:
- **`Locate` (`REQUEST_LOCATION`)** — Request an immediate location refresh from the device.
- **`Ring` (`RING_PHONE`)** — Trigger a high-visibility audible alert to locate a nearby misplaced phone.
- **`Lost Mode` (`ENABLE_LOST_MODE` / `DISABLE_LOST_MODE`)** — Transition the device into `LOST` lifecycle state, increase heartbeat/location reporting frequency (if permitted), and activate the Custom Recovery Screen.
- **`Recovery Message` (`DISPLAY_RECOVERY_MESSAGE`)** — Update the owner contact message displayed on the recovery screen.
- **`Device Status` (`REQUEST_DEVICE_STATUS`)** — Request an immediate heartbeat containing battery percentage, network type, and security posture.

#### 3.3.2 Remote Phone Ringing (`RING_PHONE`) Workflow
1. **User Action:** User clicks **`RING PHONE`** in the Web Console and completes step-up command authorization.
2. **Command Dispatch:** Backend creates a signed `RemoteCommand` (`commandType = RING_PHONE`) with a unique cryptographic nonce and short expiration window (e.g., 5 minutes), and pushes a high-priority wake notification to the Android device.
3. **Device Verification:** The Android app wakes, verifies the backend cryptographic signature, checks that the nonce has not been replayed, and confirms the command has not expired.
4. **Command Acknowledgement (`RING_ACKNOWLEDGED`):** The device immediately sends a signed acknowledgement back to `vajra-api` confirming receipt.
5. **Audible Execution:** Using standard Android `AudioManager` and `MediaPlayer` / `RingtoneManager` APIs on the `STREAM_ALARM` audio channel ( paired with a full-screen high-priority notification so the owner can tap "Stop Ringing" once found), the phone plays a distinct audible tone for a bounded duration (e.g., 60 seconds or until dismissed on the device or cancelled from the console).
6. **OS Boundary Respect:** VAJRA does **not** exploit system vulnerabilities to bypass hardware mute switches or restricted Android Do Not Disturb (DND) policies. If Android's DND policy blocks alarm/media playback and the user has not granted `ACCESS_NOTIFICATION_POLICY`, the app plays at the maximum permitted stream level and reports the exact execution status (`COMPLETED_WITH_OS_AUDIO_RESTRICTION`) in `CommandResult`.

---

### Module 4 — Custom Recovery Screen (Lost-Device Information Screen)

**Status:** `PLANNED`

When a user enables Lost Mode (`ENABLE_LOST_MODE`) or dispatches `DISPLAY_RECOVERY_MESSAGE`, VAJRA provides a structured **Custom Recovery Screen** on Android to help a Good Samaritan return the device to its owner without exposing private data on the phone.

#### 3.4.1 Displayed Information Layout
```text
┌──────────────────────────────────────────────┐
│                 DEVICE LOST                  │
│                                              │
│  This device belongs to:                     │
│  [Owner Name / Alias]                        │
│                                              │
│  Please contact:                             │
│  [Recovery Contact Phone / Email]            │
│  [Optional Custom Recovery Note]             │
│                                              │
│  Device ID:                                  │
│  [Masked Device ID, e.g., VJR-••••-8F4B]     │
│                                              │
│  [ Contact Owner ]                           │
└──────────────────────────────────────────────┘
```

#### 3.4.2 Privacy & Data Minimization Rules
- **No Unnecessary Private Information:** The screen only displays the owner alias and recovery contact details explicitly configured in the user's `RecoveryProfile`. It never displays the owner's primary account email unless chosen, home address, full unmasked Device UUID, or any notifications/files from the phone.
- **Masked Device ID:** Only the final 4 characters of the device identifier are shown so the finder can quote the reference code to the owner without exposing internal database identifiers.

#### 3.4.3 Activation, Deactivation & Authentication
- **Activation:** Triggered remotely via an authenticated, step-up authorized `ENABLE_LOST_MODE` or `DISPLAY_RECOVERY_MESSAGE` command signed by `vajra-api`.
- **Deactivation:** Triggered remotely via `DISABLE_LOST_MODE` from the Web Console, OR locally on the device only after the owner unlocks the Android OS lockscreen (Keyguard biometric/PIN/pattern verification) and confirms recovery inside the VAJRA app. A stranger holding the locked phone cannot dismiss Lost Mode without unlocking the OS.

#### 3.4.4 Android OS Limitations & Native Integration Strategy
- **Strict OS Truthfulness:** A standard third-party Android application **cannot** replace or override the native Android System UI lockscreen (`Keyguard`) or block the power/reboot menu. VAJRA never claims to replace the OS lockscreen.
- **Permitted Android Mechanisms:**
  1. **Full-Screen Intent / Lockscreen Activity (`setShowWhenLocked(true)` & `setTurnScreenOn(true)`):** When permitted by Android (`USE_FULL_SCREEN_INTENT` on Android 14+), VAJRA launches a dedicated, read-only `RecoveryActivity` visible over the secure lockscreen that displays the recovery card while keeping the underlying Android Keyguard locked.
  2. **Persistent High-Priority Lockscreen Notification:** Displays the recovery contact details on the lockscreen notification shade if full-screen intents are restricted.
  3. **Complementing Native Android Find My Device:** VAJRA explicitly encourages users to keep Google's native *Find My Device* enabled, as system-level firmware integrations can set native lockscreen messages and locate offline devices via Google's network in ways third-party apps are restricted from doing.

#### 3.4.5 Failure Conditions
- **Device Offline / Powered Off:** Command remains in `AUTHORIZED` (queued) state until the device reconnects before TTL expiration, or transitions to `EXPIRED` and notifies the user in the Web Console.
- **Full-Screen Intent Permission Not Granted (Android 14+):** Falls back to a persistent lockscreen notification and reports `PARTIAL_SUCCESS_NOTIFICATION_ONLY` in `CommandResult`.
- **Lockscreen Notifications Hidden by User OS Settings:** If the user configured Android to hide all notification content on the lockscreen, the recovery card will only appear when the screen is woken via the full-screen intent activity; this limitation is surfaced in the Android app setup checklist.

---

### Module 5 — VAJRA Alert (Security & Operational Alerting)

**Status:** `PLANNED` (Mock `Active Alerts: 0` currently rendered in Web Console)

VAJRA Alert turns raw security events, tamper signals, and ThreatCheck detections into actionable notifications.

#### 3.5.1 Alert Categories & Severity Levels
- **Alert Categories (`AlertCategory`):**
  - `SECURITY` — Failed logons, Defender disabled, firewall lowered, suspicious configuration change.
  - `DEVICE` — New device registered, device online/offline state changes, low battery during lost mode.
  - `LOCATION` — Location permission revoked while in Lost Mode, significant unexpected location jump.
  - `TAMPER` — Heartbeat timeout expired unexpectedly, Windows agent service stopped (`SECURITY_AGENT_STOPPED`), invalid cryptographic signature detected.
  - `THREAT` — High/Critical malicious URL detected in ThreatCheck.
  - `RECOVERY` — Lost mode activated/deactivated, remote ring executed or failed.
  - `SYSTEM` — Account password/passkey changed, enrollment token expired after failed attempts.
- **Severity Levels (`AlertSeverity`):**
  - `INFO` — Informational operational milestone (e.g., `New device registered`, `Lost mode deactivated`).
  - `LOW` — Minor anomaly or advisory (e.g., `Location permission foreground-only`).
  - `MEDIUM` — Notable security change requiring review (e.g., `New unknown public network joined`, `USB storage device detected`).
  - `HIGH` — Urgent security or availability issue (e.g., `Multiple failed Windows logins`, `Device offline unexpectedly`, `Agent stopped`).
  - `CRITICAL` — Immediate threat or compromise indicator (e.g., `Windows Defender disabled`, `Tamper/signature verification failure`, `Critical phishing URL detected`, `Lost mode activated`).

#### 3.5.2 Lifecycle: Creation, Deduplication, Priority, Notification, Acknowledgement, Resolution & Audit
1. **Alert Creation:** Triggered deterministically by the Security Event System or Risk Engine when an incoming `SecurityEvent`, heartbeat timeout, or `ThreatCheck` crosses a defined rule threshold.
2. **Alert Deduplication:** Every alert generates a deterministic `dedupKey = hash(userId + deviceId + alertCategory + ruleId)`. If an open (`UNACKNOWLEDGED`) alert with the same `dedupKey` already exists within a configurable cooldown window (e.g., 15 minutes for repeated failed logins), VAJRA increments `occurrenceCount` and updates `lastSeenAt` on the existing alert rather than flooding the user with duplicate rows.
3. **Priority Queueing:** Alerts are sorted in the console by `Severity (CRITICAL -> INFO)` and then by `lastSeenAt DESC`.
4. **Notification Delivery:**
   - `CRITICAL` and `HIGH` alerts trigger immediate in-console realtime banners and (when configured in future milestones) outbound email/push notifications.
   - `MEDIUM`, `LOW`, and `INFO` alerts appear in the Web Console Alert Center without intrusive out-of-band paging unless configured by the user.
5. **Acknowledgement:** An authenticated user marks an alert `ACKNOWLEDGED` (`POST /api/alerts/:id/acknowledge`), recording `acknowledgedByUserId` and `acknowledgedAt`.
6. **Resolution:** An alert transitions to `RESOLVED` either automatically when a compensating signed event arrives (e.g., `DEVICE_ONLINE` resolves an unexpected offline alert) or manually when the user resolves it with an optional resolution note.
7. **Audit Trail:** Every alert state transition (`CREATED`, `DEDUP_INCREMENTED`, `ACKNOWLEDGED`, `RESOLVED`) writes an entry to `AuditLog`.

---

### Module 6 — ThreatCheck & VAJRA Risk Engine Overview

**Status:** `PLANNED` (Detailed specifications in `docs/product/threatcheck.md` and `docs/product/risk-engine.md`)

- **ThreatCheck:** Allows the user to submit a suspicious URL (`https://example.com`) for safe, passive multi-layer analysis (syntax/lexical checks, homograph/punycode detection, domain/DNS context, and pluggable `ThreatIntelProvider` lookups) while redacting query-string secrets and prohibiting unauthorized active vulnerability scanning.
- **VAJRA Risk Engine:** Computes an explainable `0–100` risk score (`SAFE/LOW/MEDIUM/HIGH/CRITICAL`) for each device and URL by combining explicit weighted rules with human-readable reasons and recommended actions.

---

## 4. Non-Goals & Permanent Security Prohibitions

To ensure VAJRA remains a trustworthy personal cybersecurity product, the following capabilities are **permanently out of scope**:
1. Stealth or hidden agent installation (the user must always see that VAJRA is installed and active).
2. Keylogging, password scraping, browser cookie theft, or private message monitoring.
3. Covert microphone, webcam, or screen capture.
4. Kernel-mode rootkits, antivirus/Defender tampering, or OS permission bypasses.
5. Arbitrary remote shell (`cmd.exe`, `powershell.exe`, `/bin/sh`) or arbitrary binary execution (`DOWNLOAD_AND_EXECUTE`).
6. Intrusive vulnerability scanning or exploitation of third-party websites without verified authorization.
