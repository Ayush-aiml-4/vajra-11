# VAJRA — Offline & Failure Model Specification

**Document Status:** Architecture & Resilience Specification (Prompt 0002 — `PLANNED`)  
**Related Documents:** `docs/architecture/device-lifecycle.md`, `docs/security/remote-command-security.md`, `docs/platform/android.md`, `docs/platform/windows.md`

---

## 1. Core Resilience Principles

Real-world personal devices frequently lose Wi-Fi/cellular connectivity, run out of battery, sleep, or encounter OS permission restrictions. VAJRA is designed to **fail safely, transparently, and deterministically** without losing audit integrity or executing stale commands.

```text
Device loses connectivity / goes offline
      │
      ▼
Heartbeat TTL window expires on Backend Watchdog
      │
      ▼
Backend transitions Device connectivityStatus -> OFFLINE
(and lifecycleState -> OFFLINE if not in LOST / COMPROMISED)
      │
      ▼
Backend emits DEVICE_OFFLINE event & triggers Alert if configured
      │
      ▼
Device regains network connectivity
      │
      ▼
Device performs cryptographic handshake / sends signed Heartbeat + queued events
      │
      ▼
Backend verifies DeviceCredential signature & timestamp/nonce
      │
      ▼
Device transitions back to ACTIVE; queued non-expired commands are delivered
```

---

## 2. Ten Failure Scenarios & Deterministic System Behavior

### Scenario 1 — Windows PC Loses Internet Connectivity
- **Detection:** The Windows Agent fails to reach `vajra-api` during its periodic heartbeat check (e.g., every 60 seconds).
- **Local Agent Behavior:**
  - Continues monitoring local Windows Event Logs (`LOGIN_FAILURE`, `USB_DEVICE_DETECTED`, `SECURITY_CONFIGURATION_CHANGED`, `DEVICE_LOCKED`).
  - Buffers high-priority `SecurityEvent` records in a bounded, encrypted/ACL-protected local ring buffer on disk (capped at `500 events` or `2 MB`; oldest low-severity events dropped first if full).
  - Applies exponential backoff with jitter (`5s -> 15s -> 30s -> 60s max`) for reconnection probes.
- **Backend Behavior:** After 3 missed heartbeat intervals (180 seconds), the Backend Watchdog marks `connectivityStatus = OFFLINE`, records `DEVICE_OFFLINE`, and raises an alert if unexpected offline alerting is enabled.
- **Recovery:** Upon reconnection, the agent sends a fresh signed heartbeat followed by the buffered signed events (preserving their original `occurredAt` timestamps alongside the server's `ingestedAt` timestamp).

---

### Scenario 2 — Android Phone Loses Internet Connectivity
- **Detection:** Phone enters airplane mode, loses cellular/Wi-Fi signal, or powers down.
- **Local App Behavior:**
  - Queues any locally observed security state transitions in protected app storage (`Context.filesDir`).
  - If the phone is currently in `LOST` mode, the Custom Recovery Screen remains active locally using the cached `RecoveryProfile` even while completely offline.
- **Backend Behavior:**
  - Marks the phone `OFFLINE` once the expected heartbeat window expires.
  - If the user issues `RING_PHONE` or `ENABLE_LOST_MODE` while the phone is offline, the command is stored as `AUTHORIZED (Queued Until Online)` with an explicit `expiresAt` timestamp, and the Web Console clearly informs the user: *"Android Phone is currently offline. Command is queued and will execute if the phone reconnects before expiration."*
- **Recovery:** As soon as Android `ConnectivityManager` reports `NET_CAPABILITY_VALIDATED`, the app checks in with a signed heartbeat and fetches any non-expired queued commands.

---

### Scenario 3 — Backend (`vajra-api` or PostgreSQL) Is Unavailable
- **Web Console Behavior:**
  - `GET /api/health` or API calls fail/timeout.
  - The Web Console displays an explicit **"Backend API Unreachable"** banner with retry controls and never fabricates fake live success states.
- **Endpoint Agent Behavior (Windows & Android):**
  - Agents never crash when `vajra-api` returns `502/503/504` or connection refused.
  - Agents buffer critical security events locally and retry with exponential backoff + random jitter (`max 5 minutes`) to prevent a thundering herd when the backend recovers.

---

### Scenario 4 — Device Agent Crashes Unexpectedly
- **Windows Agent:**
  - Windows Service Control Manager (SCM) failure recovery policy automatically restarts `VajraGuardService` after 60 seconds.
  - Upon restart, the agent detects from its local state journal that the previous run did not exit cleanly, and immediately emits a signed `SECURITY_AGENT_STOPPED` / `DEVICE_ONLINE` recovery event noting `UNEXPECTED_EXIT_RECOVERED`.
- **Android App:**
  - Periodic `WorkManager` tasks and `BOOT_COMPLETED` receivers survive process death and automatically reschedule heartbeat checks during the next OS maintenance window.

---

### Scenario 5 — Notification Delivery Fails
- **Scenario:** Push wakeup (FCM) or outbound alert notification fails to deliver or times out.
- **System Behavior:**
  - Alerts are always persisted first in PostgreSQL (`Alert` table) before any notification dispatch is attempted, ensuring the Web Console Alert Center is always authoritative.
  - For Android remote commands, if the push wakeup fails to reach the device immediately, the command remains queued in `RemoteCommand` (`status = AUTHORIZED`) so the device will still pick it up on its next scheduled `WorkManager` heartbeat poll (provided `now() < expiresAt`).

---

### Scenario 6 — Location Is Unavailable (`VAJRA Locate`)
- **Causes:** User revoked location permission (`PermissionState = DENIED`), OS Location Services are turned off (`OS_DISABLED`), or GPS/Wi-Fi signal cannot acquire a fix indoors.
- **System Behavior:**
  - The agent never attempts to bypass OS location settings.
  - The agent returns a signed `CommandResult` with `executionStatus = OS_PERMISSION_DENIED` (or `LOCATION_FIX_TIMEOUT`) and current `PermissionState`.
  - The Web Console displays the **Last Known Location** (if a non-expired `LocationRecord` exists in the database) clearly labeled with its historical timestamp, or falls back to `IP_APPROXIMATE` with an explicit warning that IP location is city/region-level only and not GPS.

---

### Scenario 7 — Remote Command Expires Before Execution
- **Causes:** User issued `RING_PHONE` (`TTL = 5 minutes`), but the phone remained powered off or without signal for 20 minutes.
- **System Behavior:**
  - Background expiration sweep on `vajra-api` transitions any `RemoteCommand` where `status IN ('AUTHORIZED', 'DISPATCHED')` and `now() > expiresAt` to `status = EXPIRED`.
  - Even if the phone receives a delayed push packet at minute 20, the Android app checks `currentUtcTime > command.expiresAt`, refuses to ring the phone unexpectedly 20 minutes late, and returns a signed `CommandResult` with `executionStatus = REJECTED_EXPIRED`.

---

### Scenario 8 — Remote Command Is Rejected by the Device
- **Causes:** Invalid server signature (`REJECTED_INVALID_SIGNATURE`), replayed nonce (`REJECTED_REPLAY`), target `deviceId` mismatch, or OS restriction blocking execution.
- **System Behavior:**
  - The device refuses to execute the command, logs a local security warning, and submits a signed `CommandResult` detailing the rejection reason.
  - `vajra-api` records the rejection in `AuditLog`, transitions the command to `REJECTED` or `FAILED`, and surfaces a `TAMPER` or `RECOVERY` alert in the Web Console.

---

### Scenario 9 — Device Is Revoked
- **Trigger:** User clicks **Revoke Device** in the Web Console (`Device.lifecycleState -> REVOKED`).
- **System Behavior:**
  - All `DeviceCredential` public keys for that device are marked `active = false, revokedAt = now()`.
  - All pending `RemoteCommand` entries for that device are cancelled (`REJECTED`).
  - Any subsequent HTTP/WebSocket request from that device receives `403 Forbidden (DEVICE_REVOKED)`.
  - Upon receiving `DEVICE_REVOKED`, the endpoint agent stops polling `vajra-api` and enters an un-enrolled idle state.

---

### Scenario 10 — Device Private Key Is Compromised (or Suspected Compromised)
- **Trigger:** User marks the device `COMPROMISED`, or `vajra-api` detects anomalous concurrent requests/replay violations from the device key.
- **System Behavior:**
  1. Device immediately enters `COMPROMISED` lifecycle state (`docs/architecture/device-lifecycle.md`).
  2. A `CRITICAL` severity `TAMPER` alert is generated.
  3. The compromised key is blocked from clearing alerts, disabling Lost Mode, or updating trusted posture scores.
  4. To restore trust, the owner must revoke the old credential (`REVOKED`), remediate the endpoint, and execute a fresh enrollment ceremony (`ENROLLMENT_PENDING -> TRUSTED`) with a newly generated hardware-backed keypair.
