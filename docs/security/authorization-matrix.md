# VAJRA — Authorization Matrix (Three-Plane Access Control)

**Document Status:** Security Architecture Specification (Prompts 0002–0011D — `IMPLEMENTED` for enforced controls)  
**Related Documents:** `docs/security/security-principles.md`, `docs/security/remote-command-security.md`, `docs/security/authentication.md`

---

## 1. Principal Actors & Trust Planes

VAJRA evaluates every operation against four distinct actor roles:

1. **Unauthenticated Caller (`Public`)** — Any caller without a valid user session or device signature.
2. **Authenticated User (`Plane 1`)** — The human account owner authenticated via Web Console session (`Standard Session` vs. `Step-Up Verified Session`).
3. **Trusted Device (`Plane 2`)** — An enrolled Windows or Android endpoint signing requests with its active hardware-backed `DeviceCredential` private key (`TRUSTED` / `ACTIVE` / `LOST` state).
4. **Backend Authority (`vajra-api` / `Plane 3`)** — Internal server subsystems (Command Authorization Engine, Heartbeat Watchdog, Risk Engine, Retention Scheduler).

> **Strict Tenant & Device Isolation Rule:**  
> Even when an action is marked **Yes** for `Authenticated User` or `Trusted Device`, access is strictly scoped to **resources owned by that specific `userId`** (for Users) or **records belonging to that specific `deviceId`** (for Devices). Cross-user or cross-device lateral access is unconditionally denied (`No`).

---

## 2. Comprehensive Authorization Matrix

| Action / Operation | Unauthenticated Caller | Authenticated User (Plane 1) | Trusted Device (Plane 2) | Backend Authority (Plane 3) | Required Preconditions & Audit Rule |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **System Health** | | | | | |
| Check service liveness (`GET /api/health`) | **Yes** | **Yes** | **Yes** | **Yes** | Returns only `{"status":"ok","service":"vajra-api"}`. |
| **Account & Authentication** | | | | | |
| Initiate login / Passkey assertion | **Yes** | **Yes** | No | **Yes** | Rate-limited (`5 / 15m`); audited in `AuditLog`. |
| Register new Passkey / rotate MFA | No | **Yes (Step-Up)** | No | **Yes** | Requires fresh Step-Up Auth; emits `ACCOUNT_CHANGE`. |
| Logout / revoke own user sessions | No | **Yes** | No | **Yes** | Audited as `USER_LOGOUT`. |
| Update `RecoveryProfile` contact info | No | **Yes (Step-Up)** | No | **Yes** | Audited in `AuditLog`. |
| **Device Lifecycle & Enrollment** | | | | | |
| View own devices list & posture | No | **Yes** | No | **Yes** | Device cannot list other devices on the account. |
| Generate device enrollment token | No | **Yes (Step-Up)** | No | **Yes** | Token expires in 10 minutes; single-use. |
| Submit device public key for enrollment | No (Requires valid Enrollment Token) | No | **Yes (During Enrollment)** | **Yes** | Must include valid Proof-of-Possession signature over token + nonce. |
| Confirm device enrollment (`-> TRUSTED`) | No | **Yes (Step-Up)** | No | **Yes** | Only human owner can promote `ENROLLMENT_PENDING -> TRUSTED`. |
| Mark device `COMPROMISED` | No | **Yes** | No | **Yes (Watchdog)** | Quarantines device telemetry; raises `CRITICAL` alert. |
| Revoke device (`-> REVOKED`) | No | **Yes (Step-Up)** | No | **Yes** | Permanently invalidates `DeviceCredential` public keys. |
| Decommission revoked device | No | **Yes (Step-Up)** | No | **Yes** | Device must already be in `REVOKED` state. |
| **Telemetry, Heartbeats & Events** | | | | | |
| Submit signed device heartbeat | No | No | **Yes (Own Device Only)** | No | Verified against `DeviceCredential` public key; rejected if `REVOKED`. |
| Submit signed `SecurityEvent` | No | No | **Yes (Own Device Only)** | **Yes (System Events)** | Validated against `event-taxonomy.md` and `sanitizeLogMetadata()`. |
| Transition device `ACTIVE -> OFFLINE` on timeout | No | No | **Yes (Graceful Shutdown)** | **Yes (Watchdog)** | Backend Watchdog triggers on expired heartbeat window. |
| View Security Timeline (`GET /api/events`) | No | **Yes (Own Devices)** | No | **Yes** | Cursor-paginated; scoped to `userId`. |
| **Alerts & Risk Engine** | | | | | |
| Create `Alert` or compute `RiskAssessment` | No | No | No | **Yes** | Computed deterministically by Backend Risk/Alert Engine. |
| View active and historical alerts | No | **Yes** | No | **Yes** | Scoped to `userId`. |
| Acknowledge or resolve an alert | No | **Yes** | No | **Yes (Auto-Resolve on signed recovery)** | Compromised devices can never auto-resolve alerts. |
| **Location (`VAJRA Locate`)** | | | | | |
| Request fresh device location | No | **Yes (Step-Up)** | No | **Yes** | Creates signed `REQUEST_LOCATION` command; audited. |
| Upload encrypted `LocationRecord` | No | No | **Yes (Own Device Only)** | No | Only when OS `PermissionState` permits; encrypted at rest. |
| View device location coordinates | No | **Yes (Step-Up)** | No | **Yes** | Requires Step-Up Auth; logs `LOCATION_RECORD_VIEWED` in `AuditLog`. |
| **Remote Commands & Recovery (`VAJRA Recover`)** | | | | | |
| Request device status (`REQUEST_DEVICE_STATUS`) | No | **Yes** | No | **Yes** | Standard session allowed; signed by Backend. |
| Ring own phone (`RING_PHONE`) | No | **Yes (Step-Up)** | No | **Yes** | Requires Step-Up Auth + Nonce + Expiration + Audit record. |
| Enable Lost Mode (`ENABLE_LOST_MODE`) | No | **Yes (Step-Up)** | No | **Yes** | Transitions device to `LOST`; activates Custom Recovery Screen. |
| Disable Lost Mode (`DISABLE_LOST_MODE`) | No | **Yes (Step-Up)** | **Yes (After Local OS Keyguard Unlock)** | **Yes** | Device can only self-clear Lost Mode after owner unlocks OS Keyguard. |
| Update Recovery Screen message | No | **Yes (Step-Up)** | No | **Yes** | Dispatches `DISPLAY_RECOVERY_MESSAGE`. |
| Poll pending commands for device | No | No | **Yes (Own Device Only)** | **Yes** | Device receives only commands where `targetDeviceId === device.id`. |
| Submit signed `CommandResult` receipt | No | No | **Yes (Own Device Only)** | No | Signed by device private key; verified by Backend. |
| **ThreatCheck & Audit** | | | | | |
| Submit URL for Standard Passive ThreatCheck | No | **Yes** | No | **Yes** | Query secrets redacted; SSRF ranges blocked. |
| Run Authorized Header Security Audit | No | **Yes (With Ownership Attestation)** | No | **Yes** | Passive header/TLS check only; intrusive scanning prohibited. |
| View hash-chained `AuditLog` | No | **Yes (Own Account)** | No | **Yes** | Append-only; nobody (not even User) can edit or delete individual `AuditLog` rows. |
| **Permanently Prohibited Actions** | | | | | |
| Send arbitrary shell command (`EXECUTE_SHELL`) | **No** | **No** | **No** | **No** | Permanently banned across all planes (`@vajra/security`). |
| Upload or execute binary (`UPLOAD_EXECUTABLE`) | **No** | **No** | **No** | **No** | Permanently banned across all planes. |
| Capture keystrokes, passwords, mic, or webcam | **No** | **No** | **No** | **No** | Permanently banned across all planes. |
| Bypass OS permissions or Windows Defender | **No** | **No** | **No** | **No** | Permanently banned across all planes. |
