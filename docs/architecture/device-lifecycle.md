# VAJRA — Device Lifecycle & State Machine

**Document Status:** Architecture Specification (Prompts 0004 & 0008 — `IMPLEMENTED`)  
**Related Documents:** `docs/security/device-enrollment.md`, `docs/architecture/failure-model.md`, `docs/security/authorization-matrix.md`, `packages/security/src/device-identity.ts`, `src/server/events/engine.ts`

---

## 1. Lifecycle State Overview

Every device managed by VAJRA exists in exactly one primary lifecycle state at any given moment. No device may send accepted telemetry or receive remote commands unless its lifecycle state permits it.

### 1.1 Primary Lifecycle Progression

```text
  UNREGISTERED
       │
       │  (User initiates enrollment token in Web Console)
       ▼
ENROLLMENT_PENDING
       │
       │  (Device generates keypair, submits public key + user confirms device)
       ▼
    TRUSTED
       │
       │  (First valid signed heartbeat verified by Backend)
       ▼
    ACTIVE  ◄──────────────────────────────────────┐
       │                                           │
       │  (Heartbeat TTL expires / shutdown)       │ (Signed heartbeat resumes)
       ▼                                           │
    OFFLINE ───────────────────────────────────────┘
       │
       │  (User or security policy revokes trust)
       ▼
    REVOKED
       │
       │  (Retention archive / permanent removal)
       ▼
 DECOMMISSIONED
```

### 1.2 Special Security & Recovery States

In addition to the standard operational states above, a trusted device can transition into specialized defensive states:

```text
    TRUSTED / ACTIVE / OFFLINE
       │
       ├──────────────────────────►  LOST          (User enables Lost Mode; returns to TRUSTED/ACTIVE upon recovery)
       │
       ├──────────────────────────►  COMPROMISED   (Tamper/key compromise detected; blocks normal trust until re-enrolled or revoked)
       │
       └──────────────────────────►  REVOKED       (Cryptographic credentials permanently invalidated)
                                        │
                                        ▼
                                  DECOMMISSIONED   (Device retired from active inventory)
```

---

## 2. State Definitions

| State | Meaning | Accepts Telemetry? | Can Receive Remote Commands? |
| :--- | :--- | :---: | :---: |
| **`UNREGISTERED`** | Conceptual state before an enrollment token is bound to a device record. | No | No |
| **`ENROLLMENT_PENDING`** | User requested an enrollment token; waiting for the endpoint to submit its hardware-backed public key and for the user to confirm enrollment. | Enrollment payload only | No |
| **`TRUSTED`** | Public key is registered and confirmed by the account owner; awaiting initial or resumed signed heartbeat to transition to `ACTIVE`. | Yes (Signed) | Yes (Queued) |
| **`ACTIVE`** | Device is enrolled, trusted, and actively transmitting signed heartbeats within the expected heartbeat window. | Yes (Signed) | Yes (Immediate dispatch) |
| **`OFFLINE`** | A previously `ACTIVE` or `TRUSTED` device has missed its heartbeat window or sent a signed shutdown notice. | Yes (Re-activates on valid heartbeat) | Yes (Queued until online or command TTL expires) |
| **`LOST`** | User explicitly activated Lost Mode (`ENABLE_LOST_MODE`). High-priority recovery state: Custom Recovery Screen enabled, location reporting active (where permitted), and alerts elevated. | Yes (Signed heartbeats & location) | Yes (`RING_PHONE`, `REQUEST_LOCATION`, `DISPLAY_RECOVERY_MESSAGE`, `DISABLE_LOST_MODE`) |
| **`COMPROMISED`** | Marked by the user or automated tamper detection when a device's private key is suspected of compromise or persistent signature anomalies occur. | Quarantined (Logged for audit only; cannot clear alerts) | No (Requires revocation or full re-enrollment) |
| **`REVOKED`** | Device trust and all associated `DeviceCredential` public keys are permanently invalidated. All pending commands are cancelled. | No (`401/403` rejected) | No |
| **`DECOMMISSIONED`** | Terminal archival state for old hardware replaced by the user. Historical audit logs are retained per retention policy, but the device is hidden from the active dashboard. | No | No |

---

## 3. State Transition Matrix & Authorization Rules

Every lifecycle transition produces an immutable record in `AuditLog` and a corresponding `SecurityEvent`.

| Transition | Triggering Actor | Preconditions & Verification Required | Resulting System Actions |
| :--- | :--- | :--- | :--- |
| `UNREGISTERED` $\rightarrow$ `ENROLLMENT_PENDING` | **Authenticated User** | Active Web Console session + MFA/Passkey verified. | Generates single-use, short-lived enrollment token (`TTL = 10 minutes`). |
| `ENROLLMENT_PENDING` $\rightarrow$ `TRUSTED` | **Device + Authenticated User** | Device submits valid enrollment token + `Public Key` + attestation metadata; User confirms device name/fingerprint in Web Console. | Persists `DeviceCredential`, invalidates enrollment token, logs `DEVICE_ENROLLED` in `AuditLog`. |
| `TRUSTED` $\rightarrow$ `ACTIVE` | **Trusted Device** (verified by **Backend**) | Device sends a heartbeat with a valid cryptographic signature matching its active `DeviceCredential`. | Updates `lastHeartbeatAt`, emits `DEVICE_ONLINE` event. |
| `ACTIVE` $\rightarrow$ `OFFLINE` | **Backend Watchdog** or **Trusted Device** | Heartbeat interval expires without check-in, OR device sends signed graceful shutdown notice. | Emits `DEVICE_OFFLINE` event; generates `DEVICE` or `TAMPER` alert if unexpected. |
| `OFFLINE` $\rightarrow$ `ACTIVE` | **Trusted Device** (verified by **Backend**) | Device reconnects and submits a fresh, non-replayed signed heartbeat. | Clears transient offline state, emits `DEVICE_ONLINE` event. |
| `TRUSTED` / `ACTIVE` / `OFFLINE` $\rightarrow$ `LOST` | **Authenticated User** | Step-up command authorization (`ENABLE_LOST_MODE`). | Dispatches signed `ENABLE_LOST_MODE` command, activates recovery profile, emits `LOST_MODE_ENABLED` (`CRITICAL` alert). |
| `LOST` $\rightarrow$ `TRUSTED` / `ACTIVE` | **Authenticated User** or **Device Owner (Local OS Unlock)** | User dispatches `DISABLE_LOST_MODE` with step-up auth in Web Console, OR owner unlocks device OS Keyguard and confirms recovery in app. | Disables Custom Recovery Screen, emits `LOST_MODE_DISABLED`, resolves Lost Mode alert. |
| `TRUSTED` / `ACTIVE` / `OFFLINE` / `LOST` $\rightarrow$ `COMPROMISED` | **Authenticated User** or **Backend Security Engine** | User flags device as compromised, OR backend detects critical cryptographic/tamper invariant violation. | Suspends normal trust, alerts user on all other channels (`CRITICAL`), blocks device from resolving alerts. |
| `TRUSTED` / `ACTIVE` / `OFFLINE` / `LOST` / `COMPROMISED` $\rightarrow$ `REVOKED` | **Authenticated User** | Step-up authentication in Web Console (`Revoke Device`). | Marks all `DeviceCredential` public keys `revokedAt = now()`, cancels pending `RemoteCommand` records, rejects all future requests from device. |
| `REVOKED` $\rightarrow$ `DECOMMISSIONED` | **Authenticated User** or **Backend Retention Job** | Device is already in `REVOKED` state and user archives it. | Removes device from primary dashboard counters while preserving `AuditLog` integrity. |

---

## 4. Prohibited Transitions

1. **`REVOKED` $\rightarrow$ `TRUSTED` / `ACTIVE` is Strictly Prohibited:** A revoked credential can never be reactivated. If a user wishes to re-add a previously revoked physical device, the device must undergo a brand-new enrollment ceremony (`UNREGISTERED` $\rightarrow$ `ENROLLMENT_PENDING` $\rightarrow$ `TRUSTED`) and generate a fresh cryptographic keypair.
2. **Self-Promotion by Device is Prohibited:** A device cannot transition itself from `ENROLLMENT_PENDING` to `TRUSTED`, nor can a `COMPROMISED` device transition itself back to `ACTIVE` without explicit owner action in the Web Console.
