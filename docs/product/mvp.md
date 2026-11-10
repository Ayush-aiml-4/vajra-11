# VAJRA — Minimum Viable Product (MVP) Definition

**Document Status:** Product Scope Specification (Prompt 0002 — `PLANNED`)  
**Related Documents:** `docs/product/PRD.md`, `docs/product/roadmap.md`, `docs/product/acceptance-criteria.md`

---

## 1. MVP Objective

The VAJRA Minimum Viable Product (MVP) delivers a complete, end-to-end **personal cross-device security and recovery loop** for a single user managing their trusted Windows PC and Android phone—without cutting any cryptographic, authentication, or privacy corners, and without overloading the initial release with enterprise or complex multi-tenant features.

---

## 2. Inside MVP Scope (Core Deliverables)

### 2.1 Web Console (`React 19 + TypeScript + Vite`)
1. **Security Posture Dashboard:** Live (non-mock) device counts, online/offline counts, active alert counters, and explainable device Risk Score / Security Score cards.
2. **Device List & Enrollment Modal:** View enrolled devices (`WINDOWS`, `ANDROID`), generate a 10-minute pairing token/QR code, confirm public key fingerprints, and revoke devices.
3. **Chronological Security Timeline:** Filterable feed of canonical `SecurityEvent` and translated `SecurityActivity` records (`Authentication`, `Device`, `Protection`, `Recovery`, `ThreatCheck`) via `GET /api/activity` and `GET /api/audit`.
4. **Notification & Advisory Center:** Header notification bell with unread counter, slide-over Notification Center panel, full Alerts page (`GET /api/notifications`), read/unread/acknowledged/dismissed states, and optional browser Notification API permissions.
5. **ThreatCheck UI:** Input form to submit suspicious URLs for safe analysis (`POST /api/threatcheck/inspect`), displaying the redacted URL, `riskScore`, `riskLevel`, structural/provider indicators, and epistemic-honest recommendations while logging activity and creating notifications when suspicious/unsafe links are detected.
6. **Unified Device Control & Recovery Foundation:** Authenticated action panel to request device location (`POST /api/devices/:id/actions/locate`), trigger audible phone ring (`POST /api/devices/:id/actions/ring`), set custom recovery message (`POST /api/devices/:id/actions/recovery-message`), and enable/disable Lost Mode (`POST /api/devices/:id/actions/lost-mode`) with persistent `DeviceActionRecord` status tracking (`QUEUED_FOR_AGENT`).

### 2.2 Backend API (`Express + TypeScript + PostgreSQL / Prisma`)
1. **Health Endpoint (`IMPLEMENTED`):** `GET /api/health` (`{"status":"ok","service":"vajra-api"}`).
2. **Authentication Foundation (Plane 1):** Argon2id password + mandatory TOTP MFA and initial WebAuthn Passkey support with short-lived, rotated `__Host-vajra_session` cookies.
3. **Device Identity Foundation (Plane 2):** Single-use enrollment tokens, `DeviceCredential` public key registry (`Ed25519` / `ECDSA P-256`), and request signature verification middleware.
4. **Event Ingestion & Watchdog Foundation:** `POST /api/events` for signed heartbeats and canonical security events, plus heartbeat timeout detection (`ACTIVE -> OFFLINE`) and deterministic `RiskAssessment` / `Alert` creation.
5. **ThreatCheck Abstraction:** Built-in `LocalHeuristicProvider` (syntax, Punycode/homograph, IP literal, shortener, SSRF guard, query secret redaction) plus pluggable `ThreatIntelProvider` interface.
6. **Hash-Chained Audit Trail:** Append-only `AuditLog` recording all security-sensitive Plane 1, Plane 2, and Plane 3 operations.

### 2.3 Windows Agent (`C# / .NET 8+ Service`)
1. **Secure Enrollment:** Pairing token submission and non-exportable CNG / TPM 2.0 keypair generation.
2. **Signed Heartbeats:** Periodic cryptographically signed check-ins (`60s` default cadence) and graceful shutdown event signing (`SECURITY_AGENT_STOPPED`).
3. **Basic Security Events:** Windows Security Logon/Logoff (`4624`, `4625`, `4800`, `4801`), Windows Defender operational state (`5001`, `1116`), USB storage arrival (`USB_DEVICE_DETECTED`), and network profile changes (`NETWORK_CHANGED`).

### 2.4 Android Application (`Native Kotlin`)
1. **Secure Enrollment:** QR/token pairing and hardware-backed `AndroidKeyStore` keypair generation.
2. **Signed Heartbeat & Status:** Periodic `WorkManager` signed heartbeat reporting battery percentage, network type, and screen-lock security state.
3. **Notification Foundation:** Local security alert channel and high-priority push wakeup handling for incoming commands.
4. **Permitted Location Foundation (`VAJRA Locate`):** Opt-in foreground/background location reporting with explicit `LocationSource`, `LocationAccuracy`, `Timestamp`, and `PermissionState`.

### 2.5 Recovery Architecture (`VAJRA Recover`)
1. **Remote Ring Request (`RING_PHONE`):** Step-up authorized, signed, nonce-protected command that plays an audible alert on the Android phone and returns a signed `CommandResult` receipt.
2. **Lost Mode & Custom Recovery Screen (`ENABLE_LOST_MODE` / `DISABLE_LOST_MODE`):** Step-up authorized transition to `LOST` state displaying the privacy-preserving Custom Recovery Screen (`Owner Name`, `Recovery Contact`, `Masked Device ID`) over the locked Android Keyguard where permitted.

---

## 3. Outside MVP Scope (Deferred to Post-MVP / Future Releases)

To keep the MVP focused, secure, and verifiable, the following items are **excluded from the initial MVP**:
1. **Multi-User / Family / Enterprise RBAC:** MVP is strictly scoped to a single personal account owner managing their own devices.
2. **macOS, Linux, or iOS Native Agents:** MVP supports Windows PCs/laptops and Android phones only.
3. **Automated Third-Party Threat Feed Subscriptions Requiring Paid Commercial Keys:** MVP ships with the zero-dependency `LocalHeuristicProvider` and `ThreatIntelProvider` adapter interface; optional external providers (`VirusTotal`, `Google Safe Browsing`, `URLhaus`) are plug-in extensions.
4. **Continuous Historical Location Breadcrumb Trails / Geofencing:** MVP stores only recent location snapshots (capped at 10 records / 7 days) for lost-device recovery, avoiding continuous movement tracking.
5. **Hardware Firmware Lock / Remote Factory Reset (`Wipe`):** Deferred and excluded from MVP to prevent accidental catastrophic data loss; users are guided to use native Android Find My Device or Windows BitLocker for destructive wipe operations.
6. **Permanently Prohibited Capabilities (Never in MVP or Post-MVP):** Keylogging, credential harvesting, hidden mic/webcam/screen recording, OS/Defender bypasses, rootkits, and arbitrary remote shell execution (`EXECUTE_SHELL`).
