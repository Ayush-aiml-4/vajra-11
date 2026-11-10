# VAJRA — Privacy Model, Data Minimization & Retention Specification

**Document Status:** Security & Privacy Specification (`PARTIALLY IMPLEMENTED` in Prompt 0003: Argon2id password hashes, AES-256-GCM encrypted TOTP secrets, salted HMAC-SHA256 recovery code hashes, SHA-256 session token hashes, IP `/24` truncation, and hash-chained `AuditLog` `IMPLEMENTED`; `LocationRecord` & `ThreatCheck` retention jobs `PLANNED`)  
**Related Documents:** `docs/architecture/database.md`, `docs/product/threatcheck.md`, `docs/product/PRD.md`, `docs/security/csrf.md`

---

## 1. Core Privacy Principles

VAJRA is built for personal device owners who want strong security visibility **without** sacrificing their own privacy or turning their devices into surveillance endpoints.

1. **Strict Data Minimization:** VAJRA collects only the minimum metadata necessary to verify device health, detect security anomalies, and assist with lost-device recovery.
2. **Never Collect Private Content:** VAJRA never collects, inspects, or transmits user files, photos, SMS messages, emails, chat logs, browsing history, clipboard contents, keystrokes, passwords, microphone audio, or camera feeds.
3. **Explicit OS Permission Alignment:** Optional features such as `VAJRA Locate` operate strictly when the user has granted the corresponding Windows or Android OS permission.
4. **Defense-in-Depth Secret Redaction:** Both structured telemetry (`sanitizeLogMetadata`) and ThreatCheck URLs (`redactUrlSecrets`) strip tokens, keys, and credentials before persistence or logging.

---

## 2. Sensitive Data Inventory, Protections & Retention Schedule

| Sensitive Data Category | Why It Is Collected | Storage & Cryptographic Protection | Default Retention Window | User Control |
| :--- | :--- | :--- | :--- | :--- |
| **Physical Location (`LocationRecord`)** | Enables the owner to locate a misplaced or stolen phone/laptop via `VAJRA Locate`. | Coordinates (`latitude`, `longitude`) are encrypted at the application layer using **AES-256-GCM** bound to `userId:deviceId`. Viewing requires Step-Up Auth. | **Maximum 7 days** (and capped at the latest 10 records per device) unless Lost Mode is actively enabled. | User can revoke OS location permission at any time or click *"Purge Location History"* in the Web Console. |
| **Device Identifiers (`Device`, `DeviceCredential`)** | Binds security events and commands to a specific trusted endpoint. | Uses random UUIDv4 and cryptographic public key fingerprints (`SHA-256`). Hardware serial numbers, IMEIs, IMSI, and raw MAC addresses are **never** collected. | Retained while device is enrolled; cleared upon `DECOMMISSIONED` / account deletion. | User can rename, revoke, or delete any device from the Web Console. |
| **Security Events (`SecurityEvent`)** | Powers the chronological Security Timeline, Alerting, and Risk Engine. | Sanitized via `sanitizeLogMetadata()`. Event payloads record event codes and state transitions—never passwords or file contents. | **90 days** rolling retention (configurable by user from 7 to 365 days). | User can export events or purge non-audit event history per device. |
| **IP Addresses (`DeviceSession`, `LocationRecord`)** | Protects against brute-force logins and provides optional coarse fallback location when GPS/OS location is unavailable. | Stored in truncated/privacy-minimized form (`ipAddressTruncated`, e.g., `/24` IPv4 or `/48` IPv6) for session logs; never misrepresented as GPS accuracy. | **7 days** after session expiration. | Automatically pruned by session cleanup job. |
| **Submitted ThreatCheck URLs (`ThreatCheck`)** | Allows the user to analyze suspicious links and review recent checks. | Query parameter secrets (`token=`, `key=`, `code=`, `reset=`, `password=`, etc.) are replaced with `[REDACTED]` **before** database write or provider lookup. | **30 days** rolling retention. | User can delete individual ThreatCheck records or clear all ThreatCheck history immediately. |
| **Authentication Material (`UserCredential`, `DeviceSession`)** | Verifies the human owner (Plane 1) and active browser sessions. | WebAuthn public keys, Argon2id password hashes, AES-256-GCM encrypted TOTP seeds, and SHA-256 session token hashes. Plaintext secrets are never stored. | Active while credential/session is valid; expired sessions purged after **7 days**. | User can revoke any Passkey, rotate password/MFA, or sign out all sessions. |
| **Recovery Contact Info (`RecoveryProfile`)** | Displays owner return instructions on the Android Custom Recovery Screen during Lost Mode. | Explicitly configured by the user; only displayed on the device when an authenticated `ENABLE_LOST_MODE` command is active. | Retained until edited or cleared by user. | User can leave blank, use an alias/secondary contact, or clear at any time. |
| **Security Audit Trail (`AuditLog`)** | Provides tamper-evident accountability for logins, enrollments, revocations, and remote commands. | Append-only SHA-256 hash chain (`previousEntryHash -> entryHash`) with sanitized context JSON. | **365 days** (or until full account deletion). | User can inspect and verify the hash chain in the Web Console. |

---

## 3. Comprehensive User Control Guarantees

Every user in VAJRA has direct, self-service control over their devices and data:

1. **Instant Device Revocation:** Revoking a device (`POST /api/devices/:id/revoke`) immediately invalidates its public key credentials and stops all future telemetry ingestion from that endpoint.
2. **Granular Feature Toggles:** Users can disable location reporting, USB arrival monitoring, or network change notifications per device without unenrolling the device.
3. **OS Permission Transparency:** If a user revokes location or notification permission in Android Settings or Windows Privacy Settings, the VAJRA agent respects the revocation immediately and never nags the user with deceptive popups.
4. **Full Account & Data Deletion:** When a user deletes their VAJRA account, cascading foreign-key deletion (`ON DELETE CASCADE`) permanently removes their `User`, `UserCredential`, `Device`, `DeviceCredential`, `DeviceSession`, `SecurityEvent`, `Alert`, `LocationRecord`, `RemoteCommand`, `CommandResult`, `ThreatCheck`, `ThreatIndicator`, `RiskAssessment`, `RecoveryProfile`, and associated `AuditLog` records.
