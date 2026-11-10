# VAJRA — Source-Grounded Functional Requirements Audit (Prompt 0051)

> Canonical copy synchronized with `docs/quality/functional-requirements-audit.md` and `docs/quality/final-gap-closure-0051.md`.

**Classification Legend:** `IMPLEMENTED` · `PARTIAL` · `MOCKED` · `BLOCKED` · `NOT IMPLEMENTED` · `VERIFIED IN THIS RUN`

| Domain | Capability | Status | Evidence |
| :--- | :--- | :---: | :--- |
| **Auth & Sessions** | Register, Argon2id Login, Logout, Session Restore, Per-Session Revocation | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | `src/server/auth/routes.ts`, `src/server/auth/middleware.ts`, unit + 9/9 Chromium E2E tests |
| **MFA & Step-Up** | TOTP MFA (AES-256-GCM), 8 Hashed Single-Use Recovery Codes, Scoped One-Time Step-Up | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | `src/server/auth/routes.ts`, `tests/prompt0049-release-acceptance.test.ts`, E2E tests 4 & 6 |
| **WebAuthn Passkeys** | Runtime Passkey Assertion Ceremonies | `NOT IMPLEMENTED` | `PasskeyCredential` schema table only; runtime routes/UI deferred |
| **Devices & Plane 2** | 3-Step PoP Enrollment, Signed Heartbeats, Nonce Replay (`409`), Revoke/Decommission + Command Cancel, Fresh-Key Re-Enrollment | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | `src/server/devices/routes.ts`, `tests/prompt0051-security-gap-closure.test.ts`, Android `rotateKey()` |
| **Remote Commands** | `REQUEST_DEVICE_STATUS` (Win + Android), `RING_DEVICE` (Android Only) — Receipt-Gated & Immutable Terminal State | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | `src/server/notifications/routes.ts` (`validateActionCapabilityForDevice`) |
| **Lost Mode** | `ENABLE_LOST_MODE` / `DISABLE_LOST_MODE` Server-Side Account State Transition | `PARTIAL` (Account State) / `VERIFIED IN THIS RUN` | Updates `Device.lifecycleState` (`LOST` <-> `ACTIVE`/`TRUSTED`) without faking `ONLINE` status or OS lock |
| **Locate & Lock Banner** | `REQUEST_LOCATION` & `DISPLAY_RECOVERY_MESSAGE` | `NOT IMPLEMENTED` | Rejected server-side (`400 UNSUPPORTED_COMMAND_FOR_PLATFORM`) & disabled on real devices in UI |
| **ThreatCheck & Reports** | Zero-Fetch SSRF-Safe URL Analysis, Redacted History, Persisted Analytics, CSV/JSON Export | `IMPLEMENTED` / `VERIFIED IN THIS RUN` | `src/server/threatcheck/urlSafety.ts`, `escapeCsvCellSafe`, E2E tests 5 & 7 |
| **Native Agents & Live PG/Cloud** | Windows `.NET 8` Agent, Android Kotlin App, Live `test:pg`, Azure Bicep Provisioning | `IMPLEMENTED` (Source) / `BLOCKED` (Host Runtime) | Runners exit `2` (`BLOCKED`) cleanly on this Linux container due to missing `.NET 8`, `JDK 17/Android SDK`, and local `postgres` daemon |
