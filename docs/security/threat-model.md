# VAJRA — Threat Model Foundation

**Document Status:** Initial Threat Modeling & Mitigation Matrix (Prompt 0001 — `FOUNDATION`)

This document identifies foundational security threats against the VAJRA platform, evaluates their potential impact, and defines the planned architectural mitigations. Advanced mitigations are documented for structured implementation in upcoming milestones.

---

## Threat 1: Attacker Obtains Web Credentials

- **Threat:** An attacker compromises a user's email and password through credential stuffing, phishing, or a breach on an unrelated third-party service.
- **Impact:** Unauthorized access to the user's VAJRA Web Console, exposing device inventory, security event timelines, alert history, and potentially allowing unauthorized remote command requests.
- **Potential Mitigation:**
  - Enforce mandatory Multi-Factor Authentication (MFA) and phishing-resistant WebAuthn Passkeys.
  - Rate-limit authentication endpoints and enforce Argon2id password hashing.
  - Require separate step-up authentication before dispatching any remote command.
- **Future Implementation (`PLANNED`):**
  - FIDO2/WebAuthn Passkey registration and assertion flow in `/api/auth`.
  - TOTP second-factor verification and anomalous login alerts sent to enrolled devices.

---

## Threat 2: Attacker Steals an Authentication Token

- **Threat:** An attacker intercepts or exfiltrates an active web session token (e.g., via local malware on a shared computer or XSS).
- **Impact:** Session hijacking for the remaining validity window of the token, allowing the attacker to view console telemetry as the authenticated user.
- **Potential Mitigation:**
  - Issue short-lived session tokens (e.g., 15-minute TTL) stored in `HttpOnly`, `Secure`, `SameSite=Strict` cookies rather than `localStorage`.
  - Store only SHA-256 hashes of session tokens in PostgreSQL so database read leaks do not yield usable tokens.
  - Require cryptographic step-up confirmation for sensitive state changes or remote commands.
- **Future Implementation (`PLANNED`):**
  - Short-lived rotating session middleware with instant revocation endpoints (`/api/auth/revoke`).
  -Strict Content Security Policy (CSP) headers on the Web Console.

---

## Threat 3: Attacker Attempts to Impersonate a Device

- **Threat:** An adversary discovers a valid `deviceId` and attempts to send forged heartbeats (`ONLINE` status) or fake `SecurityEvent` records to mask a compromised or stolen device.
- **Impact:** False security posture reported in the Web Console; suppression of offline alerts or injection of misleading telemetry.
- **Potential Mitigation:**
  - Require asymmetric cryptographic device identity (`Device ID + Public Key + Registration Metadata`).
  - Reject any telemetry or heartbeat request that does not carry a valid cryptographic signature over the payload and timestamp using the device's registered private key.
- **Future Implementation (`PLANNED`):**
  - Hardware-backed key generation in the Windows Agent (TPM/CNG) and Android App (Android Keystore).
  - Signature verification middleware on `/api/devices/:id/heartbeat`, `/api/devices/:id/events`, and agent command endpoints. Route `:id` is bound to the authenticated device identity.

---

## Threat 4: Attacker Sends Unauthorized Remote Commands

- **Threat:** An attacker attempts to trigger remote actions (such as ringing the user's phone repeatedly or displaying spoofed recovery messages) by calling command endpoints directly or escalating privileges.
- **Impact:** Harassment of the device owner, nuisance disruption, or display of deceptive recovery instructions on the device screen.
- **Potential Mitigation:**
  - Strict separation of user authentication, device authentication, and command authorization.
  - Hard-code an explicit enum allowlist of safe commands (`RING_DEVICE`, `LOST_MODE_MESSAGE`, `REQUEST_HEARTBEAT`, `VERIFY_INTEGRITY`). Prohibit arbitrary shell/code execution (`PROHIBITED_CAPABILITIES`).
  - Cryptographically sign authorized commands on the backend and verify signatures on the endpoint agent.
- **Future Implementation (`PLANNED`):**
  - Step-up MFA/Passkey challenge required per sensitive command in `/api/commands`.
  - End-to-end command signature verification inside the Android and Windows agents.

---

## Threat 5: Someone Attempts to Disable the Windows Agent

- **Threat:** A local intruder or malicious process on the user's Windows PC attempts to stop, uninstall, or kill the VAJRA Windows Agent service to prevent security event reporting.
- **Impact:** Loss of real-time telemetry from the Windows endpoint.
- **Potential Mitigation:**
  - **Without resorting to rootkits or OS security bypasses**, use standard Windows Service recovery policies, restricted service ACLs (requiring administrative consent to stop), and server-side **tamper-evident heartbeat monitoring**.
  - If the backend ceases to receive signed heartbeats within the expected interval, or receives a Windows Service Control Manager shutdown event, the backend immediately transitions the device status to `OFFLINE` / `TAMPER_DETECTED` and alerts the user on their other devices.
- **Future Implementation (`PLANNED`):**
  - Server-side heartbeat watchdog timer and missing-heartbeat alert generation.
  - Signed service lifecycle events in the C# / .NET Windows Agent.

---

## Threat 6: Someone Obtains Access to the Backend

- **Threat:** An attacker gains unauthorized read/write access to the backend server or PostgreSQL database.
- **Impact:** Potential exposure of user metadata, device inventory, or attempts to issue malicious commands to connected devices.
- **Potential Mitigation:**
  - Never store device private keys on the backend (only public keys are stored).
  - Never store plaintext passwords or raw session tokens in PostgreSQL.
  - Strictly disallow arbitrary remote code/shell execution in the agent binaries—even a completely compromised backend cannot instruct a Windows or Android agent to execute shell commands, keyloggers, or spyware because the agents only contain code for the allowlisted safe actions (`RING_DEVICE`, etc.).
  - Encrypt sensitive records (like opt-in location coordinates) at rest and maintain a hash-chained `AuditLog`.
- **Future Implementation (`PLANNED`):**
  - Application-layer AES-256-GCM encryption for sensitive database columns.
  - Hardened agent command parser that rejects any command outside the compiled enum allowlist.

---

## Threat 7: Malicious URL Is Submitted to ThreatCheck

- **Threat:** A user (or attacker) submits a specially crafted malicious URL to the ThreatCheck feature that targets the backend via Server-Side Request Forgery (SSRF), command injection, or oversized response payloads.
- **Impact:** Backend network scanning of internal cloud metadata services (`169.254.169.254`), localhost port scanning, or denial of service.
- **Potential Mitigation:**
  - Never blindly fetch or render submitted URLs inside an unisolated backend process or headless browser.
  - Strictly parse and validate URL syntax, block private/loopback/link-local IP ranges (RFC 1918, RFC 4193, `127.0.0.0/8`, `169.254.0.0/16`), and rely on passive reputation APIs, lexical analysis, and sandboxed AI explanation rather than direct active execution.
- **Future Implementation (`PLANNED`):**
  - Strict URL validator and SSRF-safe reputation analyzer in `/api/threatcheck`.

---

## Threat 8: Replay of an Old Remote Command

- **Threat:** An attacker captures a previously valid, signed `RING_DEVICE` or `LOST_MODE_MESSAGE` command packet in transit and replays it hours or days later.
- **Impact:** Repeated unauthorized triggering of a previously completed defensive action.
- **Potential Mitigation:**
  - Every `RemoteCommand` envelope must include a cryptographically random, single-use `cryptographicNonce`, an `issuedAt` timestamp, and a short `expiresAt` timestamp (e.g., 5 minutes).
  - Both the backend and the endpoint agent maintain a cache of recently executed command IDs/nonces and reject any command whose nonce has already been processed or whose `expiresAt` timestamp has passed.
- **Future Implementation (`PLANNED`):**
  - Nonce uniqueness constraint in PostgreSQL (`RemoteCommand.cryptographicNonce`) and local ring-buffer nonce cache in the Windows and Android agents.


## Prompt 0011D Enforcement Notes

- Plane-2 event ingestion: `POST /api/devices/:id/events` with full signature + nonce + route binding.
- Command receipts are idempotent; terminal states (COMPLETED/FAILED/EXPIRED/CANCELLED) cannot be overwritten.
- MFA step-up: `POST /api/auth/step-up` grants a 5-minute, session-bound, action-scoped authorization. Protected operations return `403 STEP_UP_REQUIRED` when the grant is missing, expired, or scoped to a different action.
- No real device agent is shipped; device-execution commands remain QUEUED until a valid signed `CommandResult` is accepted.
