# VAJRA — Authentication & Session Security Specification

**Document Status:** Security Architecture Specification (`IMPLEMENTED` in Prompt 0003: Argon2id, RFC 6238 TOTP MFA with AES-256-GCM encryption, Single-Use Recovery Codes, Hashed Sessions, CSRF Protection, Rate Limiting & Hash-Chained Audit Log; `PARTIALLY IMPLEMENTED` / Schema Prepared: `PasskeyCredential` for WebAuthn)  
**Related Documents:** `docs/security/security-principles.md`, `docs/security/csrf.md`, `docs/security/authorization-matrix.md`, `docs/architecture/database.md`

> **Prompt 0003 Implementation Notes:**  
> - **Argon2id Parameters (`packages/security/src/password.ts`):** `Algorithm.Argon2id`, `memoryCost = 19456 KiB (19 MiB)`, `timeCost = 2`, `parallelism = 1`, `outputLen = 32`, unique 16-byte random salt per password, length policy `10–128` characters.  
> - **TOTP MFA (`packages/security/src/totp.ts`):** 160-bit Base32 secret encrypted via `AES-256-GCM` (`v1:<iv>:<authTag>:<ciphertext>`) using an HKDF-SHA256 key derived from `TOTP_ENCRYPTION_KEY` and bound to `userId` via AAD. MFA is only marked `totpEnabled = true` after the user verifies a valid 6-digit code (`POST /api/auth/mfa/verify`).  
> - **Recovery Codes (`packages/security/src/recovery-codes.ts`):** 8 codes (`XXXX-XXXX-XXXX`), displayed once at generation, stored as salted HMAC-SHA256 digests (`recoveryCodeHashes`), verified in constant time, and marked `usedAt` upon consumption.  
> - **Sessions & CSRF (`packages/security/src/session.ts` & `src/server/auth/middleware.ts`):** 256-bit random tokens stored as `SHA-256` hashes in `DeviceSession` (`15m` idle TTL, `12h` absolute TTL, rotation after `7.5m`), paired with `HttpOnly; SameSite=Lax; Path=/` (`__Host-vajra_session` + `Secure` on HTTPS) and `X-CSRF-Token` verification (`docs/security/csrf.md`).

---

## 1. Authentication Hierarchy (Plane 1)

VAJRA protects access to the user's personal device security console using phishing-resistant authentication by default:

```text
Primary (Preferred):   FIDO2 / WebAuthn Passkeys (Platform or Cross-Platform Roaming Keys)
                                    +
Fallback / Secondary:  Argon2id Password + Mandatory Second Factor (TOTP / WebAuthn Security Key)
                                    ↓
Output:                Short-Lived, Rotated, HttpOnly Session (__Host-vajra_session)
```

### 1.1 WebAuthn / Passkey Architecture
- **Relying Party (RP) Binding:** Passkey credentials (`UserCredential` with `credentialType = WEBAUTHN_PASSKEY`) are strictly bound to the VAJRA origin RP ID, neutralizing domain-spoofing phishing attacks.
- **User Verification (`uv = required`):** Passkey assertions require local biometric, PIN, or device-unlock verification on the authenticator (`userVerification: 'required'`), satisfying multi-factor assurance in a single cryptographic step.
- **Clone Detection:** `webauthnCounter` is verified and incremented on each assertion; if a signature counter regresses, the credential is flagged as potentially cloned and an alert is raised.

### 1.2 Password + Mandatory MFA Architecture
- **Argon2id Hashing:** When a password is used, it is hashed using **Argon2id** (`memoryCost >= 64 MiB`, `timeCost >= 3`, `parallelism = 4`) with a unique 16-byte random salt per credential.
- **Mandatory Second Factor:** Password verification alone **never** grants a full Web Console session. It transitions the login attempt to `MFA_REQUIRED`, requiring either a WebAuthn security key assertion or a 6-digit RFC 6238 TOTP code (whose seed is stored encrypted with AES-256-GCM in `UserCredential`).

---

## 2. Session Management, Expiration, Refresh & Token Rotation

### 2.1 Session Token Format & Storage
- **Opaque High-Entropy Tokens:** Session tokens are 256-bit cryptographically random values (`crypto.randomBytes(32)`) encoded as Base64URL.
- **Zero Raw Token Persistence:** The backend computes `tokenHash = SHA-256(rawSessionToken)` and stores only `tokenHash` in the `DeviceSession` table. Even a full database read compromise cannot yield active session cookies.
- **Cookie Security Attributes:**
  - Name: `__Host-vajra_session` (enforces `Secure`, `Path=/`, and no `Domain` attribute)
  - `HttpOnly: true` (inaccessible to `document.cookie` / XSS)
  - `Secure: true` (transmitted over HTTPS only; adapted safely for localhost test runner)
  - `SameSite: Strict` (prevents cross-site request forgery)

### 2.2 Session Expiration & Rolling Refresh Mechanism
- **Idle Timeout (`SESSION_TTL_SECONDS`):** Default **15 minutes (`900 seconds`)** of inactivity.
- **Absolute Session Lifetime:** Maximum **12 hours** from initial login, after which the user must re-authenticate regardless of activity.
- **Token Rotation:** Whenever a session is refreshed past half its idle window (e.g., after 7.5 minutes of activity), `vajra-api` issues a new session token, updates `tokenHash` with a 30-second grace window for in-flight concurrent requests, and invalidates the previous token hash.

### 2.3 Step-Up Authentication Window (Plane 3 Bridge)
- Issuing sensitive remote commands (`RING_PHONE`, `ENABLE_LOST_MODE`, `DISABLE_LOST_MODE`, `DISPLAY_RECOVERY_MESSAGE`, `REQUEST_LOCATION`) or revoking a device requires `DeviceSession.stepUpVerifiedUntil > now()`.
- Completing a fresh Passkey assertion or MFA challenge sets `stepUpVerifiedUntil = now() + 5 minutes`.

### 2.4 Logout & Instant Revocation
- **Single-Session Logout:** `POST /api/auth/logout` sets `revokedAt = now()` on the current `DeviceSession` row and clears the `__Host-vajra_session` cookie.
- **Global Session Revocation:** Users can trigger *"Sign Out All Sessions"* (or it triggers automatically upon password/passkey revocation), immediately invalidating every active `DeviceSession` row for that `userId`.

---

## 3. Account Recovery

Because VAJRA is a high-security personal platform, account recovery must not become a weak backdoor bypassing MFA:
1. **Multiple Enrolled Passkeys (Recommended):** Users are encouraged during onboarding to register at least two Passkeys (e.g., one on their primary laptop/phone and one on a backup hardware security key).
2. **One-Time Cryptographic Recovery Codes:** Upon enabling MFA/Passkeys, the user is given a set of single-use, high-entropy recovery codes (`UserCredential` with `credentialType = RECOVERY_CODE_HASH`, stored only as Argon2id/SHA-256 hashes).
3. **Cooldown & Notification on Recovery:** Using a recovery code to reset credentials triggers a `CRITICAL` security alert across all enrolled devices, revokes existing browser sessions, and imposes a 15-minute cooling period before sensitive remote commands can be dispatched.

---

## 4. Suspicious Login Detection, Rate Limiting & Brute-Force Protection

### 4.1 Rate Limiting & Progressive Backoff
- **Per-IP + Per-Account Limiter:** Maximum **5 failed login or MFA attempts** within a 15-minute sliding window.
- **Temporary Lockout:** Reaching 5 failed attempts locks password/MFA login for that account/IP combination for 15 minutes (`423 Locked`), while still allowing a previously registered hardware WebAuthn Passkey to authenticate if cryptographically valid.
- **Constant-Time Verification:** Password and hash comparisons use constant-time evaluation (`crypto.timingSafeEqual`) and perform a dummy Argon2id computation when an unknown email is submitted to prevent timing-based account enumeration.

### 4.2 Suspicious Login Detection
- Every `POST /api/auth/login` attempt is evaluated by the Security Event System:
  - Burst of $\ge 3$ `LOGIN_FAILURE` events within 5 minutes generates a `HIGH` severity `SECURITY` alert.
  - Login from an unrecognized browser user-agent or after multiple failed MFA challenges emits an `ACCOUNT_CHANGE` / `LOGIN_SUCCESS` event highlighted in the Security Timeline.
