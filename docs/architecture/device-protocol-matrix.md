# VAJRA — Cross-Platform Device Protocol Matrix

**Status:** Prompt 0016 (source-verified)  
**Applies to:** API (`packages/security`, Express middleware), Windows agent, Android companion

This document records the **actual** contract. Agents and server must stay aligned with these rules.

---

## 1. Device types & identifiers

| Field | Contract |
| :--- | :--- |
| Device type | `WINDOWS` \| `ANDROID` \| `UNKNOWN` |
| Device ID | Server-generated UUID at enrollment initiate; client binds this ID |
| Credential | Active `DeviceCredential` with `status=ACTIVE`, `active=true`, non-null public key |

---

## 2. Enrollment lifecycle

| Step | Actor | Endpoint / action |
| :--- | :--- | :--- |
| 1 | Owner (session) | `POST /api/devices/enrollment/initiate` → raw token (once), `deviceId`, `challengeNonce`, expiry (~10 min) |
| 2 | Agent | Generate ECDSA P-256 key (Windows DPAPI / Android Keystore); never upload private key |
| 3 | Agent | `POST /api/devices/enrollment/submit` with PoP signature |
| 4 | Server | Verify token, expiry, PoP, store public key as `PENDING_CONFIRMATION`; lifecycle `ENROLLMENT_PENDING` |
| 5 | Owner | `POST /api/devices/:id/enrollment/confirm` → credential `ACTIVE`, lifecycle `TRUSTED` |
| 6 | Agent | Plane-2 signed requests only after confirm (middleware rejects `ENROLLMENT_PENDING`) |
| 7 | Owner | Revoke → credentials revoked; subsequent device auth fails |

**Enrollment PoP transcript (exact):**
```text
VAJRA-ENROLL-V1|{deviceId}|{enrollmentToken.toUpperCase()}|{challengeNonce}|{publicKeyFingerprint}|{timestampIso}|{clientNonce}
```
Signed with ECDSA P-256 + SHA-256; signature **Base64 DER** (Android/Node native; Windows converts P1363→DER).

---

## 3. Plane-2 request authentication

**Headers (required):**
- `X-Vajra-Device-Id`
- `X-Vajra-Timestamp` (ISO-8601 UTC)
- `X-Vajra-Nonce` (16–128 chars)
- `X-Vajra-Signature` (Base64)

**Transcript (exact):**
```text
VAJRA-DEVICE-AUTH-V1|{METHOD}|{path}|{deviceId}|{timestampIso}|{nonce}|{sha256hex(canonicalBody)}
```

| Element | Rule |
| :--- | :--- |
| METHOD | Uppercase HTTP method |
| path | `req.originalUrl` without query (e.g. `/api/devices/{id}/heartbeat`) |
| canonicalBody | Recursive key-sorted JSON (`canonicalJsonSerialize`); empty/missing → `{}` |
| Timestamp window | ±120 seconds |
| Nonce | Consumed server-side; replay → `409 DEVICE_NONCE_REPLAYED` |
| TLS | Certificate validation required; production HTTP disabled |

**Signature:** ECDSA_P256 with SHA-256 over UTF-8 transcript bytes; **DER** encoding Base64.

---

## 4. Endpoints (device-authenticated)

| Method | Path | Purpose |
| :--- | :--- | :--- |
| POST | `/api/devices/:id/heartbeat` | Health check-in; server sets `lastHeartbeatAt` |
| GET | `/api/devices/:id/commands/pending` | Poll; response `{ commands: [...] }` |
| POST | `/api/devices/:id/commands/:commandId/acknowledge` | Ack |
| POST | `/api/devices/:id/commands/:commandId/result` | Receipt (`status`, `safeMessage`, optional `resultMetadata`) |
| POST | `/api/devices/:id/events` | Security event ingest |

Route `:id` **must** equal authenticated device ID (`assertDeviceRouteBinding`).

---

## 5. Heartbeat

- Auth: Plane-2 trusted device only.
- Server persists heartbeat row and updates device last-seen / connectivity from **server receive time**.
- Failed auth must not advance last-successful heartbeat.
- Cadence: Windows agent ~60s configurable; Android WorkManager ≥15 minutes — console “stale” thresholds should tolerate Android delays.

---

## 6. Commands

| Action | Windows | Android |
| :--- | :---: | :---: |
| `REQUEST_DEVICE_STATUS` | Yes | Yes |
| `RING_DEVICE` | No (unsupported result) | Yes (notification + ringtone) |
| `REQUEST_LOCATION` | No | No (deferred) |
| Lost mode / recovery UI | No | No |
| Shell / RCE | **Never** | **Never** |

Unsupported actions return **FAILED** with a clear `safeMessage`, not a fake COMPLETED.

Dedup: clients track processed command IDs; server enforces terminal-state immutability and legal transitions.

---

## 7. Events

- Schema-validated via event engine; size/title/description bounds enforced server-side.
- Clients must not send client risk scores (`CLIENT_RISK_SCORE_REJECTED`).
- Append-only audit chain remains server-side.

---

## 8. Prompt 0016 corrections

| Mismatch | Fix |
| :--- | :--- |
| Windows ECDSA signatures were IEEE P1363; Node expects DER | `EcdsaSignatureFormat.P1363ToDer` on Windows |
| Client body hash could disagree with server key-sorted canonical JSON | Both agents canonicalize JSON before SHA-256 |
| Docs incomplete | This matrix + agent README references |

---

## 9. Not claimed

End-to-end live enrollment/heartbeat/command against a database-backed server was **not** executed in this phase.
