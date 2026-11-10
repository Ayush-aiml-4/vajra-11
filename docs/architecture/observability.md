# VAJRA — Observability, Logging & Audit Telemetry Specification

**Document Status:** Architecture Specification (Prompt 0002 — `PLANNED`, `GET /api/health` & `sanitizeLogMetadata` `IMPLEMENTED`)  
**Related Documents:** `packages/security/src/index.ts`, `docs/architecture/database.md`, `docs/security/privacy-model.md`

---

## 1. Observability Pillars & Strict Secret Redaction

Observability in a cybersecurity platform must provide high-fidelity operational insight while guaranteeing that **logs never become a secondary data leak**.

### 1.1 Mandatory Non-Logged Data Policy
VAJRA application logs, error traces, and metrics must **never** contain:
- Plaintext passwords, password hashes, or MFA/TOTP codes
- Session tokens (`__Host-vajra_session`), enrollment tokens, or CSRF tokens
- Device private keys or server signing keys
- Recovery codes or unencrypted recovery secrets
- Raw submitted ThreatCheck URLs containing query parameters (must always use redacted URLs where `token=[REDACTED]`)
- Precise physical GPS coordinates (`latitude`, `longitude`) in application stdout/stderr logs

### 1.2 Automated Sanitization via `sanitizeLogMetadata()`
Every structured log entry emitted by `vajra-api` passes its metadata object through `sanitizeLogMetadata()` (`packages/security/src/index.ts`), which automatically replaces any key matching `/(password|secret|token|key|authorization|cookie|credential)/i` with `"[REDACTED]"` and truncates oversized string fields at 512 characters.

---

## 2. Application Logs vs. Security Audit Logs

VAJRA separates transient operational logs from permanent security audit records:

| Attribute | Application Logs (Operational) | Security Audit Logs (`AuditLog` Table) |
| :--- | :--- | :--- |
| **Primary Audience** | Platform operators & debugging | Account owner (Web Console) & forensic verification |
| **Storage Medium** | Structured JSON to `stdout` / log aggregator | PostgreSQL `AuditLog` table |
| **Tamper Protection** | Standard container/host log stream | Cryptographic SHA-256 hash chain (`previousEntryHash -> entryHash`) |
| **Scope** | HTTP request latency, startup config validation, DB connection pool status, unhandled exceptions | User logins, Passkey changes, device enrollments/revocations, remote command authorizations, location views |
| **Retention** | Ephemeral / short retention (e.g., 7–14 days) | 365 days (append-only) |

### 2.1 Structured Application Log Format
```json
{
  "timestamp": "2026-10-06T18:30:00.120Z",
  "level": "INFO",
  "service": "vajra-api",
  "correlationId": "req_01J9ZB10C2D4E6F8G0H2J4K6L8",
  "method": "GET",
  "path": "/api/health",
  "statusCode": 200,
  "durationMs": 2,
  "metadata": {}
}
```

---

## 3. Correlation IDs & Request Tracing

1. **Generation & Propagation (`X-Correlation-Id`):**
   - Every incoming HTTP request to `vajra-api` is assigned a unique `correlationId` (`req_<ULID>`). If the caller supplies a valid alphanumeric `X-Correlation-Id` (1–64 chars), it is preserved; otherwise, a new ID is generated.
   - The `correlationId` is returned in the `X-Correlation-Id` response header, included in any standard error envelope, and attached to all application log lines and `AuditLog` entries produced during that request.
2. **End-to-End Command Tracing:**
   - Remote commands link `correlationId -> auditLogId -> commandId -> CommandResult.id`, allowing the user to trace an action from the Web Console button click all the way to the device's signed execution receipt.

---

## 4. Operational Metrics & Health Checks

### 4.1 Health Checks
- **`GET /api/health` (`IMPLEMENTED`):**
  - Public liveness endpoint returning strictly `{"status":"ok","service":"vajra-api"}` with zero internal state or secret exposure.
- **Internal Readiness Verification (`PLANNED` for Prompt 0003+):**
  - Verifies PostgreSQL connection pool responsiveness without exposing connection strings or database hostnames in public responses.

### 4.2 Core Security & Operational Metrics (`PLANNED`)
Metrics are aggregated as anonymous counters and histograms (never indexed by PII, email, or URL):
- `vajra_http_requests_total{route, method, status_code}`
- `vajra_http_request_duration_ms{route}`
- `vajra_auth_attempts_total{method, result}` (tracks brute-force spikes)
- `vajra_device_heartbeats_verified_total{device_type}`
- `vajra_device_signature_failures_total` (critical tamper indicator)
- `vajra_commands_dispatched_total{command_type, status}`
- `vajra_threatcheck_executions_total{risk_level, provider_status}`

---

## 5. Safe Error Tracking

- Unhandled exceptions in `vajra-api` are caught by a central Express error-handling middleware.
- **Client Response:** Returns a generic `500 Internal Server Error` with `{ "error": { "code": "INTERNAL_ERROR", "message": "An unexpected error occurred.", "correlationId": "req_..." } }`. Stack traces, SQL queries, file paths, and environment variables are **never** sent to the client.
- **Server Log:** Logs the error message, error code, and `correlationId` after passing any context object through `sanitizeLogMetadata()`.
