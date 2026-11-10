# VAJRA — Cross-Site Request Forgery (CSRF) Protection Strategy

**Document Status:** Security Architecture & Implementation Specification (Prompt 0003 — `IMPLEMENTED`)  
**Related Files:** `src/server/auth/middleware.ts`, `packages/security/src/session.ts`

---

## 1. Why `HttpOnly` Alone Does Not Prevent CSRF

Setting `HttpOnly` on a session cookie (`__Host-vajra_session` / `vajra_session`) prevents malicious JavaScript executing via Cross-Site Scripting (XSS) from reading `document.cookie`. However, `HttpOnly` does **not** prevent a browser from automatically attaching cookies to cross-origin HTTP requests initiated by a third-party website.

Therefore, VAJRA implements a **three-layer defense-in-depth CSRF strategy** for all state-changing API endpoints (`POST`, `PUT`, `PATCH`, `DELETE`).

---

## 2. Three-Layer CSRF Defense Architecture

### Layer 1 — `SameSite=Lax` + `__Host-` Cookie Prefix
- **Cookie Attributes:**
  - In HTTPS / production environments, VAJRA sets the cookie name to `__Host-vajra_session` with `HttpOnly; Secure; SameSite=Lax; Path=/`.
  - The `__Host-` prefix forces the browser to reject any cookie set with a `Domain` attribute or non-root `Path`, preventing subdomain cookie-tossing attacks.
  - `SameSite=Lax` blocks cookies from being sent on cross-site `POST`/`FETCH`/`XHR` requests while remaining compatible with top-level browser navigation in iframe/cloud preview environments.

### Layer 2 — Strict `Origin` Header Verification
- In `requireAuthenticatedUser` (`src/server/auth/middleware.ts`), for every non-safe HTTP method (`POST`, `PUT`, `PATCH`, `DELETE`):
  - If the browser includes an `Origin` header, the middleware parses `new URL(origin)` and verifies that `originUrl.host === req.headers.host`.
  - Any cross-origin mismatch is immediately rejected with `403 Forbidden (CSRF_ORIGIN_MISMATCH)` before reaching the route handler.

### Layer 3 — Cryptographic Session-Bound Synchronizer Token (`X-CSRF-Token`)
- Every `DeviceSession` row in PostgreSQL stores a cryptographic hash (`csrfTokenHash = SHA-256("vajra-session-v1:" + rawCsrfToken)`) alongside `tokenHash`.
- The `rawCsrfToken` (256-bit random Base64URL string) is returned in the JSON response body of `POST /api/auth/login`, `POST /api/auth/register`, and `GET /api/auth/me` (and in `X-Vajra-Csrf-Token` upon session rotation).
- The React SPA keeps `csrfToken` strictly in React memory (never in `localStorage` or `sessionStorage`) and attaches it in the custom `X-CSRF-Token` HTTP header on all authenticated state-changing requests (`/api/auth/logout`, `/api/auth/mfa/setup`, `/api/auth/mfa/verify`, `/api/auth/mfa/disable`, `/api/auth/recovery-codes/regenerate`, `/api/auth/password/change`).
- Because of the browser Same-Origin Policy (SOP), a third-party website cannot read the JSON response of `/api/auth/me` and cannot set a custom `X-CSRF-Token` header without triggering a CORS preflight (which `vajra-api` does not grant to external origins).
- The server verifies `X-CSRF-Token` against `session.csrfTokenHash` using constant-time comparison (`crypto.timingSafeEqual` in `verifyCsrfToken()`). Missing or invalid tokens are rejected with `403 Forbidden (CSRF_TOKEN_INVALID)`.
