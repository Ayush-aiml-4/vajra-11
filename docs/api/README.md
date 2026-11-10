# VAJRA — API Architecture & Endpoint Overview

**Service Name:** `vajra-api`  
**Active Runtime Stack:** Node.js + Express + TypeScript (mounted with Vite SPA in development, serving static `dist/` in production on port `3000`)  
**Document Status:** API Overview & Index (Prompt 0002)

> **Detailed Endpoint Contracts:** See [`docs/api/endpoints.md`](./endpoints.md) for the complete request/response schemas, authentication requirements, rate limits, error codes, and audit rules for every planned route.

---

## 1. Implementation Status Distinction

| Route Group | Base Path | Status | Specification Reference |
| :--- | :--- | :--- | :--- |
| **Health Check** | `GET /api/health` | **`IMPLEMENTED`** | Section 2 below & `docs/api/endpoints.md` |
| **Authentication & MFA** | `/api/auth/*` | **`IMPLEMENTED`** (Prompt 0003) | `docs/api/endpoints.md` §1 & `docs/security/authentication.md` |
| **Devices & Enrollment** | `/api/devices/*` | **`PLANNED`** (Prompt 0004) | `docs/api/endpoints.md` §2 & `docs/security/device-enrollment.md` |
| **Security Events** | `/api/events/*` | **`PLANNED`** (Prompt 0007) | `docs/api/endpoints.md` §3 & `docs/product/event-taxonomy.md` |
| **Alerts** | `/api/alerts/*` | **`PLANNED`** (Prompt 0007) | `docs/api/endpoints.md` §4 & `docs/product/PRD.md` |
| **Location (`Locate`)** | `/api/devices/:id/location*` | **`PLANNED`** (Prompt 0006/0008) | `docs/api/endpoints.md` §5 & `docs/product/PRD.md` |
| **Remote Commands** | `/api/devices/:id/commands`, `/api/commands/*` | **`PLANNED`** (Prompt 0008) | `docs/api/endpoints.md` §6 & `docs/security/remote-command-security.md` |
| **ThreatCheck** | `/api/threatcheck/*` | **`PLANNED`** (Prompt 0009) | `docs/api/endpoints.md` §7 & `docs/product/threatcheck.md` |
| **Audit Trail** | `GET /api/audit` | **`IMPLEMENTED`** (Prompt 0003) | `docs/api/endpoints.md` §8 & `docs/architecture/database.md` |

---

## 2. Currently Implemented Endpoint (`GET /api/health`)

In accordance with Prompt 0001 and Prompt 0002 security rules, **only `GET /api/health` is currently active in `src/server/app.ts`**. All other `/api/*` paths return a safe `404` JSON response (`{"error":"not_implemented_in_foundation","message":"This API endpoint is planned for a future VAJRA milestone."}`).

- **Request:** `GET /api/health`
- **Response (`200 OK`):**
```json
{
  "status": "ok",
  "service": "vajra-api"
}
```
- **Security Headers Applied:**
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: SAMEORIGIN`
  - `Referrer-Policy: no-referrer`
  - `Cache-Control: no-store`
