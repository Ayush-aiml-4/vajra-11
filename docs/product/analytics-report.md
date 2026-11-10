# VAJRA — Analytics Summary & Security Report Export

**Status:** Implemented (Prompts 0008 / 0011 / 0012)  
**Endpoints:** `GET /api/analytics/summary`, `GET /api/reports/export?format=json|csv`  
**UI:** Overview analytics cards + export controls in `src/App.tsx`

---

## 1. Data source policy

| Source | Used in analytics/export? | Label |
| :--- | :---: | :--- |
| Persisted PostgreSQL / in-memory repo rows for the authenticated user | Yes | `dataSource: "PERSISTED"` |
| Sample/demo devices (`MOCK_DEVICES`) | No | UI-only device cards marked `isDemo` |
| Demo event scenarios (`POST /api/demo/events`) | Indirect | Creates real persisted events for the user when invoked |

Live analytics **never** silently mixes mock telemetry into counts. Empty accounts return zero totals with posture defaults (`score` 100 / `PROTECTED` when no risk assessment exists).

---

## 2. Analytics summary definitions

Response shape: `AnalyticsSummaryDto` (`packages/shared-types`).

| Field | Definition |
| :--- | :--- |
| `generatedAt` | Server ISO timestamp when the aggregate was computed |
| `dataSource` | Always `PERSISTED` for this endpoint |
| `windowDescription` | Human-readable note: latest 100 events/commands, full notification set, ThreatCheck totals |
| `accountPosture.currentScore` | Latest `RiskAssessment.score` or 100 if none |
| `accountPosture.averageDeviceRiskScore` | Mean of enrolled devices’ `currentRiskScore` (0 if no devices) |
| `devices.*` | Counts by lifecycle and platform; hardware-backed active credentials |
| `securityEvents.*` | Up to 100 recent events; breakdown by severity and category |
| `alerts.*` | Notification totals; unread = `readAt` null and `dismissedAt` null |
| `threatChecks.*` | Total count + mean `riskScore` + verdict buckets |
| `remoteCommands.*` | Up to 100 recent issuer commands by status and action type |

**Authorization:** `requireAuthenticatedUser` only; all repository calls pass `ctx.user.id`.

---

## 3. Report export

| Parameter | Rules |
| :--- | :--- |
| `format` | `json` (default) or `csv`; else `400 UNSUPPORTED_EXPORT_FORMAT` |
| `limit` | Integer 1–200 (default 100); else `400 INVALID_EXPORT_LIMIT` |

**Security controls:**

- No password hashes, TOTP secrets, recovery codes, session/CSRF hashes, or private keys.
- ThreatCheck URLs are stored redacted; export field named `submittedUrlRedacted`.
- CSV cells via `escapeCsvCellSafe()` (prefix `=` `+` `-` `@` tab/CR with `'`).
- Headers: `Content-Disposition` attachment filename, `Cache-Control: no-store`, `Pragma: no-cache`.
- Audit: `SECURITY_REPORT_EXPORTED` with format and record counts (no secrets).

---

## 4. UI behavior

- Loading, empty (zero devices/events/commands), and error states on Overview.
- Explicit **Data source: Persisted account records** line when summary is present.
- Export buttons disable while an export is in flight.

---

## 5. Limitations

- Aggregates are application-layer (not materialized warehouse cubes).
- SQL views support DBA/course evidence and optional future read models; the HTTP API uses the repository for portability with the in-memory test backend.
- Not verified against live Azure PostgreSQL unless operators run migrations and integration tests in that environment.
