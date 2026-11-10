# VAJRA — Security Timeline Specification

**Document Status:** Product & UX Specification (Prompt 0002 — `PLANNED`, Mock preview currently in Web Console)  
**Related Documents:** `docs/product/event-taxonomy.md`, `docs/product/risk-engine.md`, `docs/security/privacy-model.md`

---

## 1. Overview & Chronological Feed Design

The **Security Timeline** provides a unified, chronological audit feed of security-relevant events across all of a user's enrolled Windows and Android devices, alongside account-level ThreatCheck and Risk Engine transitions.

### 1.1 Example Chronological Feed Sequence
```text
23:02  [INFO]     ASUS TUF F16 · Device online (Signed heartbeat verified)
23:03  [INFO]     ASUS TUF F16 · Login successful (Interactive workstation logon)
23:04  [MEDIUM]   ASUS TUF F16 · New network detected (Joined public Wi-Fi profile)
23:05  [MEDIUM]   ASUS TUF F16 · USB device detected (External mass storage connected)
23:05  [HIGH]     ASUS TUF F16 · Risk increased to HIGH (Score: 82/100)
23:05  [HIGH]     VAJRA Alert  · Alert sent: Correlated network + USB + posture change
```

---

## 2. Filtering, Grouping & Query Capabilities

### 2.1 Multi-Dimensional Filtering
Users can filter the Security Timeline in real time across four dimensions:
1. **Device Filter (`deviceId`):**
   - `All Devices` (default unified view), a specific device (e.g., `ASUS TUF F16` or `Android Phone`), or `Account / System Only` (for console logins and ThreatCheck events).
2. **Severity Filter (`severity`):**
   - Filter by minimum severity threshold (`All`, `LOW+`, `MEDIUM+`, `HIGH+`, `CRITICAL Only`) or select individual severities (`INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
3. **Category / Event Type Filter (`category` / `eventType`):**
   - `AUTHENTICATION`, `DEVICE`, `SECURITY`, `RECOVERY`, `THREATCHECK`.
4. **Time Range Filter (`from` / `to`):**
   - Presets (`Last 1 Hour`, `Last 24 Hours`, `Last 7 Days`, `Last 30 Days`) or custom UTC/local date range.

### 2.2 Intelligent Event Grouping (Burst Coalescing)
To keep the timeline readable during noisy operational bursts without losing forensic detail:
- **Routine Heartbeat Coalescing:** Routine periodic heartbeats (`HEARTBEAT_CHECK`) do not clutter the primary timeline with a new row every 60 seconds. Only **state transitions** (`DEVICE_ONLINE`, `DEVICE_OFFLINE`, `SECURITY_AGENT_STOPPED`) appear as primary rows, while continuous heartbeats are collapsed into an expandable *"Verified 60 consecutive heartbeats over the past hour"* summary indicator.
- **Repeated Event Burst Grouping:** If multiple identical events occur on the same device within a 5-minute window (e.g., 6 consecutive `LOGIN_FAILURE` events), the timeline displays a single grouped row (`LOGIN_FAILURE (×6 within 2 minutes)`) that expands on click to show each individual timestamp and `eventId`.

---

## 3. Pagination & Performance Architecture

- **Cursor-Based Pagination:** Because new security events can arrive continuously while a user is inspecting the timeline, `/api/events` uses **cursor-based pagination** (`?cursor=evt_01J9Z...&limit=50`, max `limit=100`) ordered by `(timestamp DESC, eventId DESC)` rather than offset pagination.
- **Tabular Alignment:** All timestamps (`HH:mm:ss` and ISO dates), risk scores, and event counters in the timeline UI use monospace tabular numerals (`font-mono tabular-nums`) so vertical columns remain strictly aligned.

---

## 4. Retention & Privacy Controls

1. **Default Retention Window:**
   - Standard `SecurityEvent` timeline entries are retained for **90 days** by default (configurable by the user between `7 days` and `365 days`).
   - Routine low-severity status snapshots are automatically pruned after the retention window, while `AuditLog` entries for security-sensitive actions (`DEVICE_ENROLLED`, `COMMAND_AUTHORIZED`, `DEVICE_REVOKED`) follow the audit retention policy documented in `docs/security/privacy-model.md`.
2. **Zero Sensitive Payload Storage:**
   - Timeline events never store passwords, file contents, message bodies, browsing history, or unredacted URL query tokens.
   - Users can export their own Security Timeline as JSON/CSV or purge historical non-audit telemetry when decommissioning a device.
