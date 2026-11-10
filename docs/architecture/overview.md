# VAJRA — Architecture Overview

**Product Name:** VAJRA — Intelligent Digital Security (वज्र — strength, protection, resilience)  
**Product Category:** Personal Cross-Device Security & Recovery Platform  
**Active Web & API Stack:** `React 19 + TypeScript + Tailwind CSS v4 + Vite` (Web Console) + `Express + TypeScript` (Backend API on port `3000`)  
**Document Status:** Architecture Overview (Updated in Prompt 0008 — Security Event Engine, Risk Engine, Command Lifecycle & Heartbeat Protocol `IMPLEMENTED`)

---

## 1. High-Level System Topology

VAJRA enables an authenticated individual to monitor and protect their own trusted Windows PCs/laptops and Android phones through an encrypted, auditable, and permission-aware architecture.

```text
Android Application (Native Kotlin — PLANNED)
   │
   │  TLS 1.3 + Android Keystore Signed Payloads (Plane 2)
   ▼
Backend / API Service (Node.js / Express + TypeScript — IMPLEMENTED)
   │
   ├── PostgreSQL + Prisma ORM (Identity, Devices, SecurityEvent, Notification,
   │                             DeviceActionCommand, CommandResult, DeviceHeartbeat,
   │                             RiskAssessment & Hash-Chained AuditLog)
   │
   ├── Plane 1: User Authentication (Argon2id + TOTP MFA + Recovery Codes)
   │
   ├── Plane 2: Device Identity Service (Public Key Registry, Replay Nonce Ledger & Heartbeat)
   │
   ├── Plane 3: Stateful Command Lifecycle Engine (Allowlisted Commands, Nonces, TTL, Ack/Result)
   │
   ├── Security Event, Notification Policy & Deterministic Risk Engine (0–100 Scoring)
   │
   └── ThreatCheck Engine (URL Sanitization, SSRF Guard & Lexical/Domain Inspection)
   │
   ▼
Web Console (React 19 + TypeScript + Vite — IMPLEMENTED)
   │
   ▼
Windows Agent (C# / .NET 8+ Service — PLANNED)
```

---

## 2. Core Component Responsibilities

### 2.1 Web Console (`src/` & `apps/web` — *Shell `IMPLEMENTED`, Dashboard Telemetry `MOCKED`*)
- **Active Technology:** `React 19 + TypeScript + Tailwind CSS v4 + Vite`, served via unified `server.ts` alongside Express on port `3000` (see `apps/web/README.md`).
- **Responsibilities:**
  - Provide a unified dark cybersecurity console for **VAJRA Guard**, **VAJRA Locate**, **VAJRA Recover**, **VAJRA Alert**, **Security Timeline**, **ThreatCheck**, and **Risk Engine** explanations.
  - Enforce Plane 1 user authentication and Plane 3 step-up authentication prompts before issuing sensitive commands (`RING_PHONE`, `ENABLE_LOST_MODE`, `REQUEST_LOCATION`).
  - Clearly distinguish `IMPLEMENTED`, `MOCKED`, and `PLANNED` capabilities.

### 2.2 Backend / API Service (`src/server/app.ts` & `server.ts` — *`GET /api/health` `IMPLEMENTED`, Core Modules `PLANNED`*)
- **Active Technology:** `Node.js + Express + TypeScript` (`vajra-api`).
- **Responsibilities:**
  1. **Three-Plane Trust Enforcement:** Strictly separates User Authentication (Plane 1), Device Authentication (Plane 2), and Command Authorization (Plane 3) (`docs/security/remote-command-security.md`).
  2. **PostgreSQL Persistence (`docs/architecture/database.md`):** Manages the 15 planned entities including `User`, `UserCredential`, `Device`, `DeviceCredential`, `DeviceSession`, `SecurityEvent`, `Alert`, `LocationRecord`, `RemoteCommand`, `CommandResult`, `ThreatCheck`, `ThreatIndicator`, `RiskAssessment`, `AuditLog`, and `RecoveryProfile`.
  3. **Explainable Risk Engine (`docs/product/risk-engine.md`):** Evaluates deterministic `0–100` risk scores with itemized reasons and recommendations.
  4. **ThreatCheck (`docs/product/threatcheck.md`):** Performs safe URL analysis with query secret redaction (`?token=[REDACTED]`), SSRF protection, and pluggable `ThreatIntelProvider` adapters.

### 2.3 Windows Agent (`apps/windows-agent` — *`PLANNED`*)
- **Target Technology:** `C# / .NET 8+` Windows Service (`VajraGuardService`, `docs/platform/windows.md`).
- **Responsibilities:**
  - Generate non-exportable asymmetric keys in **Windows TPM 2.0 / CNG**.
  - Monitor documented Windows Event Logs (`4624`, `4625`, `4800`, `4801`), Windows Defender status (`5001`, `1116`), Firewall/BitLocker state, USB arrival (`USB_DEVICE_DETECTED`), and network transitions (`NETWORK_CHANGED`).
  - Maintain signed heartbeats and emit signed `SECURITY_AGENT_STOPPED` notices on service shutdown.
- **Explicit Boundaries:** Zero kernel rootkits, zero keylogging/password/file collection, 100% coexistence with Windows Defender, and zero remote shell execution (`EXECUTE_SHELL` is permanently prohibited).

### 2.4 Android Application (`apps/android` — *`PLANNED`*)
- **Target Technology:** `Native Kotlin` (`API 29+`, targeting `Android 14/15`, `docs/platform/android.md`).
- **Responsibilities:**
  - Generate hardware-backed asymmetric keys in the **Android Keystore**.
  - Report signed heartbeats, battery level, network type, Keyguard lock status, and Play Protect state.
  - Support permission-aware `VAJRA Locate` (`ANDROID_FUSED_GPS`, `ANDROID_NETWORK`), audible `RING_PHONE`, and the privacy-preserving **Custom Recovery Screen** (`ENABLE_LOST_MODE` / `DISPLAY_RECOVERY_MESSAGE`) within Android OS lockscreen boundaries.
- **Explicit Boundaries:** Never bypasses Android runtime permissions; never accesses microphone, camera, SMS, contacts, or Accessibility services.

---

## 3. Related Architecture Specifications

- [`docs/architecture/database.md`](./database.md) — 15 Planned Relational Entities & Retention Rules
- [`docs/architecture/device-lifecycle.md`](./device-lifecycle.md) — Device State Machine (`UNREGISTERED` to `DECOMMISSIONED`)
- [`docs/architecture/failure-model.md`](./failure-model.md) — Offline Buffering, Watchdog Timeouts & Failure Handling
- [`docs/architecture/observability.md`](./observability.md) — Structured Logging, Secret Redaction, Metrics & Hash-Chained Audit Trail
