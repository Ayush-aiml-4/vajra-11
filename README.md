# VAJRA — Intelligent Digital Security

**VAJRA** (वज्र — representing strength, protection, and resilience) is a personal cross-device cybersecurity and device-recovery platform designed to help users monitor and protect their own trusted **Windows PCs/laptops** and **Android phones** through a secure web console.

> **Ethical & Legal Scope:**  
> **VAJRA is designed to protect devices owned or explicitly authorized by the user.**  
> VAJRA is a legitimate personal-device security product. It is strictly **not** stealth spyware, offensive malware, or covert surveillance software. It operates exclusively through documented OS APIs, explicit user permissions, and hardware-backed cryptographic identity.

---

## 1. Core Responsibilities

1. **Protect (`VAJRA Guard`)** — Hardware-backed cryptographic device identity (`Device ID + Public Key + Proof`) and least-privilege posture monitoring.
2. **Detect (`VAJRA Guard`)** — Legitimate Windows and Android security event detection without collecting passwords, keystrokes, or private files.
3. **Alert (`VAJRA Alert`)** — Deduplicated, prioritized notifications across `SECURITY`, `DEVICE`, `LOCATION`, `TAMPER`, `THREAT`, `RECOVERY`, and `SYSTEM` categories (`INFO` to `CRITICAL`).
4. **Locate (`VAJRA Locate`)** — Permission-aware device location with explicit `LocationSource`, `LocationAccuracy`, `Timestamp`, and `PermissionState` (never misrepresenting `IP_APPROXIMATE` as GPS).
5. **Recover (`VAJRA Recover`)** — Step-up authorized remote phone ringing (`RING_PHONE`), Lost Mode (`ENABLE_LOST_MODE` / `DISABLE_LOST_MODE`), and a privacy-preserving Android Custom Recovery Screen (`DISPLAY_RECOVERY_MESSAGE`).
6. **Analyze Threats (`ThreatCheck` & `Risk Engine`)** — Safe URL/website analysis (`ThreatIntelProvider` abstraction with query secret redaction and SSRF protection) and explainable `0–100` deterministic risk scoring.

---

## 2. Active Technology Stack

- **Web Console:** `React 19 + TypeScript + Tailwind CSS v4 + Vite` (`src/App.tsx`, `src/lib/*`, `src/components/*`)
- **Backend Server:** `Node.js + Express + TypeScript` (`server.ts`, `src/server/*` listening on port `3000`)
- **Shared Monorepo Packages:** `@vajra/shared-types`, `@vajra/security`, `@vajra/config`
- **Database:** `PostgreSQL + Prisma ORM` (`prisma/schema.prisma`, forward-only migrations `0003`–`0007`, PostgreSQL append-only `AuditLog` trigger `trg_prevent_audit_log_mutation`; production fails closed without TLS PostgreSQL)
- **Windows Endpoint Agent:** `C# / .NET 8` Windows Worker Service (`apps/windows-agent`, DPAPI credential protection, `VAJRA-DEVICE-AUTH-V1` ECDSA P-256 signing, `REQUEST_DEVICE_STATUS` capability)
- **Android Companion App:** `Native Kotlin` Android App (`apps/android`, Android Keystore ECDSA P-256 signing, `WorkManager` heartbeat/command sync, `REQUEST_DEVICE_STATUS` and visible `RING_DEVICE` foreground service)
- **Deployment Templates (Offline Ready; Not Provisioned):** Azure App Service (Linux) + Azure Database for PostgreSQL Flexible Server + Key Vault (`infrastructure/azure/main.bicep`, `infrastructure/scripts/*`)

### Local development

```bash
cp .env.example .env
# Optional: set DATABASE_URL, SESSION_SECRET, TOTP_ENCRYPTION_KEY
npm install
npx prisma generate
npm run dev          # http://0.0.0.0:3000
```

### Production-oriented commands (configuration only; does not deploy to Azure)

```bash
npm run build
export NODE_ENV=production APP_ENV=production
export DATABASE_URL="postgresql://...&sslmode=require"
export APP_PUBLIC_ORIGIN="https://vajra.example.com"
export REQUIRE_PUBLIC_ORIGIN=true
export SESSION_SECRET="$(openssl rand -hex 32)"
export TOTP_ENCRYPTION_KEY="$(openssl rand -hex 32)"
export TRUST_PROXY=true
export VAJRA_ENABLE_DEMO_ENDPOINTS=false
# Optional only if trusted parent iframe embedding is explicitly required:
# export CSP_FRAME_ANCESTORS="https://portal.example.com"
npx prisma migrate deploy
npm run start:prod
```

Health: `GET /api/health` (liveness) · `GET /api/ready` (PostgreSQL readiness).  
**This repository does not claim that Azure resources have been provisioned or that a production cloud deployment has been executed.**

---

## 3. Source-Grounded Implementation Status (`IMPLEMENTED` / `PARTIAL` / `MOCKED` / `BLOCKED` / `NOT IMPLEMENTED`)

Every capability in this repository is classified strictly against the current source code and verification evidence (`docs/quality/final-gap-closure-0051.md`):

| Capability / Deliverable | Status | Source Evidence & Operational Scope |
| :--- | :--- | :--- |
| **Monorepo Foundation, Config & Security Primitives** | **`IMPLEMENTED`** | `packages/shared-types`, `packages/security` (Argon2id, RFC 6238 TOTP, AES-256-GCM, ECDSA P-256 `VAJRA-DEVICE-AUTH-V1`, SHA-256 hash chain), `packages/config` |
| **Health & Readiness Probes (`GET /api/health`, `GET /api/ready`)** | **`IMPLEMENTED`** | `src/server/app.ts` — liveness + bounded identity-store readiness probe without secret leakage |
| **Plane 1 Auth, Sessions, MFA, Recovery Codes & Step-Up** | **`IMPLEMENTED`** | `src/server/auth/routes.ts`, `src/server/auth/middleware.ts` — Argon2id login/register/password-change/account-delete, AES-256-GCM TOTP MFA, single-use hashed recovery codes, per-session listing/revocation, action-scoped one-time step-up grants |
| **CSP, Framing, Trusted-Proxy & CSRF Hardening** | **`IMPLEMENTED`** | `src/server/app.ts`, `src/server/auth/middleware.ts` — `script-src 'self'` (no `'unsafe-eval'`), standalone production default `frame-ancestors 'none'` + `X-Frame-Options: DENY` (or validated `https://` `CSP_FRAME_ANCESTORS`), `X-Forwarded-*` headers ignored unless `trust proxy` or verified local loopback proxy |
| **WebAuthn Passkey Runtime Ceremonies** | **`NOT IMPLEMENTED`** | `PasskeyCredential` Prisma table exists for schema readiness; runtime WebAuthn assertion routes/UI are intentionally deferred in favor of Argon2id + TOTP MFA + recovery codes |
| **Plane 2 Device Enrollment, Signatures, Heartbeats & Lifecycle** | **`IMPLEMENTED`** | `src/server/devices/routes.ts` — single-use hashed pairing tokens, Proof-of-Possession verification, owner step-up confirmation, `VAJRA-DEVICE-AUTH-V1` ±120s timestamp + atomic nonce replay defense, revocation/compromised/decommission command cancellation & fresh-key re-enrollment |
| **Security Event Engine, Risk Scoring (`0–100`) & Notifications** | **`IMPLEMENTED`** | `src/server/events/engine.ts`, `src/server/notifications/routes.ts` — signed device telemetry ingestion, metadata sanitization, deterministic risk factors, deduplicated alerts, user-scoped activity feed |
| **Plane 3 Remote Commands & Platform Capability Boundaries** | **`IMPLEMENTED` (Scoped)** | `src/server/notifications/routes.ts` — receipt-gated `REQUEST_DEVICE_STATUS` (Windows + Android) and `RING_DEVICE` (Android only); unsupported platform commands rejected server-side with `400 UNSUPPORTED_COMMAND_FOR_PLATFORM` |
| **Lost Mode (`ENABLE_LOST_MODE` / `DISABLE_LOST_MODE`)** | **`PARTIAL` (Account State)** | Transitions server-side VAJRA device lifecycle (`LOST` / `ACTIVE` / `TRUSTED`) and records owner recovery contact notice in console/audit trail; **does not** lock OS screens or track live GPS |
| **Live Device GPS / Location Tracking (`REQUEST_LOCATION`)** | **`NOT IMPLEMENTED`** | Rejected server-side (`400 UNSUPPORTED_COMMAND_FOR_PLATFORM`) and disabled on enrolled devices in UI; VAJRA never fabricates IP-geolocation as GPS |
| **On-Device Lock-Screen Recovery Banner (`DISPLAY_RECOVERY_MESSAGE`)** | **`NOT IMPLEMENTED`** | Rejected server-side (`400 UNSUPPORTED_COMMAND_FOR_PLATFORM`) and disabled on enrolled devices in UI |
| **ThreatCheck URL Inspection, History & Safe Reports Export** | **`IMPLEMENTED`** | `src/server/threatcheck/urlSafety.ts`, `src/server/notifications/routes.ts` — zero-outbound-fetch SSRF-safe lexical/destination analysis, secret query redaction, paginated history, JSON + formula-injection-safe CSV export |
| **Optional Sample Preview Inventory (`MOCK_DEVICES`)** | **`MOCKED` (Opt-In Dev Only)** | `src/data/mockFoundationData.ts`, `src/App.tsx` — enrolled inventory is empty by default; sample preview requires explicit user opt-in and `/api/demo/*` returns `404 DEMO_DISABLED` in production |
| **PostgreSQL Schema, Migrations (`0003`–`0007`) & Backup Scripts** | **`IMPLEMENTED` (`BLOCKED` Live DB Here)** | `prisma/schema.prisma`, `prisma/migrations/*`, `infrastructure/scripts/backup-postgres.sh` & `restore-postgres.sh`; live `npm run test:pg` requires a reachable disposable PostgreSQL server |
| **Windows Agent (`apps/windows-agent`) & Android Companion (`apps/android`)** | **`IMPLEMENTED` (`BLOCKED` Native Build Here)** | Full C#/.NET 8 Worker Service and Kotlin Android source, protocol tests, and packaging scripts implemented; native compilation/device execution requires Windows/.NET 8 and JDK 17/Android SDK 34 runners |

---

## 4. Documentation Index

```text
Documentation (docs/)
├── Product (docs/product/)
│   ├── PRD.md                        # Master Product Requirements Document
│   ├── event-taxonomy.md             # Canonical SecurityEvent envelope & categories
│   ├── threatcheck.md                # Safe URL analysis & query secret redaction
│   ├── risk-engine.md                # Explainable 0–100 deterministic risk scoring model
│   ├── security-timeline.md          # Chronological feed, filtering & cursor pagination
│   ├── analytics-report.md           # Persisted posture analytics & CSV/JSON export
│   ├── mvp.md                        # Minimum Viable Product scope
│   ├── roadmap.md                    # Architectural stage history
│   └── acceptance-criteria.md        # Measurable verification conditions
│
├── Architecture (docs/architecture/)
│   ├── overview.md                   # System topology & component responsibilities
│   ├── database.md                   # PostgreSQL/Prisma entities, indexes & retention rules
│   ├── device-lifecycle.md           # State machine (ENROLLMENT_PENDING -> TRUSTED -> ACTIVE -> REVOKED)
│   ├── device-protocol-matrix.md     # Windows & Android Plane-2 wire protocol & capabilities
│   ├── failure-model.md              # Offline, timeout, expiry & compromise scenarios
│   └── observability.md              # Structured logging, sanitizeLogMetadata & AuditLog
│
├── Security (docs/security/)
│   ├── security-principles.md        # Core cryptographic charter & Three-Plane Trust summary
│   ├── threat-model.md               # Threat impact & mitigation matrix
│   ├── authentication.md             # Argon2id, TOTP MFA, recovery codes, session rotation & lockout
│   ├── csrf.md                       # SameSite, Origin/Referer, trusted-proxy & X-CSRF-Token defense
│   ├── authorization-matrix.md       # Actor permission matrix across User, Device & Backend planes
│   ├── device-enrollment.md          # Pairing tokens, Proof-of-Possession & revocation ceremony
│   ├── remote-command-security.md    # Command allowlist, platform matrix, nonces & receipts
│   ├── threatcheck-limitations.md    # Zero-outbound-fetch lexical boundary & non-scanning guarantee
│   ├── privacy-model.md              # Data minimization, AES-256-GCM encryption & user controls
│   ├── production-checklist.md       # Operational pre-deployment security checklist
│   └── testing-strategy.md           # Unit, PostgreSQL, browser E2E & native agent test suites
│
├── Deployment (docs/deployment/)
│   └── azure-app-service.md          # Azure Bicep topology, Key Vault, TLS PostgreSQL & backup runbook
│
├── Quality (docs/quality/)
│   ├── functional-requirements-audit.md      # Source-grounded functional capability audit
│   ├── non-functional-requirements-audit.md  # Security, reliability, privacy & operational audit
│   ├── implementation-roadmap.md             # Remaining external hardware/cloud closure tasks
│   └── final-gap-closure-0051.md             # Prompt 0051 comprehensive security & gap closure report
│
├── API (docs/api/)
│   ├── README.md                     # API route group index
│   └── endpoints.md                  # Full REST endpoint contracts matching src/server/*
│
└── Platform (docs/platform/)
    ├── android.md                    # Android 10–15 Keystore, WorkManager, Ring & privacy model
    └── windows.md                    # Windows 10/11 SCM service, DPAPI, Event Logs & signing
```

---

## 5. Non-Negotiable Security Boundaries

VAJRA **never** implements (`packages/security/src/index.ts`):
- Stealth spyware, keylogging, password collection, or credential theft
- Hidden microphone, webcam, or covert screen recording
- Bypassing Android permissions, Windows security, or Windows Defender/antivirus
- Rootkits, evasive persistence, or privilege escalation
- Arbitrary remote shell execution (`EXECUTE_SHELL`) or arbitrary remote code execution (`DOWNLOAD_AND_EXECUTE`)
- Unauthorized intrusive vulnerability scanning against third-party websites

---

## 6. Development & Verification Commands

```bash
# Install dependencies
npm install

# Run TypeScript strict lint / typecheck and Prisma validation
npm run lint
npm run typecheck
npm run db:validate

# Audit npm dependency tree
npm run verify:audit

# Run unit, API, security & regression test suites (113 tests across 34 suites)
npm test

# Build production web bundle
npm run build

# Run headless Chromium browser E2E suite (9 end-to-end tests)
DATABASE_URL="" npm run test:e2e:browser

# Run disposable PostgreSQL integration suite (requires local PostgreSQL + VAJRA_PG_INTEGRATION=1)
VAJRA_PG_INTEGRATION=1 DATABASE_URL="postgresql://..." npm run test:pg

# Run native agent verification scripts (require Windows/.NET 8 or JDK 17 + Android SDK 34)
npm run test:windows-agent
npm run test:android-agent

# Run offline Azure deployment preflight check (contacts zero cloud resources)
./infrastructure/scripts/azure-preflight.sh
```

