# VAJRA — Workspace Recovery & Release Verification (Prompt 0032)

**Date:** 2026-10-10  
**Repository path:** `/tmp/vajra-durable`  
**Permissions:** `drwxr-xr-x` root:root  
**Disk:** `/tmp` on `/dev/vdc`, 50G, ~46G free (8% used)  
**Git:** **absent**. No commit history was inspected. No commit IDs are claimed.

This audit does **not** mean Windows integration passed. The real Windows agent milestone remains **BLOCKED**.

## Snapshot identity

| Item | Value |
| :--- | :--- |
| Only archive found | `/workspace/attachments/vajra-personal-security-complete.zip` |
| Zip root timestamp | `vajra-durable/` dated 2026-10-10 12:55 |
| Newest content inside zip | `docs/**/device-integration-0028.md` and `tests/prompt0028-inventory-demo.test.ts` (12:51–12:55) |
| Current tree | That zip, extracted, plus `docs/quality/device-integration-0031.md` written in Prompt 0031 |
| Recovered application code this task | **None.** No newer authoritative source was found. Unverified 0029/0030 implementations were **not** recreated from chat summaries. |
| Preserved | Prisma schema, migrations `0003`–`0007`, `package-lock.json`, `.npmrc` (`registry=https://registry.npmjs.org/`), override `deepmerge-ts@8.0.2` |
| Files in tree excluding `node_modules` / `dist` | 176 (before generated client; `node_modules` added by `npm ci`) |

Searched `/workspace`, `/tmp`, `/opt`, `/home` for other zips or `device-integration-0030.md` / `prompt0030*`. Only the attachment zip and the 0031 report under `/workspace/artifacts` exist. The zip filename does **not** imply later prompts.

## Prompt presence (source, not prior reports)

| Prompt | Present in this tree? | Evidence |
| :--- | :---: | :--- |
| 0028 inventory honesty | **Yes** | `tests/prompt0028-inventory-demo.test.ts`. `src/App.tsx` `unifiedDevices` returns enrolled devices only (`isDemo: false`). Comment: “Never present sample devices as the real inventory.” `MOCK_DEVICES` is opt-in sample preview (`showSampleDevicePreview`). Demo route gated by `DEMO_DISABLED` / `VAJRA_ENABLE_DEMO_ENDPOINTS`. |
| 0029 server capability enforcement | **Unrecovered / absent** | No `isAgentExecutableCommand`, no `UNSUPPORTED_ON_PLATFORM`. `src/server/notifications/routes.ts` still sets `simulator: true` on location/ring/recovery/status action payloads (lines near 1718, 1735, 1776, 1868). |
| 0030 PG protocol E2E test | **Unrecovered / absent** | No `tests/prompt0030-live-protocol-pg.test.ts`. `npm run test:pg` still runs only `tests/postgres-integration.test.ts`. No `docs/quality/device-integration-0030.md`. |
| 0031 evidence | **Doc only** | `docs/quality/device-integration-0031.md` records Windows agent **BLOCKED**. No agent binary was produced. |

### Missing files (need an artifact that actually contains them)

- `packages/shared-types/src/index.ts` helpers: `isAgentExecutableCommand`, `isServerLifecycleAction`, `platformUnsupportedReason` (0029)
- Server rejection of unsupported platform actions before step-up (0029 edits to `src/server/notifications/routes.ts`)
- UI gating of Locate / Windows Ring (0029 edits to `src/App.tsx`) — current UI still offers those controls
- `tests/prompt0029-capability-honesty.test.ts`
- `tests/prompt0030-live-protocol-pg.test.ts`
- `docs/quality/device-integration-0030.md`
- `docs/quality/functional-requirements-audit.md` as updated for 0029 (current copy is still titled Prompt 0027)

**Artifact needed:** a writable copy or archive of `/tmp/vajra-durable` **after** Prompts 0029 and 0030, not `vajra-personal-security-complete.zip`.

## Capability audit (static, this tree)

| Check | Result |
| :--- | :--- |
| Windows agent local matrix | `apps/windows-agent/src/Commands/CommandCapabilityMatrix.cs`: `IsExecutableOnWindows` is true **only** for `REQUEST_DEVICE_STATUS`. Location, ring, recovery UI, lost mode return explicit unsupported reasons. **Not executed** (no .NET). |
| Android companion matrix | `CommandCapabilityMatrix.kt` exists; not built (no Android SDK). |
| Server API | Still allowlists `REQUEST_LOCATION`, `RING_DEVICE`, `DISPLAY_RECOVERY_MESSAGE`, lost mode, and status. Unsupported Windows actions are **not** rejected by the server in this snapshot. |
| Inventory fallback | Real list is server `enrolledDevices` only. Sample cards are a separate opt-in preview, not the default inventory. Confirmed by passing Prompt 0028 unit tests. |
| Real device E2E | **Not claimed.** No Windows process, no protocol-client run, no PostgreSQL this session. |

## Environment

| Tool | Availability |
| :--- | :--- |
| Node | v22.23.3 |
| npm | 10.9.9 |
| Java | OpenJDK 17.0.20.1 |
| javac | `/usr/bin/javac` |
| .NET SDK | **Missing** (`dotnet` not on PATH). apt install not attempted (prior session: sandbox `setgroups`/`seteuid` denied). |
| PostgreSQL / psql | **Missing** |
| Android SDK / adb | **Missing** |
| Gradle | **Missing** (wrapper exists under `apps/android/gradlew`; SDK not present) |
| Docker | **Missing** |

## Quality gates (this session)

`npm ci --legacy-peer-deps` exit **0** (252 packages).  
`npx prisma generate` (client was not emitted by `npm ci`) exit **0**, Prisma Client 6.19.3. No schema or dependency upgrade.

| Command | Exit | Result |
| :--- | :---: | :--- |
| `npm run lint` before `prisma generate` | **1** | `PrismaClient` not exported |
| `npm test` before `prisma generate` | **1** | 17 pass / 11 fail (import crash) |
| `npm run lint` after generate | **0** | clean |
| `npm test` after generate | **0** | **77 pass / 0 fail** (27 suites). PG suite only asserts skip when `VAJRA_PG_INTEGRATION` is unset. |
| `npm run build` | **0** | Vite client build succeeded |
| `npx prisma validate` with a non-secret dummy `DATABASE_URL` | **0** | schema valid |
| `npm audit --registry https://registry.npmjs.org` | **0** | 0 vulnerabilities |
| `npm run test:pg` | **not run** | no PostgreSQL; not substituted with in-memory storage |

In-memory tests (including enrollment/heartbeat/command lifecycle in `prompt0008`) are **not** a live database or a Windows agent.

## Windows handoff (not executed)

**Prerequisites**

- Windows 10 22H2+ or Windows 11, x64 or ARM64
- .NET 8 SDK
- This repository **plus** the missing 0029/0030 tree if server-side unsupported-command rejection must match the agent
- PostgreSQL, `DATABASE_URL` for a disposable DB, `npx prisma migrate deploy`
- Express on loopback, or HTTPS if the agent is not on loopback
- Demo endpoints left disabled (`VAJRA_ENABLE_DEMO_ENDPOINTS` unset; production rejects `/demo/events`)
- No Azure deploy

**Procedure** (from `apps/windows-agent/README.md`)

```powershell
cd apps/windows-agent
dotnet restore
dotnet build -c Release
dotnet test tests/Vajra.ProtocolParity -c Release
# Console: initiate WINDOWS enrollment; capture deviceId, one-time token, challengeNonce
dotnet run -- enroll --token <TOKEN> --device-id <UUID> --challenge-nonce <HEX>
# Console/API: authenticated owner confirms; device must stay pending until then
dotnet run
# Queue REQUEST_DEVICE_STATUS for that device id
```

**Sanitized evidence a successful run must show**

- Release build exit 0; protocol test totals
- HTTP statuses only: initiate 201, submit 200, confirm 200, heartbeat 200/201, command create 201 `QUEUED`, pending 200, acknowledge 200/201, result 200/201 `COMPLETED`
- PostgreSQL: `Device.lifecycleState` in `TRUSTED`/`ACTIVE`, a `DeviceHeartbeat` row, `RemoteCommand.status=COMPLETED`, a `CommandResult` row, an audit row — IDs only, no keys or tokens
- Replay of the same device nonce rejected
- Another user’s session gets 404/403 for that device
- Agent log: `REQUEST_LOCATION` / `RING_DEVICE` not executed locally (`UnsupportedReason`)
- Explicit note that the process was `Vajra.WindowsAgent`, not a Node protocol client

## Next step

Obtain the post-0029/0030 source archive, or re-implement capability enforcement in a later prompt from the actual files (not from this summary alone). Then run the Windows procedure above on a Windows host with .NET 8 and PostgreSQL. Do not treat this audit as agent integration.
