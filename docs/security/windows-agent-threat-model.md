# VAJRA — Windows Agent Threat Model (Summary)

**Status:** Prompt 0014  
**Scope:** Endpoint agent on an owner-controlled Windows PC

## Assets

- Device private key (DPAPI-protected)
- Enrollment token (ephemeral; never logged)
- Signed telemetry and command receipts
- Backend trust decision (lifecycle + credential status)

## Threats & mitigations

| Threat | Mitigation |
| :--- | :--- |
| Stolen private key from disk | DPAPI LocalMachine; no export API in agent; rotate via re-enroll if compromised |
| Enrollment token theft | Single-use server token; short TTL; not written to logs |
| Replay of signed requests | Server nonce store + ±120s timestamp window |
| Malicious “server” URL via command | Base URL only from local config/identity |
| Command injection / RCE | Fixed capability matrix; no shell execution |
| Over-collection of personal data | Allowlisted event logs; redacted/truncated messages; no keylogger/screenshot |
| Impersonation after revoke | Server rejects revoked credentials; agent stops on 401/403 backoff |

## Residual risks

- DPAPI LocalMachine is weaker than TPM-bound non-exportable keys (future hardening).
- Local admin can extract DPAPI material.
- Event Log Readers may be required for richer Security-channel collection (not enabled by default).

## Permissions

- Default user/service: read Application/System logs when permitted.
- Service install requires administrator consent via `sc.exe`.
- No silent privilege escalation.
