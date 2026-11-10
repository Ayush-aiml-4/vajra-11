# VAJRA — Android Companion Threat Model (Summary)

## Assets

- Android Keystore private key (non-exportable)
- Enrollment token (ephemeral UI input; not persisted long-term)
- Signed command receipts

## Mitigations

| Threat | Control |
| :--- | :--- |
| Key extraction | AndroidKeystore; no private key export APIs |
| MITM | System TLS trust; no custom TrustManager; cleartext only for emulator loopback in debug |
| Command injection | Fixed capability matrix; no shell |
| Malicious server URL via command | Base URL only from local settings / enrollment meta |
| Over-collection | Minimal permissions; no location in this phase |
| Stealth | Visible notifications for ring; no hidden persistence beyond WorkManager |

## Residual risk

- Compromised device / unlocked backup policies may affect app data; Keystore still hardware-backed when available.
- WorkManager delays under Doze — offline detection must tolerate Android cadence.
