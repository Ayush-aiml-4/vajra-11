# VAJRA — Windows Platform & Service Security Specification

**Target Directory:** `apps/windows-agent`  
**Target Technology:** C# / .NET 8+ Windows Service (`Microsoft.Extensions.Hosting.WindowsServices`)  
**Document Status:** Platform Engineering & Security Specification (Prompt 0014 — agent foundation `IMPLEMENTED` in `apps/windows-agent`; field validation pending on real Windows)  
**Related Documents:** `docs/product/PRD.md`, `docs/product/event-taxonomy.md`, `docs/security/device-enrollment.md`

---

## 1. Supported Windows Versions & Architecture Overview

- **Supported Operating Systems:**
  - `Windows 11` (22H2, 23H2, 24H2+ — Home, Pro, Enterprise, Education)
  - `Windows 10` (22H2 — 64-bit `x64` and `ARM64`)
- **Service Architecture:**
  - Runs as a standard, visible Windows background service registered with the Windows Service Control Manager (SCM) under the service name `VajraGuardService` (Display Name: `VAJRA Personal Security Guard`).
  - Does **not** install kernel-mode drivers (`*.sys`), does **not** inject DLLs into other processes, and does **not** hide its process or service entry from Task Manager or Services (`services.msc`).

---

## 2. Least-Privilege Execution & Cryptographic Key Storage

### 2.1 Service Account & Privilege Minimization
- **Dedicated Virtual Service Account (`NT SERVICE\VajraGuardService`):**
  - Instead of running with unrestricted `NT AUTHORITY\SYSTEM` privileges where avoidable, the service is designed to run under a dedicated, least-privilege Windows Virtual Service Account (`NT SERVICE\VajraGuardService`) added to the local **`Event Log Readers`** built-in group so it can read Windows Security and Defender event logs without needing full administrative control over the OS.
  - All unneeded Windows token privileges (such as `SeDebugPrivilege`, `SeTakeOwnershipPrivilege`, `SeLoadDriverPrivilege`) are explicitly stripped at service startup using `AdjustTokenPrivileges`.

### 2.2 Hardware-Backed Device Identity (TPM 2.0 / CNG / DPAPI)
- During enrollment (`docs/security/device-enrollment.md`), the Windows Agent generates its asymmetric device identity keypair using **Windows Cryptography API: Next Generation (CNG)**:
  - Provider: `Microsoft Platform Crypto Provider` (TPM 2.0 hardware-backed key storage) with `NCRYPT_ALLOW_EXPORT_FLAG = 0` (non-exportable private key).
  - Fallback (only if a legacy VM lacks a virtual TPM): `Microsoft Software Key Storage Provider` with private key material protected via **Windows DPAPI (`CryptProtectData`)** scoped strictly to the `NT SERVICE\VajraGuardService` machine/service security descriptor (`hardwareBacked = false` reported in `DeviceCredential`).
- Configuration files (`C:\ProgramData\Vajra\config.json`) have explicit NTFS ACLs granting write access only to `NT AUTHORITY\SYSTEM`, `BUILTIN\Administrators`, and read access to `NT SERVICE\VajraGuardService`.

---

## 3. Windows Event Log Integration & Permitted Security Sources

The Windows Agent uses `System.Diagnostics.Eventing.Reader.EventLogWatcher` (push-based XPath subscriptions) and read-only WMI/CIM queries to monitor legitimate security posture indicators.

| Telemetry Domain | Windows Event Log Channel / API Source | Event IDs / Classes Inspected | Mapped VAJRA `eventType` | Privacy Safeguards |
| :--- | :--- | :--- | :--- | :--- |
| **Interactive Logon Success** | `Security` Channel | Event ID `4624` (Logon Types `2` Interactive, `7` Unlock, `10` RemoteInteractive) | `LOGIN_SUCCESS` | Records only timestamp, logon type, and target account alias. Never captures credentials or tokens. |
| **Failed Logon Attempts** | `Security` Channel | Event ID `4625` | `LOGIN_FAILURE` | Records failure reason code and logon type. Never logs mistyped password strings. |
| **Workstation Lock / Unlock** | `Security` Channel / Session Notification | Event IDs `4800` (Locked), `4801` (Unlocked) | `DEVICE_LOCKED`, `DEVICE_UNLOCKED` | Captures lock/unlock state transition only. |
| **Windows Defender Posture** | `Microsoft-Windows-Windows Defender/Operational` & `ROOT\Microsoft\Windows\Defender` (`MSFT_MpComputerStatus`) | Event IDs `1116` (Malware detected), `5001` (Real-time protection disabled), `5007` (Config changed) | `SECURITY_CONFIGURATION_CHANGED` | Reads protection status booleans (`RealTimeProtectionEnabled`, `AntivirusEnabled`). Never modifies or disables Defender. |
| **Windows Firewall State** | `Microsoft-Windows-Windows Firewall With Advanced Security/Firewall` | Event IDs `2002`, `2003` (Profile state changed) | `SECURITY_CONFIGURATION_CHANGED` | Reads Domain/Private/Public firewall enabled state. |
| **BitLocker Encryption Status** | WMI `ROOT\CIMV2\Security\MicrosoftVolumeEncryption` / `BitLocker-API` | Read-only volume protection status check | `SECURITY_CONFIGURATION_CHANGED` | Checks whether OS drive protection is `On` or `Off`; never accesses BitLocker recovery keys. |
| **External USB Device Arrival** | `Microsoft-Windows-DriverFrameworks-UserMode/Operational` or WMI `Win32_VolumeChangeEvent` | Device arrival notification | `USB_DEVICE_DETECTED` | Records device class, vendor/product ID, and whether workstation was locked. Never reads files on the USB drive. |
| **Network Profile Changes** | `Microsoft-Windows-NetworkProfile/Operational` | Event IDs `10000` (Connected), `10001` (Disconnected) | `NETWORK_CHANGED` | Records profile category (`Public`, `Private`, `DomainConnected`) and a salted hash of the network profile ID. |

---

## 4. Service Health, Startup Behavior, Tamper-Evidence & Update Strategy

### 4.1 Startup & Service Recovery Configuration
- **Startup Type:** `Automatic (Delayed Start)` or `Automatic` so security monitoring begins on boot without slowing down initial Windows desktop sign-in.
- **SCM Failure Recovery Actions:** Configured via Windows SCM to automatically `Restart the Service` on first and second unexpected process crashes (after `60 seconds`), with a crash counter reset window of 24 hours.

### 4.2 Tamper-Evident Design (Without Rootkits or OS Bypass)
VAJRA explicitly rejects rootkit techniques (such as hooking SSDT, installing ELAM drivers without certification, or blocking legitimate local administrators). Instead, VAJRA achieves **tamper-evidence** through three legitimate mechanisms:
1. **Standard Windows Service ACLs:** Non-administrative standard users cannot stop or reconfigure `VajraGuardService`.
2. **Signed Graceful Shutdown Event (`SECURITY_AGENT_STOPPED`):** When the Windows SCM sends an `OnStop` or `OnShutdown` control signal, the agent signs and dispatches a final `SECURITY_AGENT_STOPPED` (`stopReason: SERVICE_CONTROL_STOP` or `OS_SHUTDOWN`) event before exiting.
3. **Server-Side Heartbeat Watchdog:** If an attacker with local administrator privileges kills the process (`taskkill /F`) or disables the service, the backend stops receiving signed heartbeats from the device's TPM-backed private key. Once the heartbeat grace window (e.g., 3 minutes) expires, `vajra-api` marks the device `OFFLINE`, raises a `HIGH` severity `TAMPER` / `DEVICE` alert, and notifies the owner on their other devices.

### 4.3 Windows Defender & Antivirus Compatibility
- **100% Defender Coexistence:** The VAJRA Windows Agent is purely an event-log consumer and HTTPS client. It never injects code, never hooks OS APIs, never modifies system binaries, and never adds exclusions to Windows Defender.
- **Signed Binaries:** Production agent executables must be Authenticode-signed so Windows SmartScreen and Windows Defender Application Control (WDAC) can verify publisher authenticity.

### 4.4 Firewall, Network & Update Strategy
- **Network Requirements:** Outbound HTTPS (`TCP 443`, TLS 1.3) to `vajra-api` only. The Windows Agent **never** opens any inbound listening TCP or UDP ports on the user's PC.
- **Update Strategy:** Updates are never pushed via arbitrary remote command execution. Instead, updates are distributed via signed MSI/MSIX installer packages verified against the publisher's Authenticode certificate and SHA-256 manifest before installation.
