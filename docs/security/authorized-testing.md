# VAJRA — Authorized Security Testing vs. Standard URL Checking

**Document Status:** Security Policy & Boundary Specification (Prompt 0002 — `PLANNED`)  
**Related Documents:** `docs/product/threatcheck.md`, `packages/security/src/index.ts`

---

## 1. Fundamental Policy: Defensive Analysis Only

VAJRA is a personal defensive security platform. **VAJRA must never be used to attack, exploit, brute-force, or intrusively scan third-party websites or infrastructure.**

To enforce this boundary cleanly, ThreatCheck distinguishes between two strictly separated operational modes:

---

## 2. Mode 1 — Standard URL Check (Default for All Users)

When a user submits any arbitrary URL (e.g., a link received in an email or text message) to ThreatCheck:

- **Authorization Required:** Standard authenticated VAJRA user session (no domain ownership required because the check is strictly passive/non-intrusive).
- **Permitted Operations:**
  1. Local lexical, structural, and Punycode/homograph analysis of the URL string.
  2. Passive DNS resolution (`A`, `AAAA`, `CNAME`, `TXT`) and public WHOIS/RDAP domain age lookup.
  3. Reputation lookups via configured `ThreatIntelProvider` adapters (using URL hashes, domain names, or redacted URLs).
- **Prohibited in Standard URL Check:**
  - Port scanning, directory brute-forcing, or vulnerability fuzzing.
  - Sending malformed payloads, SQL injection strings, or XSS probes.
  - Automated credential stuffing or login form submission.

---

## 3. Mode 2 — Authorized Security Audit (Strictly Gated & Passive/Header-Only)

If VAJRA ever provides deeper configuration inspection (such as inspecting a web server's public HTTP security headers—`Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`, TLS cipher configuration—for a personal domain owned by the user):

### 3.1 Mandatory Ownership / Authorization Preconditions
1. **Explicit User Attestation:** The user must explicitly confirm in the UI: *"I own this domain or have explicit written authorization from the system owner to perform a configuration audit."*
2. **Technical Domain Verification (For Repeated or Automated Audits):** Verified via a DNS `TXT` verification token (`_vajra-verify.example.com`) bound to the user's account.
3. **Immutable Audit Trail:** Every Authorized Security Audit records the user ID, target hostname, timestamp, and authorization attestation in `AuditLog`.

### 3.2 Permanent Ban on Intrusive Vulnerability Scanning
Even when a user attests ownership of a domain, VAJRA **never** implements offensive exploitation or intrusive vulnerability scanning:
- **Permitted in Authorized Security Audit:**
  - Single-request inspection of public HTTP response security headers (`HEAD` / `GET` to the root document with a transparent `User-Agent: Vajra-Security-Audit/1.0`).
  - TLS certificate chain expiration and protocol version verification.
  - Checking `/.well-known/security.txt` presence.
- **Permanently Prohibited (Even with Owner Consent):**
  - Active exploitation or payload injection (SQLi, XSS, SSRF, RCE probes).
  - High-volume crawling, stress testing, or Denial-of-Service (DoS) traffic.
  - Brute-forcing directories, subdomains, or authentication endpoints.
  - Bypassing web application firewalls (WAFs) or rate limits.

---

## 4. SSRF & Internal Network Protection

Regardless of mode, `vajra-api` enforces a strict network egress filter before performing any DNS-resolved request:
- **Blocked Destinations:**
  - Loopback addresses (`127.0.0.0/8`, `::1`, `localhost`)
  - Private RFC 1918 networks (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`)
  - Link-local & Cloud Metadata networks (`169.254.0.0/16`, `fe80::/10`, `metadata.google.internal`)
  - Carrier-grade NAT (`100.64.0.0/10`) and multicast ranges
- **DNS Rebinding Defense:** Any outbound HTTP header check resolves DNS once, validates the resulting IP address against the blocklist above, and pins the socket connection to that validated IP.
