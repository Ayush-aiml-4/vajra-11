# VAJRA — ThreatCheck URL Safety & SSRF Boundary Limitations (`docs/security/threatcheck-limitations.md`)

## 1. Scope & Purpose of ThreatCheck

VAJRA's ThreatCheck service (`src/server/threatcheck/urlSafety.ts` and `/api/threatcheck/*`) provides an explainable, privacy-preserving **lexical and destination-boundary inspection** for HTTP and HTTPS links submitted by an authenticated user.

Its goals are:
1. **Protocol & Syntax Validation**: Accept only valid `http:` and `https:` web links (`<= 2048` characters) and reject malformed inputs, control characters, unsupported schemes (`javascript:`, `data:`, `file:`, `ftp:`), and links with embedded credentials (`user:pass@host`).
2. **Hostname Normalization**: Parse and normalize hostnames consistently via the platform WHATWG `URL` parser, including IDNA / Punycode (`xn--`) normalization.
3. **Query-String & Fragment Redaction**: Automatically strip `#fragment` data and replace every query parameter value with `[REDACTED]` (`?token=[REDACTED]`) before writing to `ThreatCheck`, `AuditLog`, or `SecurityEvent`.
4. **Restricted Destination Boundary Classification (SSRF-Aware Lexical Defense)**: Flag links targeting local loopback, private internal networks, link-local addresses, Carrier-Grade NAT, IPv6 private/link-local ranges, IPv4-mapped IPv6 addresses, alternative integer/hex/octal IP encodings, and cloud metadata endpoints (`169.254.169.254`, `fd00:ec2::254`, `metadata.google.internal`).

---

## 2. Classification Categories

ThreatCheck distinguishes between three explicit structural classifications rather than claiming a URL is malicious based solely on its appearance:

| Classification | Verdict | Meaning |
| :--- | :--- | :--- |
| **`restricted destination`** | `HIGH RISK` | The URL points to a loopback (`127.0.0.0/8`, `[::1]`, `localhost`), private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`), link-local (`169.254.0.0/16`, `fe80::/10`), CGNAT (`100.64.0.0/10`), IPv4-mapped IPv6 (`[::ffff:127.0.0.1]`), or cloud instance metadata address (`169.254.169.254`, `[fd00:ec2::254]`, `metadata.google.internal`). |
| **`suspicious indicators`** | `SUSPICIOUS` or `HIGH RISK` | The URL exhibits lexical or structural risk signals such as unencrypted `http:`, IDNA punycode (`xn--`), direct IP literals, obfuscated IP encodings, excessive subdomain depth (`>= 5` levels), deceptive authentication lures (`login-verify`, `password-reset`), or direct executable paths (`.exe`, `.apk`, `.msi`, `.ps1`). |
| **`no obvious lexical indicators`** | `LOW RISK` | The URL uses `https:` and a standard domain structure with no obvious lexical or destination-boundary anomalies. |

---

## 3. Accurate Description of SSRF Boundary Protection

- **Zero Outbound Fetching or DNS Resolution**: During `POST /api/threatcheck/inspect`, VAJRA **never** fetches, crawls, previews, or opens the submitted URL, and **never** performs live DNS resolution.
- **What the SSRF-Aware Check Accomplishes**: Because no outbound HTTP or DNS request is made during lexical inspection, the restricted-destination checks serve two specific purposes:
  1. They prevent loopback, RFC 1918 private network, link-local, IPv6 internal, and cloud metadata addresses from being classified as ordinary public targets in user verdicts.
  2. They establish a tested, reusable destination-boundary gate (`analyzeThreatCheckUrl`) so that any future opt-in header-inspection or server-side fetch capability rejects internal targets prior to socket connection.
- **DNS Rebinding & Live Resolution Caveat**: Because DNS resolution is not performed during lexical analysis, a public-looking domain name that resolves in DNS to `127.0.0.1` or `169.254.169.254` will only be caught by DNS-level validation if a future DNS resolver step is enabled and checks the resolved IP against the same boundary rules.

---

## 4. Explicit Limitations of Lexical URL Analysis

Every ThreatCheck response includes an explicit `limitationsStatement`:

> *"Lexical URL analysis inspects only the structure, hostname, and destination address boundaries of a link without fetching the page or performing live DNS resolution. A low-risk result is not a guarantee that the destination website is safe."*

Specifically, lexical analysis **cannot** detect:
- Newly compromised legitimate websites hosting malicious JavaScript or phishing forms on a clean URL path.
- Malicious payloads behind URL shorteners or open redirects where the initial URL structure appears benign.
- Time-of-check to time-of-use (TOCTOU) content changes or cloaked pages that serve different content to browsers versus security scanners.
- Live TLS certificate revocation or domain expiration state.
