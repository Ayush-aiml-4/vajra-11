# VAJRA — ThreatCheck URL & Website Analysis Specification

**Document Status:** Product & Security Specification (Prompt 0002 — `PLANNED`)  
**Related Documents:** `docs/security/authorized-testing.md`, `docs/product/risk-engine.md`, `docs/security/privacy-model.md`

---

## 1. Overview & Purpose

**ThreatCheck** is VAJRA's safe URL and website threat analysis module. When a user receives a suspicious link via email, SMS, or chat, they can paste the URL (e.g., `https://example.com`) into the VAJRA Web Console to evaluate phishing, malware, and deception indicators before visiting the site on their Windows PC or Android phone.

> **Core Safety Principle:**  
> Standard ThreatCheck performs **safe, passive, and reputation-based analysis**. It never executes untrusted JavaScript on the user's device, never performs intrusive vulnerability scanning against third-party servers, and strictly blocks Server-Side Request Forgery (SSRF) against internal or private IP ranges.

---

## 2. Multi-Stage Analysis Pipeline

### Stage 1 — Local Lexical & Structural URL Analysis (Zero External Network Traffic)
Before querying any external service, VAJRA parses and inspects the URL structure locally:
1. **URL Syntax & Normalization:** Validates RFC 3986 compliance, resolves dot-segments, and extracts scheme, credentials (if embedded), hostname, port, path, and query keys.
2. **Scheme Inspection:** Flags non-HTTPS schemes (`http://`), dangerous pseudo-schemes (`javascript:`, `data:`, `file:`, `vbscript:`), or unexpected custom app schemes.
3. **Hostname & TLD Heuristics:** Detects excessive subdomain depth (e.g., `login.microsoft.com.verify-account.example.xyz`), high-entropy generated domain names (DGA-like strings), and lookalike brand tokens in subdomains.
4. **Punycode / IDN Homograph Detection:** Identifies Internationalized Domain Names (`xn--` prefix) and mixed-script Unicode characters (e.g., Cyrillic `а` substituted for Latin `a` in `pаypal.com`).
5. **IP-Based & Obfuscated Hostnames:** Flags raw IPv4 (`http://198.51.100.42/login`), IPv6, decimal/octal/hex-encoded IP hostnames, and embedded `@` userinfo tricks (`https://trusted.com@evil.example.com`).
6. **Suspicious Ports:** Flags non-standard web ports (e.g., `:8080`, `:8443`, `:4444`, `:1337`) commonly used by staging servers or command-and-control listeners.
7. **Unusual Encoding & Suspicious Query Patterns:** Detects double URL-encoding (`%252e%252e`), open-redirect parameters (`?redirect=http...`, `?next=//...`), and base64-encoded email/token blobs in query strings.
8. **URL Shortener Detection:** Matches the hostname against a maintained list of known URL shortening services (`bit.ly`, `tinyurl.com`, `t.co`, `is.gd`, etc.) to warn the user that the final destination is masked.

### Stage 2 — Passive Domain & Network Context (Where Legally & Technically Available)
For valid public domains (after passing SSRF guards blocking RFC 1918 private IPs, loopback `127.0.0.0/8`, link-local `169.254.0.0/16`, and cloud metadata endpoints):
1. **DNS Information:** Passive resolution of `A`/`AAAA`/`CNAME` records to check if the domain resolves to sinkholed, parked, or unallocated space.
2. **Domain Age & Registration Indicators:** Newly registered domains (e.g., registered $< 30\text{ days}$ ago) are weighted as elevated phishing indicators.
3. **Certificate Transparency / TLS Context:** Checks public certificate issuance history or issuer anomalies where available without intrusive scanning.
4. **Hosting & ASN Context:** Identifies whether the host resides on reputable cloud/CDN infrastructure or ASN blocks frequently associated with ephemeral phishing kits.

### Stage 3 — Pluggable Threat Intelligence (`ThreatIntelProvider` Abstraction)
VAJRA never hardcodes a single vendor into its core ThreatCheck architecture. All external threat feeds implement a uniform TypeScript interface:

```typescript
export interface ThreatIntelVerdict {
  providerId: string;
  providerName: string;
  queriedAt: string;
  status: 'CLEAN' | 'SUSPICIOUS' | 'MALICIOUS' | 'UNAVAILABLE' | 'RATE_LIMITED';
  confidenceScore: number; // 0 to 100
  categories: string[];    // e.g., ['phishing', 'malware_download', 'social_engineering']
  referenceSummary: string;
}

export interface ThreatIntelProvider {
  readonly id: string;
  readonly displayName: string;
  readonly supportsUrlHashLookup: boolean;
  analyzeUrl(sanitizedUrl: string, hostname: string): Promise<ThreatIntelVerdict>;
}
```

- **Planned Provider Adapters:**
  - `LocalHeuristicProvider` (Built-in lexical/homograph analyzer — always available offline/zero-key)
  - `GoogleSafeBrowsingProvider` (Optional adapter when configured)
  - `UrlHausProvider` (Optional abuse.ch malware URL feed adapter)
  - `VirusTotalProvider` (Optional domain/URL hash reputation adapter)
- If no external API keys are configured, ThreatCheck operates cleanly using `LocalHeuristicProvider` and passive DNS checks, explicitly stating which providers participated in the result.

---

## 3. ThreatCheck Result Model & Required Wording Discipline

Every ThreatCheck evaluation returns a structured result:

```json
{
  "threatCheckId": "tchk_01J9Z9K0M2N4P6Q8R0S2T4V6W8",
  "submittedUrlRedacted": "https://xn--pypal-4ve.com/signin?token=[REDACTED]",
  "normalizedHostname": "xn--pypal-4ve.com",
  "riskScore": 88,
  "riskLevel": "HIGH",
  "indicators": [
    {
      "code": "PUNYCODE_HOMOGRAPH_DETECTED",
      "severity": "HIGH",
      "title": "Internationalized Domain Homograph",
      "evidence": "Hostname 'xn--pypal-4ve.com' renders visually similar to a known brand using non-Latin characters."
    }
  ],
  "providerResults": [
    {
      "providerId": "local-heuristics",
      "providerName": "VAJRA Lexical & Homograph Analyzer",
      "status": "MALICIOUS",
      "confidenceScore": 90,
      "categories": ["homograph_spoofing", "phishing_indicator"]
    }
  ],
  "verdictStatement": "This URL contains indicators associated with phishing and domain impersonation.",
  "recommendation": "Do not enter credentials or personal information on this site. Close the message that delivered this link.",
  "timestamp": "2026-10-06T18:22:10.000Z"
}
```

### 3.1 ThreatCheck Risk Levels
- `SAFE` (Score `0–10`): No known threat indicators detected by active checks.
- `LOW` (Score `11–30`): Minor structural advisories (e.g., URL shortener or non-standard query parameters) without malicious reputation hits.
- `MEDIUM` (Score `31–60`): Suspicious characteristics (e.g., unencrypted `http://` login path, newly registered domain, or uncommon port).
- `HIGH` (Score `61–84`): Strong phishing or deception indicators (e.g., Punycode homograph, IP-based login URL, or suspicious provider verdict).
- `CRITICAL` (Score `85–100`): Confirmed malicious match across threat intelligence providers or severe multi-indicator credential-harvesting pattern.
- `UNKNOWN`: Analysis could not be completed (e.g., invalid URL syntax or offline providers).

### 3.2 Mandatory Epistemic Honesty (No "100% Safe" Claims)
> **CRITICAL PRODUCT RULE:**  
> ThreatCheck must **never** display or claim:  
> ❌ *"This website is 100% safe."*  
> ❌ *"Guaranteed safe to visit."*
>
> Instead, when `RiskLevel` is `SAFE`, VAJRA must use accurate, evidence-bounded language:  
> ✅ *"No known threat indicators were detected by the available checks. Always verify the sender before entering passwords or sensitive data."*
>
> When threats are found, VAJRA uses clear, evidence-backed statements:  
> ✅ *"This URL contains indicators associated with phishing."*

---

## 4. ThreatCheck Privacy & Secret Redaction Rules

URLs submitted by users frequently contain sensitive query parameters such as password-reset tokens, magic-link session keys, OAuth authorization codes, or personal email addresses.

1. **Mandatory Pre-Logging Redaction (`redactUrlSecrets`):**
   - Before a submitted URL is written to PostgreSQL (`ThreatCheck` or `AuditLog`), logged to application logs, or displayed in history lists, query parameter values matching sensitive key patterns (`token`, `key`, `secret`, `code`, `auth`, `session`, `sig`, `signature`, `password`, `pwd`, `jwt`, `access_token`, `reset`) or high-entropy bearer strings are replaced with `[REDACTED]`.
   - **Example:**
     - **Never Log:** `https://example.com/reset?token=SECRET`
     - **Always Log Safely:** `https://example.com/reset?token=[REDACTED]`
2. **External Provider Disclosure:**
   - The ThreatCheck UI clearly informs the user whether a check uses only local/hostname lookups or submits the redacted URL/hash to configured third-party `ThreatIntelProvider` services.
   - Where supported by the provider API, VAJRA prefers sending only the **hostname** or a **SHA-256 URL hash** rather than the full path and query string.
3. **User History Control:**
   - Users can delete their ThreatCheck history at any time from the Web Console.
