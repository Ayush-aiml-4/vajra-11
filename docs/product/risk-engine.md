# VAJRA — Explainable Risk Engine Specification

**Document Status:** Product & Engineering Specification (Prompt 0002 — `PLANNED`)  
**Related Documents:** `docs/product/event-taxonomy.md`, `docs/product/PRD.md`, `docs/product/threatcheck.md`

---

## 1. Core Philosophy: Deterministic & Explainable Risk Scoring

VAJRA never produces opaque, hallucinated, or unexplained AI scores. Every risk assessment calculated by VAJRA is **deterministic, auditable, and human-explainable**:
- A risk score (`0–100`) is the sum of explicit, documented contributing factors evaluated over a defined time window.
- Every point added to the risk score maps directly to a specific `SecurityEvent`, `DeviceState`, or `ThreatIndicator` with a clear human-readable reason and recommended action.
- If AI-assisted explanations are enabled in future milestones, the AI model only translates the already-computed deterministic reasons into plain language—it never invents or alters the numeric risk score.

> **Score vs. Posture Convention (Reconciling Prompt 0001 & Prompt 0002):**  
> - **Risk Score (`0–100`):** Used by the Risk Engine (`RiskAssessment`). `0` represents zero active risk indicators (`LOW` risk); `100` represents maximum active danger (`CRITICAL` risk).  
> - **Dashboard Security Score (`0–100`):** The top-level summary metric shown on the Web Console Dashboard (`98/100` in Prompt 0001 mock data) represents inverse overall health: $\text{Security Score} = 100 - \text{Weighted Average Device Risk Score}$.

---

## 2. Risk Engine Inputs

The VAJRA Risk Engine evaluates seven structured input streams for each device (and account-wide):

```text
1. Security Events        (Recent events within rolling 24h / 7d window)
2. Device State           (Defender status, Firewall state, OS lock, Encryption)
3. Authentication Events  (Failed login bursts, new session anomalies)
4. ThreatCheck Results    (High/Critical malicious URL checks on the account)
5. Tamper Signals         (Missing heartbeats, unexpected agent stops, signature errors)
6. Location Changes       (Unexpected location jumps or permission revocation in Lost Mode)
7. Device Trust State     (TRUSTED, ACTIVE, OFFLINE, LOST, COMPROMISED)
```

---

## 3. Risk Score Scale & Risk Levels

| Risk Score Range | Risk Level (`RiskLevel`) | Meaning & Operational Response |
| :--- | :--- | :--- |
| **`0 – 19`** | **`LOW`** | Nominal baseline security posture. Heartbeats verified, OS protections enabled, no active anomalies. |
| **`20 – 49`** | **`MEDIUM`** | Minor or moderate security changes detected (e.g., joined a new public Wi-Fi network, external USB device attached while unlocked). User should review when convenient. |
| **`50 – 79`** | **`HIGH`** | Multiple correlated anomalies or significant protection degradation (e.g., repeated failed logins + new network + agent configuration change). Immediate user review recommended. |
| **`80 – 100`** | **`CRITICAL`** | Active lost-device state (`LOST`), disabled core OS protection (Windows Defender turned off), suspected tamper (`SECURITY_AGENT_STOPPED` unexpectedly), or confirmed compromise (`COMPROMISED`). Urgent action required. |

---

## 4. Deterministic Scoring Rules & Weights (Initial Rule Catalog)

Scores are clamped to `[0, 100]`. Event-based contributions decay automatically once the underlying condition is resolved or acknowledged by the owner.

| Factor / Signal | Input Source | Score Weight (`+Delta`) | Decay / Reset Condition |
| :--- | :--- | :---: | :--- |
| **Unusual / Repeated Failed Logins** ($\ge 3$ in 15m) | `Authentication Events` (`LOGIN_FAILURE`) | `+25` | Decays after 24h or when user acknowledges alert after verifying activity. |
| **New / Untrusted Public Network** | `Security Events` (`NETWORK_CHANGED`) | `+15` | Resets when returning to a known private network or acknowledged. |
| **External USB Device Attached (While Locked)** | `Security Events` (`USB_DEVICE_DETECTED`) | `+20` | Decays after 24h or user acknowledgement. |
| **External USB Device Attached (While Unlocked)** | `Security Events` (`USB_DEVICE_DETECTED`) | `+10` | Decays after 12h or user acknowledgement. |
| **Agent Configuration Changed / Stopped** | `Tamper Signals` (`SECURITY_AGENT_STOPPED`) | `+30` | Resets when signed heartbeat resumes and integrity is verified. |
| **Windows Defender or Firewall Disabled** | `Device State` (`SECURITY_CONFIGURATION_CHANGED`) | `+45` | Resets immediately when signed event confirms Defender/Firewall is re-enabled. |
| **Unexpected Heartbeat Timeout (`OFFLINE`)** | `Tamper Signals` (`DEVICE_OFFLINE`) | `+20` | Resets when device reconnects with a valid signed heartbeat. |
| **Location Permission Revoked During Lost Mode** | `Location Changes` | `+25` | Resets when permission is restored or Lost Mode is disabled. |
| **Device in `LOST` Lifecycle State** | `Device Trust State` | `+50` (Minimum floor `80` / `CRITICAL`) | Resets when owner disables Lost Mode (`DISABLE_LOST_MODE`). |
| **Recent High/Critical ThreatCheck Detection** | `ThreatCheck Results` (`THREAT_DETECTED`) | `+15` | Decays after 24h or when user confirms link was not opened/credentials rotated. |

---

## 5. Canonical Risk Assessment Output Format

Every calculation produces a structured `RiskAssessment` record stored in the database and rendered in the Web Console:

### 5.1 Example Human-Readable Output
```text
Risk: 82/100
Level: HIGH (or CRITICAL threshold warning)

Reasons:
- Unusual login (+25): 4 failed workstation login attempts within 5 minutes
- New network (+15): Connected to unrecognized public Wi-Fi network
- New USB device (+12): External USB mass storage connected while workstation locked
- Agent configuration changed (+30): Windows Defender real-time monitoring state changed

Recommendation:
Review device immediately. Verify physical custody of ASUS TUF F16, confirm Windows Defender is active, and rotate credentials if login attempts were unauthorized.
```

### 5.2 Structured JSON Representation
```json
{
  "assessmentId": "rsk_01J9ZA10B2C4D6E8F0G2H4J6K8",
  "deviceId": "dev_3f8b2a10-5c4d-4e6a-9b8c-77889900aabb",
  "riskScore": 82,
  "securityScoreEquivalent": 18,
  "riskLevel": "HIGH",
  "calculatedAt": "2026-10-06T23:05:02.000Z",
  "reasons": [
    {
      "ruleId": "RULE_AUTH_UNUSUAL_LOGIN",
      "points": 25,
      "label": "Unusual login",
      "detail": "4 failed login attempts recorded within 5 minutes.",
      "sourceEventId": "evt_01J9ZA01..."
    },
    {
      "ruleId": "RULE_NET_NEW_PUBLIC",
      "points": 15,
      "label": "New network",
      "detail": "Device connected to an unrecognized public network profile.",
      "sourceEventId": "evt_01J9ZA05..."
    },
    {
      "ruleId": "RULE_HW_USB_DETECTED",
      "points": 12,
      "label": "New USB device",
      "detail": "External USB storage device attached.",
      "sourceEventId": "evt_01J9ZA08..."
    },
    {
      "ruleId": "RULE_SEC_CONFIG_CHANGE",
      "points": 30,
      "label": "Agent configuration changed",
      "detail": "Endpoint security configuration reported a posture change.",
      "sourceEventId": "evt_01J9ZA09..."
    }
  ],
  "recommendedAction": "Review device immediately."
}
```
