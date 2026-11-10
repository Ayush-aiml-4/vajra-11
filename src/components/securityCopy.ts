/**
 * VAJRA — Human-Readable Security Copywriting & Event Translation
 * Translates internal event identifiers, lifecycle states, and ThreatCheck URL heuristics
 * into calm, trustworthy consumer/prosumer security language.
 */

export interface TranslatedSecurityActivity {
  title: string;
  subtitle?: string;
  description: string;
  category: 'Authentication' | 'Device' | 'Protection' | 'Recovery' | 'ThreatCheck';
  severity: 'Healthy' | 'Information' | 'Attention' | 'Critical';
  relativeTime: string;
  clockTime: string;
}

export function formatRelativeTime(isoString: string | null | undefined): string {
  if (!isoString) return 'Recently';
  const parsed = Date.parse(isoString);
  if (Number.isNaN(parsed)) return 'Recently';

  const diffSeconds = Math.max(0, Math.floor((Date.now() - parsed) / 1000));
  if (diffSeconds < 45) return 'Just now';
  const diffMinutes = Math.floor(diffSeconds / 60);
  if (diffMinutes < 60) return `${diffMinutes} min ago`;
  const diffHours = Math.floor(diffMinutes / 60);
  if (diffHours < 24) return `${diffHours} hr ago`;
  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays}d ago`;
}

export function formatClockTime(isoString: string | null | undefined): string {
  if (!isoString) return 'Just now';
  const parsed = Date.parse(isoString);
  if (Number.isNaN(parsed)) return 'Recently';
  return new Date(parsed).toLocaleTimeString([], {
    hour: 'numeric',
    minute: '2-digit',
  });
}

export function getContextualGreeting(): string {
  const hour = new Date().getHours();
  if (hour < 12) return 'Good morning';
  if (hour < 18) return 'Good afternoon';
  return 'Good evening';
}

export function formatDeviceLifecycleLabel(state: string): {
  label: string;
  tone: 'protected' | 'warning' | 'critical' | 'neutral';
  summary: string;
} {
  switch (state) {
    case 'ACTIVE':
    case 'TRUSTED':
      return {
        label: 'Protected',
        tone: 'protected',
        summary: 'Identity verified and actively protected by VAJRA.',
      };
    case 'ENROLLMENT_PENDING':
      return {
        label: 'Setup in progress',
        tone: 'warning',
        summary: 'Waiting for device connection and owner approval.',
      };
    case 'OFFLINE':
      return {
        label: 'Offline',
        tone: 'neutral',
        summary: 'Device is currently offline. Protection resumes when connected.',
      };
    case 'LOST':
      return {
        label: 'Lost Mode',
        tone: 'critical',
        summary: 'Recovery protection is active on this device.',
      };
    case 'COMPROMISED':
      return {
        label: 'Needs attention',
        tone: 'critical',
        summary: 'Unusual device activity flagged. Trust is paused until reviewed.',
      };
    case 'REVOKED':
      return {
        label: 'Disconnected',
        tone: 'neutral',
        summary: 'Access to your VAJRA account has been permanently removed.',
      };
    case 'DECOMMISSIONED':
      return {
        label: 'Archived',
        tone: 'neutral',
        summary: 'Retired from your active devices.',
      };
    default:
      return {
        label: 'Protected',
        tone: 'protected',
        summary: 'Connected to your VAJRA account.',
      };
  }
}

export function translateAuditEventToHuman(
  eventType: string,
  timestampIso: string,
  metadata?: Record<string, unknown>
): TranslatedSecurityActivity {
  const deviceName =
    typeof metadata?.deviceName === 'string' && metadata.deviceName.trim().length > 0
      ? metadata.deviceName
      : 'your device';

  const base = {
    relativeTime: formatRelativeTime(timestampIso),
    clockTime: formatClockTime(timestampIso),
  };

  switch (eventType) {
    case 'ACCOUNT_CREATED':
      return {
        ...base,
        title: 'VAJRA account created',
        description: 'Your personal security console was initialized and secured.',
        category: 'Authentication',
        severity: 'Healthy',
      };
    case 'LOGIN_SUCCESS':
      return {
        ...base,
        title: 'New sign-in verified',
        description: 'You signed in to your VAJRA security console.',
        category: 'Authentication',
        severity: 'Information',
      };
    case 'LOGIN_FAILURE':
      return {
        ...base,
        title: 'Unrecognized sign-in blocked',
        description: 'An incorrect password attempt was blocked from accessing your account.',
        category: 'Authentication',
        severity: 'Attention',
      };
    case 'ACCOUNT_LOCKED':
      return {
        ...base,
        title: 'Sign-in protection activated',
        description: 'Account sign-in was temporarily paused after repeated failed attempts.',
        category: 'Authentication',
        severity: 'Critical',
      };
    case 'LOGOUT':
      return {
        ...base,
        title: 'Signed out safely',
        description: 'Your web console session was closed.',
        category: 'Authentication',
        severity: 'Information',
      };
    case 'MFA_SETUP_STARTED':
      return {
        ...base,
        title: 'Two-step verification started',
        description: 'Authenticator app setup was initiated for your account.',
        category: 'Authentication',
        severity: 'Information',
      };
    case 'MFA_ENABLED':
      return {
        ...base,
        title: 'Two-step verification enabled',
        description: 'Your account is now protected with an authenticator app and recovery codes.',
        category: 'Authentication',
        severity: 'Healthy',
      };
    case 'MFA_DISABLED':
      return {
        ...base,
        title: 'Two-step verification turned off',
        description: 'Authenticator verification was removed from your account.',
        category: 'Authentication',
        severity: 'Attention',
      };
    case 'MFA_VERIFICATION_FAILURE':
      return {
        ...base,
        title: 'Verification code rejected',
        description: 'An invalid two-step verification code was entered.',
        category: 'Authentication',
        severity: 'Attention',
      };
    case 'RECOVERY_CODE_USED':
      return {
        ...base,
        title: 'Recovery code used to sign in',
        description: 'One of your backup recovery codes was used to access your account.',
        category: 'Recovery',
        severity: 'Attention',
      };
    case 'RECOVERY_CODES_REGENERATED':
      return {
        ...base,
        title: 'Backup recovery codes refreshed',
        description: 'A new set of backup recovery codes was created and older codes were retired.',
        category: 'Recovery',
        severity: 'Healthy',
      };
    case 'PASSWORD_CHANGED':
      return {
        ...base,
        title: 'Account password updated',
        description: 'Your password was changed and other active sessions were signed out.',
        category: 'Authentication',
        severity: 'Healthy',
      };
    case 'SESSION_REVOKED':
      return {
        ...base,
        title: 'Other sessions signed out',
        description: 'Active sessions on other browsers were closed to protect your account.',
        category: 'Authentication',
        severity: 'Information',
      };
    case 'DEVICE_ENROLLMENT_INITIATED':
      return {
        ...base,
        title: `Connecting ${deviceName}`,
        description: `A one-time connection code was created for ${deviceName}.`,
        category: 'Device',
        severity: 'Information',
      };
    case 'DEVICE_KEY_SUBMITTED':
      return {
        ...base,
        title: `${deviceName} ready for approval`,
        description: 'Device identity was verified and is waiting for your confirmation.',
        category: 'Device',
        severity: 'Information',
      };
    case 'DEVICE_ENROLLMENT_PROOF_FAILURE':
      return {
        ...base,
        title: 'Unverified device connection blocked',
        description: 'A device attempted to connect without valid identity verification.',
        category: 'Protection',
        severity: 'Attention',
      };
    case 'DEVICE_ENROLLED':
      return {
        ...base,
        title: `${deviceName} is now protected`,
        description: `You approved ${deviceName} and added it to your trusted devices.`,
        category: 'Device',
        severity: 'Healthy',
      };
    case 'DEVICE_KEY_ROTATED':
      return {
        ...base,
        title: 'Device security credentials refreshed',
        description: `${deviceName} automatically updated its hardware security credentials.`,
        category: 'Protection',
        severity: 'Healthy',
      };
    case 'DEVICE_AUTH_VERIFIED':
      return {
        ...base,
        title: 'Device security check completed',
        description: `${deviceName} checked in and verified its protection status.`,
        category: 'Protection',
        severity: 'Healthy',
      };
    case 'DEVICE_AUTH_FAILURE':
      return {
        ...base,
        title: 'Unrecognized device check-in blocked',
        description: 'VAJRA blocked an unverified request claiming to come from a device.',
        category: 'Protection',
        severity: 'Attention',
      };
    case 'DEVICE_REPLAY_DETECTED':
      return {
        ...base,
        title: 'Repeated device request blocked',
        description: 'VAJRA automatically blocked a repeated or outdated device request.',
        category: 'Protection',
        severity: 'Attention',
      };
    case 'DEVICE_COMPROMISED_FLAGGED':
      return {
        ...base,
        title: `${deviceName} marked for review`,
        description: `You paused trusted access for ${deviceName} while you review its security.`,
        category: 'Protection',
        severity: 'Critical',
      };
    case 'DEVICE_REVOKED':
      return {
        ...base,
        title: `${deviceName} disconnected`,
        description: `Access for ${deviceName} was permanently removed from your account.`,
        category: 'Device',
        severity: 'Attention',
      };
    case 'DEVICE_DECOMMISSIONED':
      return {
        ...base,
        title: `${deviceName} archived`,
        description: `${deviceName} was moved to your archived devices.`,
        category: 'Device',
        severity: 'Information',
      };
    case 'DEVICE_ACTION_LOCATION_REQUESTED':
      return {
        ...base,
        title: 'Location requested',
        subtitle: `${deviceName} · Location updated`,
        description: `Updated last known location summary for ${deviceName}.`,
        category: 'Recovery',
        severity: 'Information',
      };
    case 'DEVICE_ACTION_RING_REQUESTED':
      return {
        ...base,
        title: `Ring alert sent to ${deviceName}`,
        subtitle: `${deviceName} · Audible alert`,
        description: `Requested a high-volume recovery sound on ${deviceName}.`,
        category: 'Recovery',
        severity: 'Attention',
      };
    case 'DEVICE_ACTION_RECOVERY_MESSAGE_SENT':
      return {
        ...base,
        title: `Recovery message set for ${deviceName}`,
        subtitle: `${deviceName} · Recovery notice`,
        description: `Prepared a custom return message for ${deviceName}.`,
        category: 'Recovery',
        severity: 'Attention',
      };
    case 'DEVICE_ACTION_LOST_MODE_ENABLED':
      return {
        ...base,
        title: `Lost Mode enabled on ${deviceName}`,
        subtitle: `${deviceName} · Lost Mode active`,
        description: `Activated Lost Mode recovery protection and return notice on ${deviceName}.`,
        category: 'Recovery',
        severity: 'Critical',
      };
    case 'DEVICE_ACTION_LOST_MODE_DISABLED':
      return {
        ...base,
        title: `Lost Mode turned off on ${deviceName}`,
        subtitle: `${deviceName} · Protected`,
        description: `${deviceName} returned to standard protected status.`,
        category: 'Recovery',
        severity: 'Healthy',
      };
    case 'DEVICE_ACTION_STATUS_CHECKED':
      return {
        ...base,
        title: 'Security check completed',
        subtitle: `${deviceName} · Healthy`,
        description: `${deviceName} checked in and confirmed all security protections are active.`,
        category: 'Protection',
        severity: 'Healthy',
      };
    case 'THREATCHECK_INSPECTED': {
      const verdict = typeof metadata?.verdict === 'string' ? metadata.verdict : 'LOW RISK';
      const hostname = typeof metadata?.hostname === 'string' ? metadata.hostname : 'website link';
      return {
        ...base,
        title:
          verdict === 'HIGH RISK'
            ? 'High-risk link flagged'
            : verdict === 'SUSPICIOUS'
            ? 'Suspicious link inspected'
            : 'Website link inspected',
        subtitle: `ThreatCheck · ${hostname} · ${verdict}`,
        description:
          typeof metadata?.summary === 'string'
            ? metadata.summary
            : `Checked ${hostname} for deceptive link characteristics.`,
        category: 'ThreatCheck',
        severity:
          verdict === 'HIGH RISK'
            ? 'Critical'
            : verdict === 'SUSPICIOUS'
            ? 'Attention'
            : 'Healthy',
      };
    }
    case 'SECURITY_REPORT_EXPORTED': {
      const format =
        typeof metadata?.format === 'string' ? metadata.format.toUpperCase() : 'JSON';
      return {
        ...base,
        title: `Security report exported (${format})`,
        subtitle: `VAJRA · ${format} Report`,
        description: `Downloaded a sanitized ${format} report of your security posture, events, and link inspections.`,
        category: 'Protection',
        severity: 'Information',
      };
    }
    default:
      return {
        ...base,
        title: 'Security check completed',
        description: 'VAJRA verified your account and device protection status.',
        category: 'Protection',
        severity: 'Healthy',
      };
  }
}

export type ThreatCheckVerdict = 'LOW RISK' | 'SUSPICIOUS' | 'HIGH RISK' | 'UNKNOWN';

export interface ThreatCheckAnalysis {
  normalizedDisplayUrl: string;
  hostname: string;
  verdict: ThreatCheckVerdict;
  summary: string;
  signals: string[];
  recommendation: string;
}

/**
 * Performs transparent, client-side structural link inspection for ThreatCheck preview.
 * Never claims a link is "100% safe".
 */
export function evaluateUrlSafetyPreview(rawInput: string): ThreatCheckAnalysis {
  const trimmed = rawInput.trim();
  const withScheme = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;

  try {
    const parsed = new URL(withScheme);
    const hostname = parsed.hostname.toLowerCase();
    const signals: string[] = [];
    let riskPoints = 0;

    if (parsed.protocol === 'http:') {
      riskPoints += 25;
      signals.push('Uses an unencrypted connection (HTTP instead of HTTPS).');
    }

    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
      riskPoints += 45;
      signals.push('Points directly to a raw numeric address instead of a verified domain name.');
    }

    if (hostname.includes('xn--')) {
      riskPoints += 35;
      signals.push('Contains international lookalike characters often used to imitate trusted brands.');
    }

    if (parsed.username || parsed.password) {
      riskPoints += 50;
      signals.push('Includes embedded sign-in credentials inside the link address to disguise the destination.');
    }

    const suspiciousKeywords = ['login-verify', 'account-update', 'secure-wallet', 'free-gift', 'password-reset-urgent'];
    for (const kw of suspiciousKeywords) {
      if (withScheme.toLowerCase().includes(kw)) {
        riskPoints += 35;
        signals.push('Contains urgent account or credential keywords commonly seen in phishing links.');
        break;
      }
    }

    const riskyTlds = ['.zip', '.mov', '.top', '.xyz', '.click', '.tk'];
    if (riskyTlds.some((tld) => hostname.endsWith(tld))) {
      riskPoints += 25;
      signals.push('Uses a domain extension frequently associated with temporary or deceptive sites.');
    }

    // Redact query values for safe display
    const safeUrl = `${parsed.protocol}//${parsed.host}${parsed.pathname}${
      parsed.search ? '?...' : ''
    }`;

    if (riskPoints >= 45) {
      return {
        normalizedDisplayUrl: safeUrl,
        hostname,
        verdict: 'HIGH RISK',
        summary: 'This link shows multiple warning signs commonly used to impersonate websites or steal information.',
        signals,
        recommendation: 'Do not open this link or enter any passwords or personal details.',
      };
    }

    if (riskPoints >= 20) {
      return {
        normalizedDisplayUrl: safeUrl,
        hostname,
        verdict: 'SUSPICIOUS',
        summary: 'This link has unusual characteristics that warrant extra caution before visiting.',
        signals,
        recommendation: 'Verify the sender independently before opening this link.',
      };
    }

    return {
      normalizedDisplayUrl: safeUrl,
      hostname,
      verdict: 'LOW RISK',
      summary: 'No immediate structural warning signs were detected in this link.',
      signals: [
        'Uses an encrypted HTTPS connection.',
        'Standard domain name structure with no disguised address patterns.',
      ],
      recommendation:
        'No automated check can guarantee a website is completely safe. Always verify the domain before entering sensitive information.',
    };
  } catch {
    const safeFallbackDisplay = trimmed
      .split('#')[0]
      .replace(/\?.*$/, '?[REDACTED]')
      .slice(0, 80);
    return {
      normalizedDisplayUrl: safeFallbackDisplay || 'Unrecognized address',
      hostname: 'Unrecognized address',
      verdict: 'UNKNOWN',
      summary: 'Please enter a valid website address or link (for example, example.com).',
      signals: ['The text entered could not be recognized as a standard website link.'],
      recommendation: 'Check the link spelling and try again.',
    };
  }
}
