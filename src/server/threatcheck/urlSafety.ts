/**
 * VAJRA — ThreatCheck URL Normalization, Query Redaction & SSRF-Aware Lexical Safety Service
 * Prompt 0011B
 *
 * Security & Honesty Guarantees:
 * 1. Never performs any outbound HTTP request, crawler fetch, or DNS lookup when analyzing a URL.
 * 2. Accepts only http: and https: protocols (or normalizes bare domains to https: when no scheme is supplied).
 * 3. Rejects malformed URLs, unsupported protocols (javascript:, data:, file:, ftp:, etc.), and embedded user:pass@ credentials.
 * 4. Normalizes hostnames consistently via the WHATWG URL parser (including IDNA / punycode).
 * 5. Redacts ALL query parameter values and strips URL fragments (#...) so raw tokens, session keys, or credentials are never persisted or logged.
 * 6. Flags loopback, private RFC1918, link-local, Carrier-Grade NAT, reserved IPv4/IPv6, IPv4-mapped IPv6, alternative integer/hex/octal IPs, and cloud metadata destinations (e.g. 169.254.169.254, fd00:ec2::254, metadata.google.internal) as RESTRICTED DESTINATION.
 * 7. Distinguishes between `restricted destination`, `suspicious indicators`, and `no obvious lexical indicators`, and explicitly states the limits of lexical analysis.
 */

import net from 'node:net';
import type { ThreatCheckAnalysis } from '../../components/securityCopy.ts';

export type ThreatCheckClassification =
  | 'restricted destination'
  | 'suspicious indicators'
  | 'no obvious lexical indicators';

export interface StructuredThreatIndicator {
  code: string;
  category: 'Transport' | 'DestinationBoundary' | 'DomainIdentity' | 'PathHeuristics' | 'QueryPrivacy';
  severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  title: string;
  explanation: string;
  weight: number;
}

export interface ThreatCheckEvaluationOutcome {
  valid: boolean;
  errorCode?:
    | 'EMPTY_URL'
    | 'URL_TOO_LONG'
    | 'UNSUPPORTED_PROTOCOL'
    | 'EMBEDDED_CREDENTIALS_FORBIDDEN'
    | 'MALFORMED_URL'
    | 'INVALID_HOSTNAME';
  errorMessage?: string;
  submittedUrlRedacted?: string;
  normalizedDisplayUrl?: string;
  normalizedDomain?: string;
  protocol?: 'http:' | 'https:';
  verdict?: 'LOW RISK' | 'SUSPICIOUS' | 'HIGH RISK';
  classification?: ThreatCheckClassification;
  riskScore?: number;
  summary?: string;
  recommendedGuidance?: string;
  limitationsStatement?: string;
  restrictedDestination?: boolean;
  restrictedReason?: string | null;
  indicators?: StructuredThreatIndicator[];
  analysisPreview?: ThreatCheckAnalysis;
}

const LEXICAL_LIMITATIONS_STATEMENT =
  'Lexical URL analysis inspects only the structure, hostname, and destination address boundaries of a link without fetching the page or performing live DNS resolution. A low-risk result is not a guarantee that the destination website is safe.';

/**
 * Attempts to parse an IPv4 address string (standard dotted-quad) into a 32-bit unsigned integer.
 */
function parseDottedIpv4ToUint32(ip: string): number | null {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const num = Number(part);
    if (num < 0 || num > 255) return null;
    result = ((result << 8) | num) >>> 0;
  }
  return result >>> 0;
}

/**
 * Detects alternative IPv4 representations (pure integer like 2130706433, hex like 0x7f000001, or octal dotted quads)
 * before or after URL parsing.
 */
function detectAlternativeIpv4Host(rawHost: string): number | null {
  const host = rawHost.trim().toLowerCase();
  if (!host) return null;

  // Single 32-bit decimal integer (e.g., 2130706433 -> 127.0.0.1)
  if (/^\d+$/.test(host)) {
    const val = Number(host);
    if (Number.isInteger(val) && val >= 0 && val <= 0xffffffff) {
      return val >>> 0;
    }
  }

  // Single hex integer (e.g., 0x7f000001)
  if (/^0x[0-9a-f]+$/i.test(host)) {
    const val = Number.parseInt(host.slice(2), 16);
    if (Number.isInteger(val) && val >= 0 && val <= 0xffffffff) {
      return val >>> 0;
    }
  }

  // Dotted parts with octal (0177.0.0.1) or hex (0x7f.0.0.1)
  const parts = host.split('.');
  if (parts.length >= 2 && parts.length <= 4) {
    const parsedParts: number[] = [];
    let allNumeric = true;
    for (const p of parts) {
      if (/^0x[0-9a-f]+$/i.test(p)) {
        parsedParts.push(Number.parseInt(p.slice(2), 16));
      } else if (/^0[0-7]+$/.test(p) && p.length > 1) {
        parsedParts.push(Number.parseInt(p, 8));
      } else if (/^\d+$/.test(p)) {
        parsedParts.push(Number.parseInt(p, 10));
      } else {
        allNumeric = false;
        break;
      }
    }
    if (allNumeric && parsedParts.length === 4 && parsedParts.every((n) => n >= 0 && n <= 255)) {
      return (
        ((parsedParts[0] << 24) |
          (parsedParts[1] << 16) |
          (parsedParts[2] << 8) |
          parsedParts[3]) >>>
        0
      );
    }
  }

  return null;
}

function uint32ToIpv4String(num: number): string {
  return [
    (num >>> 24) & 0xff,
    (num >>> 16) & 0xff,
    (num >>> 8) & 0xff,
    num & 0xff,
  ].join('.');
}

interface IpBoundaryCheckResult {
  isIpLiteral: boolean;
  isRestricted: boolean;
  code: string;
  title: string;
  explanation: string;
}

function classifyIpv4Uint32(ipUint32: number, displayIp: string): IpBoundaryCheckResult {
  const first = (ipUint32 >>> 24) & 0xff;
  const second = (ipUint32 >>> 16) & 0xff;
  const third = (ipUint32 >>> 8) & 0xff;
  const fourth = ipUint32 & 0xff;

  // Cloud metadata 169.254.169.254
  if (first === 169 && second === 254 && third === 169 && fourth === 254) {
    return {
      isIpLiteral: true,
      isRestricted: true,
      code: 'SSRF_CLOUD_METADATA_IPV4',
      title: 'Restricted cloud metadata address (169.254.169.254)',
      explanation: `Destination ${displayIp} targets the instance metadata service address (169.254.169.254), which is a restricted internal boundary.`,
    };
  }

  // Loopback 127.0.0.0/8
  if (first === 127) {
    return {
      isIpLiteral: true,
      isRestricted: true,
      code: 'SSRF_LOOPBACK_IPV4',
      title: 'Restricted loopback address (127.0.0.0/8)',
      explanation: `Destination ${displayIp} points to a local loopback interface (127.0.0.0/8) rather than a public website.`,
    };
  }

  // Unspecified / Current network 0.0.0.0/8
  if (first === 0) {
    return {
      isIpLiteral: true,
      isRestricted: true,
      code: 'SSRF_UNSPECIFIED_IPV4',
      title: 'Restricted unspecified address (0.0.0.0/8)',
      explanation: `Destination ${displayIp} is in the reserved 0.0.0.0/8 local network block.`,
    };
  }

  // Link-local 169.254.0.0/16
  if (first === 169 && second === 254) {
    return {
      isIpLiteral: true,
      isRestricted: true,
      code: 'SSRF_LINK_LOCAL_IPV4',
      title: 'Restricted link-local address (169.254.0.0/16)',
      explanation: `Destination ${displayIp} is a link-local address (169.254.0.0/16) reserved for local network segments.`,
    };
  }

  // Private RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
  if (
    first === 10 ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 168)
  ) {
    return {
      isIpLiteral: true,
      isRestricted: true,
      code: 'SSRF_PRIVATE_RFC1918_IPV4',
      title: 'Restricted private network address (RFC 1918)',
      explanation: `Destination ${displayIp} belongs to a private internal network range (RFC 1918) and is not an ordinary public destination.`,
    };
  }

  // Carrier-Grade NAT 100.64.0.0/10
  if (first === 100 && second >= 64 && second <= 127) {
    return {
      isIpLiteral: true,
      isRestricted: true,
      code: 'SSRF_CGNAT_IPV4',
      title: 'Restricted shared address space (100.64.0.0/10)',
      explanation: `Destination ${displayIp} is in the Carrier-Grade NAT shared address block (100.64.0.0/10).`,
    };
  }

  // Multicast / Reserved >= 224.0.0.0
  if (first >= 224) {
    return {
      isIpLiteral: true,
      isRestricted: true,
      code: 'SSRF_RESERVED_IPV4',
      title: 'Reserved or multicast IPv4 address',
      explanation: `Destination ${displayIp} is in a reserved or multicast IPv4 range.`,
    };
  }

  // Public IPv4 literal (not restricted, but notable because legitimate websites usually use domain names)
  return {
    isIpLiteral: true,
    isRestricted: false,
    code: 'DIRECT_PUBLIC_IPV4_HOST',
    title: 'Direct IPv4 address instead of a domain name',
    explanation: `The link uses a raw IPv4 address (${displayIp}) instead of a registered domain name.`,
  };
}

/**
 * Inspects an IPv6 literal (with or without surrounding brackets) for loopback, unspecified,
 * link-local, unique-local, cloud metadata, or IPv4-mapped IPv6 addresses.
 */
function classifyIpv6Host(rawIpv6: string): IpBoundaryCheckResult | null {
  const cleaned = rawIpv6.replace(/^\[|\]$/g, '').toLowerCase();
  if (!cleaned.includes(':')) return null;

  // Strip zone index if present (%eth0)
  const withoutZone = cleaned.split('%')[0];
  if (net.isIP(withoutZone) !== 6) {
    return null;
  }

  // Check IPv4-mapped IPv6 in dotted form (e.g., ::ffff:127.0.0.1 or ::ffff:169.254.169.254)
  const mappedDottedMatch = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(withoutZone);
  if (mappedDottedMatch) {
    const v4Uint = parseDottedIpv4ToUint32(mappedDottedMatch[1]);
    if (v4Uint !== null) {
      const inner = classifyIpv4Uint32(v4Uint, `[${withoutZone}]`);
      return {
        isIpLiteral: true,
        isRestricted: true,
        code: inner.isRestricted ? 'SSRF_IPV4_MAPPED_IPV6' : 'DIRECT_IPV6_HOST',
        title: inner.isRestricted
          ? `Restricted IPv4-mapped IPv6 address ([${withoutZone}])`
          : 'IPv4-mapped IPv6 literal',
        explanation: inner.explanation,
      };
    }
  }

  // Check IPv4-mapped IPv6 in hex form produced by WHATWG URL parser (e.g., ::ffff:7f00:1 or ::ffff:a9fe:a9fe)
  const mappedHexMatch = /^(?:0*:)*ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i.exec(withoutZone);
  if (mappedHexMatch) {
    const high16 = Number.parseInt(mappedHexMatch[1], 16);
    const low16 = Number.parseInt(mappedHexMatch[2], 16);
    const v4Uint = (((high16 & 0xffff) << 16) | (low16 & 0xffff)) >>> 0;
    const dotted = uint32ToIpv4String(v4Uint);
    const inner = classifyIpv4Uint32(v4Uint, `[${withoutZone}] (${dotted})`);
    return {
      isIpLiteral: true,
      isRestricted: inner.isRestricted,
      code: inner.isRestricted ? 'SSRF_IPV4_MAPPED_IPV6' : 'DIRECT_IPV6_HOST',
      title: inner.isRestricted
        ? `Restricted IPv4-mapped IPv6 address ([${withoutZone}] -> ${dotted})`
        : 'IPv4-mapped IPv6 literal',
      explanation: inner.explanation,
    };
  }

  // Loopback ::1 orUnspecified ::
  if (withoutZone === '::1' || withoutZone === '0:0:0:0:0:0:0:1') {
    return {
      isIpLiteral: true,
      isRestricted: true,
      code: 'SSRF_LOOPBACK_IPV6',
      title: 'Restricted IPv6 loopback address ([::1])',
      explanation: 'Destination [::1] points to the local IPv6 loopback interface.',
    };
  }

  if (withoutZone === '::' || withoutZone === '0:0:0:0:0:0:0:0') {
    return {
      isIpLiteral: true,
      isRestricted: true,
      code: 'SSRF_UNSPECIFIED_IPV6',
      title: 'Restricted unspecified IPv6 address ([::])',
      explanation: 'Destination [::] is the unspecified IPv6 address.',
    };
  }

  // AWS / Cloud IPv6 metadata (fd00:ec2::254)
  if (withoutZone === 'fd00:ec2::254') {
    return {
      isIpLiteral: true,
      isRestricted: true,
      code: 'SSRF_CLOUD_METADATA_IPV6',
      title: 'Restricted cloud metadata IPv6 address ([fd00:ec2::254])',
      explanation: 'Destination [fd00:ec2::254] targets an internal cloud metadata service endpoint.',
    };
  }

  // Unique Local IPv6 (fc00::/7 -> starts with fc or fd)
  if (/^f[cd][0-9a-f]{2}:/i.test(withoutZone)) {
    return {
      isIpLiteral: true,
      isRestricted: true,
      code: 'SSRF_UNIQUE_LOCAL_IPV6',
      title: 'Restricted unique-local IPv6 address (fc00::/7)',
      explanation: `Destination [${withoutZone}] belongs to the private IPv6 Unique Local Address range (fc00::/7).`,
    };
  }

  // Link-Local IPv6 (fe80::/10 -> starts with fe8, fe9, fea, feb)
  if (/^fe[89ab][0-9a-f]:/i.test(withoutZone)) {
    return {
      isIpLiteral: true,
      isRestricted: true,
      code: 'SSRF_LINK_LOCAL_IPV6',
      title: 'Restricted link-local IPv6 address (fe80::/10)',
      explanation: `Destination [${withoutZone}] belongs to the IPv6 link-local range (fe80::/10).`,
    };
  }

  return {
    isIpLiteral: true,
    isRestricted: false,
    code: 'DIRECT_IPV6_HOST',
    title: 'Direct IPv6 address instead of a domain name',
    explanation: `The link uses a raw IPv6 address ([${withoutZone}]) instead of a registered domain name.`,
  };
}

/**
 * Redacts all query parameter values (?key=[REDACTED]) and strips any URL fragment (#...).
 */
export function buildRedactedUrlString(parsed: URL): {
  submittedUrlRedacted: string;
  normalizedDisplayUrl: string;
  hadQueryParams: boolean;
  hadSensitiveQueryKeys: boolean;
  hadFragment: boolean;
} {
  const pathname = parsed.pathname && parsed.pathname.length > 0 ? parsed.pathname : '/';
  const portSegment = parsed.port ? `:${parsed.port}` : '';
  const baseOriginAndPath = `${parsed.protocol}//${parsed.hostname}${portSegment}${
    pathname.length > 80 ? `${pathname.slice(0, 80)}…` : pathname
  }`;

  const hadFragment = Boolean(parsed.hash && parsed.hash.length > 0);
  const searchParams = Array.from(parsed.searchParams.keys());
  const hadQueryParams = searchParams.length > 0 || parsed.search.length > 1;

  const sensitiveKeyPattern =
    /(token|key|secret|pass|pwd|auth|session|code|sig|signature|jwt|bearer|api_key|apikey|credential|otp|recovery)/i;
  let hadSensitiveQueryKeys = false;

  if (!hadQueryParams) {
    return {
      submittedUrlRedacted: `${parsed.protocol}//${parsed.hostname}${portSegment}${pathname}`,
      normalizedDisplayUrl: baseOriginAndPath,
      hadQueryParams: false,
      hadSensitiveQueryKeys: false,
      hadFragment,
    };
  }

  const redactedPairs: string[] = [];
  const seenKeys = new Set<string>();
  for (const rawKey of searchParams) {
    const safeKey = rawKey.replace(/[^a-zA-Z0-9_.-]/g, '_').slice(0, 32) || 'param';
    if (sensitiveKeyPattern.test(rawKey)) {
      hadSensitiveQueryKeys = true;
    }
    if (!seenKeys.has(safeKey)) {
      seenKeys.add(safeKey);
      redactedPairs.push(`${safeKey}=[REDACTED]`);
    }
  }

  const redactedQuery =
    redactedPairs.length > 0 ? `?${redactedPairs.join('&')}` : '?[REDACTED]';

  return {
    submittedUrlRedacted: `${parsed.protocol}//${parsed.hostname}${portSegment}${pathname}${redactedQuery}`,
    normalizedDisplayUrl: `${baseOriginAndPath}?...`,
    hadQueryParams: true,
    hadSensitiveQueryKeys,
    hadFragment,
  };
}

/**
 * Evaluates a candidate URL strictly through lexical, hostname, and destination-boundary inspection
 * without making any network or DNS requests.
 */
export function analyzeThreatCheckUrl(rawInput: string): ThreatCheckEvaluationOutcome {
  const trimmed = typeof rawInput === 'string' ? rawInput.trim() : '';
  if (!trimmed) {
    return {
      valid: false,
      errorCode: 'EMPTY_URL',
      errorMessage: 'Please provide a website link to inspect.',
    };
  }

  if (trimmed.length > 2048) {
    return {
      valid: false,
      errorCode: 'URL_TOO_LONG',
      errorMessage: 'Submitted link exceeds the maximum permitted length of 2048 characters.',
    };
  }

  // Reject whitespace/control characters inside the URL
  if (/[\s\r\n\t]/.test(trimmed)) {
    return {
      valid: false,
      errorCode: 'MALFORMED_URL',
      errorMessage: 'Malformed URL: links cannot contain spaces or control characters.',
    };
  }

  // Check if a scheme is explicitly present
  const schemeMatch = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(trimmed);
  let candidate = trimmed;
  if (schemeMatch) {
    const scheme = schemeMatch[1].toLowerCase();
    if (scheme !== 'http' && scheme !== 'https') {
      return {
        valid: false,
        errorCode: 'UNSUPPORTED_PROTOCOL',
        errorMessage: `Unsupported protocol "${scheme}:". ThreatCheck inspects only http: and https: web links.`,
      };
    }
    // Ensure http:// or https:// has double slash after colon
    if (!/^https?:\/\//i.test(trimmed)) {
      return {
        valid: false,
        errorCode: 'MALFORMED_URL',
        errorMessage: 'Malformed HTTP/HTTPS URL syntax.',
      };
    }
  } else {
    candidate = `https://${trimmed}`;
  }

  // Extract raw authority before WHATWG URL normalization to catch octal/hex/integer IPs if needed
  const rawAuthorityMatch = /^https?:\/\/([^/?#]+)/i.exec(candidate);
  const rawAuthority = rawAuthorityMatch ? rawAuthorityMatch[1] : '';

  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    return {
      valid: false,
      errorCode: 'MALFORMED_URL',
      errorMessage: 'Please enter a valid website address (for example, https://example.com).',
    };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      valid: false,
      errorCode: 'UNSUPPORTED_PROTOCOL',
      errorMessage: 'Only http: and https: URLs are supported.',
    };
  }

  // Reject embedded username or password credentials (e.g., https://user:pass@example.com)
  if (parsed.username || parsed.password || rawAuthority.includes('@')) {
    return {
      valid: false,
      errorCode: 'EMBEDDED_CREDENTIALS_FORBIDDEN',
      errorMessage:
        'Links containing embedded username or password credentials (user:pass@host) are rejected for safety.',
    };
  }

  const normalizedDomain = parsed.hostname.toLowerCase();
  if (!normalizedDomain || normalizedDomain.startsWith('.') || normalizedDomain.endsWith('.')) {
    return {
      valid: false,
      errorCode: 'INVALID_HOSTNAME',
      errorMessage: 'The submitted URL does not contain a valid hostname.',
    };
  }

  const rawHostWithoutPort = rawAuthority.replace(/:\d+$/, '').toLowerCase();
  const altIpv4 = detectAlternativeIpv4Host(rawHostWithoutPort);
  const stdIpv4 = parseDottedIpv4ToUint32(normalizedDomain);
  const ipv6Result = classifyIpv6Host(normalizedDomain);

  // If the hostname is not an IP literal, validate domain structure
  const isLocalSpecialHost =
    normalizedDomain === 'localhost' ||
    normalizedDomain.endsWith('.localhost') ||
    normalizedDomain.endsWith('.local') ||
    normalizedDomain.endsWith('.internal') ||
    normalizedDomain === 'metadata.google.internal' ||
    normalizedDomain === 'metadata';

  if (altIpv4 === null && stdIpv4 === null && ipv6Result === null && !isLocalSpecialHost) {
    if (!normalizedDomain.includes('.')) {
      return {
        valid: false,
        errorCode: 'INVALID_HOSTNAME',
        errorMessage: 'Hostname must be a valid domain name or IP address.',
      };
    }
    const labels = normalizedDomain.split('.');
    const tld = labels[labels.length - 1];
    if (!tld || tld.length < 2 || /^\d+$/.test(tld)) {
      return {
        valid: false,
        errorCode: 'INVALID_HOSTNAME',
        errorMessage: 'Hostname has an invalid top-level domain.',
      };
    }
  }

  const redaction = buildRedactedUrlString(parsed);
  const indicators: StructuredThreatIndicator[] = [];
  let restrictedDestination = false;
  let restrictedReason: string | null = null;

  // 1. Check for Restricted Destination Boundaries (SSRF / Local / Private / Metadata)
  if (
    normalizedDomain === 'metadata.google.internal' ||
    normalizedDomain === 'metadata' ||
    normalizedDomain === 'instance-data'
  ) {
    restrictedDestination = true;
    restrictedReason =
      'Destination targets a cloud instance metadata hostname, which is restricted from ordinary public target handling.';
    indicators.push({
      code: 'SSRF_CLOUD_METADATA_HOSTNAME',
      category: 'DestinationBoundary',
      severity: 'HIGH',
      title: 'Restricted cloud metadata hostname',
      explanation: restrictedReason,
      weight: 85,
    });
  } else if (
    normalizedDomain === 'localhost' ||
    normalizedDomain.endsWith('.localhost') ||
    normalizedDomain.endsWith('.local') ||
    normalizedDomain.endsWith('.internal')
  ) {
    restrictedDestination = true;
    restrictedReason = `Hostname "${normalizedDomain}" resolves to a loopback or internal network namespace and is classified as a restricted destination.`;
    indicators.push({
      code: 'SSRF_LOCAL_NAMESPACE_HOSTNAME',
      category: 'DestinationBoundary',
      severity: 'HIGH',
      title: 'Restricted local or internal hostname',
      explanation: restrictedReason,
      weight: 80,
    });
  } else if (stdIpv4 !== null || altIpv4 !== null) {
    const ipVal = stdIpv4 ?? altIpv4!;
    const ipCheck = classifyIpv4Uint32(ipVal, normalizedDomain);
    const usedAlternativeEncoding =
      altIpv4 !== null && rawHostWithoutPort !== uint32ToIpv4String(ipVal);

    if (usedAlternativeEncoding) {
      indicators.push({
        code: 'OBFUSCATED_IPV4_ENCODING',
        category: 'DestinationBoundary',
        severity: 'HIGH',
        title: 'Obfuscated IPv4 address encoding',
        explanation: `The hostname "${rawHostWithoutPort}" uses integer, octal, or hexadecimal IPv4 encoding (${uint32ToIpv4String(
          ipVal
        )}).`,
        weight: 45,
      });
    }

    if (ipCheck.isRestricted) {
      restrictedDestination = true;
      restrictedReason = ipCheck.explanation;
      indicators.push({
        code: ipCheck.code,
        category: 'DestinationBoundary',
        severity: 'HIGH',
        title: ipCheck.title,
        explanation: ipCheck.explanation,
        weight: 85,
      });
    } else {
      indicators.push({
        code: ipCheck.code,
        category: 'DomainIdentity',
        severity: 'MEDIUM',
        title: ipCheck.title,
        explanation: ipCheck.explanation,
        weight: 40,
      });
    }
  } else if (ipv6Result !== null) {
    if (ipv6Result.isRestricted) {
      restrictedDestination = true;
      restrictedReason = ipv6Result.explanation;
      indicators.push({
        code: ipv6Result.code,
        category: 'DestinationBoundary',
        severity: 'HIGH',
        title: ipv6Result.title,
        explanation: ipv6Result.explanation,
        weight: 85,
      });
    } else {
      indicators.push({
        code: ipv6Result.code,
        category: 'DomainIdentity',
        severity: 'MEDIUM',
        title: ipv6Result.title,
        explanation: ipv6Result.explanation,
        weight: 35,
      });
    }
  }

  // 2. Check Transport Security (HTTP vs HTTPS)
  if (parsed.protocol === 'http:') {
    indicators.push({
      code: 'UNENCRYPTED_HTTP_TRANSPORT',
      category: 'Transport',
      severity: 'MEDIUM',
      title: 'Unencrypted HTTP connection',
      explanation:
        'This link uses unencrypted HTTP rather than HTTPS. Traffic sent over HTTP can be intercepted or modified in transit.',
      weight: 30,
    });
  }

  // 3. Check IDNA / Punycode lookalike domains
  if (normalizedDomain.includes('xn--')) {
    indicators.push({
      code: 'IDNA_PUNYCODE_LOOKALIKE',
      category: 'DomainIdentity',
      severity: 'HIGH',
      title: 'Internationalized (Punycode) domain encoding',
      explanation:
        'The hostname uses IDNA punycode (xn--), which is sometimes used to visually impersonate trusted brands.',
      weight: 50,
    });
  }

  // 4. Check excessive subdomain nesting or deceptive brand-impersonation hyphens
  const domainParts = normalizedDomain.split('.');
  if (domainParts.length >= 5 && stdIpv4 === null) {
    indicators.push({
      code: 'EXCESSIVE_SUBDOMAIN_DEPTH',
      category: 'DomainIdentity',
      severity: 'MEDIUM',
      title: 'Deeply nested subdomain structure',
      explanation:
        'The hostname contains 5 or more domain levels, a pattern frequently used to hide the actual destination domain on mobile screens.',
      weight: 25,
    });
  }

  // 5. Check high-risk credential-harvesting / phishing keywords in hostname or path
  const combinedHostAndPath = `${normalizedDomain}${parsed.pathname.toLowerCase()}`;
  if (
    /(login-verify|account-update|secure-signin|wallet-connect|password-reset|verify-account|auth-confirm|unlock-device)/i.test(
      combinedHostAndPath
    )
  ) {
    indicators.push({
      code: 'DECEPTIVE_AUTH_LURE_PATTERN',
      category: 'PathHeuristics',
      severity: 'HIGH',
      title: 'Credential-harvesting or sign-in lure wording',
      explanation:
        'The address contains deceptive account verification or password-reset phrasing commonly used in credential phishing.',
      weight: 50,
    });
  }

  // 6. Check high-risk file extensions in URL path
  if (/\.(exe|scr|bat|cmd|ps1|vbs|msi|apk|dmg|iso)$/i.test(parsed.pathname)) {
    indicators.push({
      code: 'EXECUTABLE_DOWNLOAD_PATH',
      category: 'PathHeuristics',
      severity: 'HIGH',
      title: 'Direct executable or installer file path',
      explanation:
        'The URL path points directly to an executable binary or package installer.',
      weight: 55,
    });
  }

  // 7. Query parameter redaction notice
  if (redaction.hadSensitiveQueryKeys) {
    indicators.push({
      code: 'REDACTED_SENSITIVE_QUERY_KEYS',
      category: 'QueryPrivacy',
      severity: 'LOW',
      title: 'Sensitive query parameters redacted',
      explanation:
        'Token, key, or session parameters in the query string were automatically redacted before storage.',
      weight: 10,
    });
  }

  // Compute deterministic riskScore (0..100) and classification
  const rawScore = indicators.reduce((acc, ind) => acc + ind.weight, 0);
  const riskScore = Math.max(0, Math.min(100, rawScore));

  let classification: ThreatCheckClassification;
  let verdict: 'LOW RISK' | 'SUSPICIOUS' | 'HIGH RISK';
  let summary: string;
  let recommendedGuidance: string;

  if (restrictedDestination) {
    classification = 'restricted destination';
    verdict = 'HIGH RISK';
    summary =
      restrictedReason ??
      'This link targets a restricted local, private, or metadata network address rather than a public website.';
    recommendedGuidance =
      'Do not open or forward links pointing to local loopback, private internal networks, or cloud metadata addresses. VAJRA blocks restricted destinations from being treated as ordinary public targets.';
  } else if (riskScore >= 60) {
    classification = 'suspicious indicators';
    verdict = 'HIGH RISK';
    summary =
      'This link shows multiple high-risk lexical indicators commonly associated with credential harvesting or deceptive destinations.';
    recommendedGuidance =
      'Avoid opening this link or entering any passwords, verification codes, or personal details. Navigate to the service directly using a known bookmark.';
  } else if (riskScore >= 25) {
    classification = 'suspicious indicators';
    verdict = 'SUSPICIOUS';
    summary =
      'This link includes unusual structural or transport characteristics that warrant caution before visiting.';
    recommendedGuidance =
      'Verify the sender and check the exact domain spelling before proceeding. Do not enter credentials if the page requests an unexpected sign-in.';
  } else {
    classification = 'no obvious lexical indicators';
    verdict = 'LOW RISK';
    summary =
      'No obvious lexical or destination-boundary risk indicators were found in this URL structure.';
    recommendedGuidance =
      'Lexical analysis inspects only the URL text and does not fetch page content. Always confirm you recognize the domain before signing in.';
  }

  const signals =
    indicators.length > 0
      ? indicators.map((i) => `${i.title}: ${i.explanation}`)
      : [
          'Uses standard HTTPS encryption.',
          'Domain name structure appears standard with no obvious lexical anomalies.',
        ];

  const analysisPreview: ThreatCheckAnalysis = {
    normalizedDisplayUrl: redaction.normalizedDisplayUrl,
    hostname: normalizedDomain,
    verdict,
    summary,
    signals,
    recommendation: `${recommendedGuidance} ${LEXICAL_LIMITATIONS_STATEMENT}`,
  };

  return {
    valid: true,
    submittedUrlRedacted: redaction.submittedUrlRedacted,
    normalizedDisplayUrl: redaction.normalizedDisplayUrl,
    normalizedDomain,
    protocol: parsed.protocol as 'http:' | 'https:',
    verdict,
    classification,
    riskScore,
    summary,
    recommendedGuidance,
    limitationsStatement: LEXICAL_LIMITATIONS_STATEMENT,
    restrictedDestination,
    restrictedReason,
    indicators,
    analysisPreview,
  };
}

/**
 * Escapes a single CSV cell and neutralizes spreadsheet formula injection
 * when a cell starts with `=`, `+`, `-`, `@`, `\t`, or `\r`.
 */
export function escapeCsvCellSafe(value: unknown): string {
  if (value === null || value === undefined) {
    return '""';
  }
  let str = String(value).replace(/\r?\n/g, ' ').trim();
  if (/^[=+\-@\t\r]/.test(str)) {
    str = `'${str}`;
  }
  const escapedQuotes = str.replace(/"/g, '""');
  return `"${escapedQuotes}"`;
}
