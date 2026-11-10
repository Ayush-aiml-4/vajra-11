# VAJRA — Secure Development & Contribution Rules

Every contributor and automated workflow working on the **VAJRA** repository must adhere to the following engineering and security rules.

---

## 1. TypeScript Strictness & Type Safety
- **Strict Mode Enabled:** `strict: true`, `noImplicitAny: true`, and `strictNullChecks: true` are enforced in `tsconfig.json`.
- **Shared Contracts:** All domain models shared between the Web Console and Backend API must be defined in `@vajra/shared-types` (`packages/shared-types/src/index.ts`).
- **Avoid `any`:** Prefer explicit interfaces, discriminated unions, or `unknown` with runtime type narrowing.

## 2. Zero Hardcoded Secrets & Credential Hygiene
- **Never Commit Secrets:** Never commit `.env` files, private keys (`*.pem`, `*.key`, `*.p12`), database credentials, session secrets, or API keys to Git.
- **Use `.env.example`:** Whenever a new environment variable is introduced, document a safe, non-sensitive placeholder in `.env.example` and validate it in `@vajra/config`.
- **No Client-Side Secret Exposure:** Never expose backend environment variables or private credentials to client bundles or public API responses (such as `/api/health`).

## 3. Input Validation & Safe Logging
- **Validate All External Input:** Treat every HTTP request body, query parameter, header, device telemetry payload, and URL submitted to ThreatCheck as untrusted until validated against a strict schema.
- **Sanitize Logs:** Always pass structured metadata through `sanitizeLogMetadata()` from `@vajra/security` before logging so tokens, passwords, cookies, and authorization headers are automatically redacted as `[REDACTED]`.

## 4. Least Privilege & OS Permission Respect
- **Avoid Unnecessary Permissions:** Neither the Windows Agent nor the Android App may request OS permissions that are not strictly required for an active, user-enabled security feature.
- **Strict Command Allowlisting:** Remote commands must always map to a fixed enum (`RING_DEVICE`, `LOST_MODE_MESSAGE`, `REQUEST_HEARTBEAT`, `VERIFY_INTEGRITY`). Never introduce endpoints or handlers that accept shell strings or arbitrary scripts.
- **Check Prohibited Capabilities:** Any proposed feature must pass `isCapabilityPermitted()` in `@vajra/security`.

## 5. Dependency & Security Review
- **Review Dependencies:** Minimize third-party dependencies, especially in cryptographic, authentication, and agent modules.
- **Security-Sensitive Changes:** Any modification to `/api/auth`, `/api/commands`, `packages/security`, cryptographic key verification, or Prisma database schemas requires explicit threat-model review against `docs/security/threat-model.md`.

## 6. Verification Gate
Before completing any task or pull request, all four verification gates must pass with zero errors:
1. `npm run lint` / `npm run typecheck`
2. `npm test`
3. `npm run build`
