# Dependency audit — Prompt 0024

## Advisory

- **GHSA-ggr8-5vv4-36mx** — `deepmerge-ts` < 8.0.0 (high): stack exhaustion on recursive object graphs.
- Path (single chain, reported three times by npm):  
  `prisma@6.19.3` → `@prisma/config@6.19.3` → `deepmerge-ts@7.1.5`
- Affects **Prisma CLI / config tooling**, not `@prisma/client` query runtime directly.

## Why not a Prisma major bump

- No Prisma **6.x** release pins `deepmerge-ts` ≥ 8.
- Prisma **7.x** still depends on `deepmerge-ts@7.1.5`.
- Prisma **8** is RC-only at audit time — not adopted.

## Remediation applied

```json
"overrides": { "deepmerge-ts": "8.0.2" }
```

- Pins `prisma` and `@prisma/client` to **6.19.3** (aligned).
- `npm audit`: **0 vulnerabilities**.
- CLI smoke: `npx prisma --version` OK with override.

## Verification

- `npm run lint` PASS  
- `npm test` 73/73 PASS  
- `npm run build` PASS  

PostgreSQL integration not re-run in this environment if the server was unavailable.
