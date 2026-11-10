# Node workspace recovery (Prompt 0018)

## Root causes identified

1. **Broken npm registry default:** environment `npm config get registry` pointed at `http://35.245.43.102/npm/` which returned **404** on ping. Public `https://registry.npmjs.org/` responds normally.
2. **Invalid workspaces glob:** `"apps/*"` matched `apps/android` and `apps/windows-agent` (native projects **without** `package.json`), confusing npm workspaces.
3. **Corrupted local `node_modules`:** FUSE-backed tree exhibited **I/O errors**; `rm`/`mv` hung; size ~1MB of incomplete/temp dirs.
4. **Missing lockfile:** no `package-lock.json` for reproducible installs.

## Permanent repo fixes applied

| File | Change |
| :--- | :--- |
| `package.json` | `workspaces` → `["packages/*"]` only |
| `.npmrc` | `registry=https://registry.npmjs.org/` + retry settings (TLS not disabled) |
| `package-lock.json` | Generated via clean install against public registry (lockfileVersion 3) |

## Recovery commands (stable machine)

```bash
cd /path/to/vajra-personal-security-01-main
# If node_modules is corrupt:
rm -rf node_modules
npm install --legacy-peer-deps
npm run lint
npm test
npm run build
```

Use the project `.npmrc` (or pass `--registry https://registry.npmjs.org/`) so installs do not hit a broken private mirror.

## Verification observed in Prompt 0018

- Clean install in `/tmp` (non-FUSE): **252 packages in ~13–19s**, bins `tsx`/`tsc`/`vite`/`prisma` present.
- After bind-mount of that tree over project `node_modules`:
  - `npm run build` → **PASS** (Vite production build)
  - `npm test` → **executed** (71 tests; mix of pass/fail — failures are application/test issues, not install blockers)
  - `npm run lint` → **executed** (TypeScript reported real TS errors; see verification notes)

Bind mounts are environment-specific and not a substitute for a normal `npm install` on a healthy filesystem.
