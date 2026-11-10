# VAJRA Web Console (`apps/web`)

## Active Runtime Architecture

The active VAJRA Web Console architecture is:

```text
React 19 + TypeScript + Tailwind CSS v4 + Vite (Frontend SPA)
                        +
      Node.js + Express + TypeScript (Backend API)
```

- **Unified Full-Stack Entry Point (`server.ts`):** Serves the Express REST API (`src/server/app.ts`) and mounts the Vite application on port `3000` in development (or serves static `dist/` assets in production).
- **Source Location:** Active Web Console components live in `/src` (`src/App.tsx`, `src/data/mockFoundationData.ts`, `src/index.css`) and import shared contracts from `@vajra/shared-types`, `@vajra/security`, and `@vajra/config`.
- **Specifications:** See [`docs/product/PRD.md`](../../docs/product/PRD.md), [`docs/product/security-timeline.md`](../../docs/product/security-timeline.md), and [`docs/product/mvp.md`](../../docs/product/mvp.md).
