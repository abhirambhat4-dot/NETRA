# NETRA Frontend

React frontend for NETRA — Cyber Decision Intelligence Platform.

## Stack

Vite · React 19 · TypeScript · Tailwind CSS v4 · shadcn/ui (Radix) · Lucide · Recharts · React Router

## Commands

```bash
npm install
npm run dev      # http://localhost:5173
npm run build    # type-check + production build
npm run lint
```

## Structure

```
src/
  api/types.ts   API contract (shared with backend)
  components/    Reusable UI (components/ui = shadcn primitives)
  layouts/       App shell (sidebar, header)
  pages/         Route-level screens
  mocks/         Interconnected mock data
  services/      Data access layer (mock now, FastAPI later)
  hooks/         React hooks
  lib/           Utilities
```

See [../docs/ARCHITECTURE.md](../docs/ARCHITECTURE.md).
