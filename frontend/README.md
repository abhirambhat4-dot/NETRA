# NETRA Frontend

React frontend for NETRA, an evidence-grounded cybersecurity decision intelligence platform. Project
overview, setup and limitations: [../README.md](../README.md).

## Stack

Vite · React 19 · TypeScript · Tailwind CSS v4 · shadcn/ui (Radix) · Lucide · Recharts · React Router

## Configuration

Copy `.env.example` to `.env.development.local` and set:

| Variable | Meaning |
|---|---|
| `VITE_API_BASE_URL` | Backend URL without `/api`, e.g. `http://127.0.0.1:8001`. The dev server falls back to `http://127.0.0.1:8000`; production builds must set it. |
| `VITE_USE_MOCKS` | `true` uses bundled demo data and makes no backend calls. Leave `false` to use the FastAPI backend. Security Assessment and Dataset Import have no mock mode. |

## Commands

```bash
npm install
npm run dev                              # Vite dev server (http://localhost:5173)
npx vite --host 127.0.0.1 --port 5173 --strictPort   # same, bound to 127.0.0.1
npm test                                 # node --test tests/*.test.ts
npx tsc -p tsconfig.app.json --noEmit    # type check only
npm run lint                             # oxlint
npm run build                            # type-check + production build (dist/)
```

The backend allows the origins `http://localhost:5173` and `http://127.0.0.1:5173` by default
(`CORS_ORIGINS`).

## Structure

```
src/
  api/types.ts   API contract types (backend responses and requests)
  components/    Reusable UI (components/ui = shadcn primitives, components/netra = app components)
  layouts/       App shell (sidebar, header)
  pages/         Route-level screens (imports, events, incidents, assessments, ...)
  mocks/         Interconnected mock data (used only when VITE_USE_MOCKS=true)
  services/      Data access layer: live FastAPI client, or mocks
  hooks/         React hooks
  lib/           Pure helpers (unit-tested in tests/)
tests/           node:test unit tests
```

See [../docs/PROJECT_DOCUMENTATION.md](../docs/PROJECT_DOCUMENTATION.md) for the architecture.
