# NETRA

**Evidence-grounded cybersecurity decision intelligence.**

NETRA turns security records into traceable, prioritised and explainable findings, and supports
controlled, human-authorised response decisions. It is a final-year project: a FastAPI + PostgreSQL
backend and a React + TypeScript frontend, developed and verified locally.

The project is built around one question: given the security records and context that are actually
available, what should be investigated first, why, and what is a sensible next step? NETRA shows its
reasoning (evidence references, factors, missing information) instead of presenting an unexplained
score.

**Lifecycle:** Detect → Understand → Prioritise → Verify → Authorize → Contain (simulated) → Learn

> More documentation: [Project documentation](docs/PROJECT_DOCUMENTATION.md) ·
> [Demo and viva guide](docs/DEMO_AND_VIVA.md) · [Dataset imports](docs/DATASET_IMPORTS.md) ·
> [Demo data and accounts](docs/DEMO_DATA.md) ·
> [Security Assessment migration notes](docs/SECURITY_ASSESSMENT_MIGRATION.md) ·
> [ThreatFox threat intelligence](docs/THREAT_INTEL_THREATFOX.md)

---

## 1. Problem statement

Security teams receive events, alerts, asset details, vulnerabilities and threat indicators from
separate sources. Reviewed separately, it is hard to tell which records are related, which risks
deserve attention first, and why a response is recommended. A useful decision-support tool must
connect evidence, expose uncertainty, explain priorities and keep a record of what was decided.

## 2. Objectives and scope

- Ingest security CSV files through authenticated upload: any structurally valid security CSV via a
  previewed, user-confirmed field mapping, plus the public **CIC-IDS2017** dataset via its own
  profile, with schema and row validation, duplicate handling and import-batch provenance.
- Store accepted rows as normalised security events that keep a link to their source batch and row.
- Correlate and enrich incidents only where implemented rules and available evidence support it.
- Produce explainable risk scores and security assessments with evidence references and stated gaps.
- Support decision recommendations, separation-of-duties authorisation, **simulated** containment
  and verification, and lessons recorded in Cyber Memory.

**Out of scope or not claimed:** real host isolation or firewall changes, live SIEM/EDR or live-feed
adapters, AI/LLM analysis or autonomous learning, non-CSV formats or automatic import without a confirmed mapping, and
NETRA's own detection rules over imported dataset flows. See [Known limitations](#13-demo-instructions-and-known-limitations).

## 3. Architecture and technology stack

```
Browser (React SPA, Vite dev server :5173)
        │  HTTPS/JSON, Bearer JWT
        ▼
FastAPI backend (/api, uvicorn :8001 locally)
  routers (app/api) → services (app/services) → SQLAlchemy models (app/models)
        │
        ▼
PostgreSQL (local database "netra"; isolated test database "netra_e2e")
```

| Layer | Technology (as pinned in the repository) |
|---|---|
| Frontend | React 19, TypeScript 6, Vite 8, Tailwind CSS 4, shadcn/ui (Radix), Lucide, Recharts, React Router 7 |
| Backend | Python 3.13, FastAPI 0.141, Pydantic 2 / pydantic-settings, SQLAlchemy 2.1, Alembic 1.16, psycopg 3, PyJWT, pwdlib (Argon2) |
| Database | PostgreSQL (developed and tested on 18.6; INET and JSONB columns are used) |
| Tests | pytest (backend), Node's built-in test runner (frontend), oxlint, `tsc` |

A diagram and the full data flow are in [docs/PROJECT_DOCUMENTATION.md](docs/PROJECT_DOCUMENTATION.md#5-system-architecture-and-data-flow).

## 4. Main modules

| Module | Backend | Frontend page | Responsibility |
|---|---|---|---|
| Authentication | `api/auth.py`, `services/auth.py`, `services/password_reset.py` | Login, Register, Forgot/Reset password | JWT login, current user, optional self-registration, emailed password reset |
| Dataset import | `api/imports.py`, `services/dataset_import.py`, `dataset_profiles.py`, `security_csv.py`, `csv_preview.py`, `dataset_normalization.py` | Dataset Import | Preview and map security CSVs; validate uploads against a profile; record batches; normalise accepted rows into events |
| Event intake | `api/events.py`, `api/collector.py`, `services/intake.py`, `services/collector.py` | Security Events, Live Event Collector | List/inspect events; authenticated manual event submission |
| Incidents | `api/incidents.py`, `services/event_correlation.py`, `context_enrichment.py`, `risk_engine.py`, `prioritization.py` | Incidents, Incident details | Create incidents, link and correlate events, enrich context, calculate explainable risk, prioritise |
| Decision and response | `api/decisions.py`, `api/authorizations.py`, `api/containments.py`, `services/decision_workflow.py`, `controlled_response.py` | Incident details | Recommend an action, request/approve/reject authorisation, **simulate** containment, verify outcome |
| Cyber Memory | `api/cyber_memory.py`, `services/controlled_response.py` | Cyber Memory | Record incident outcome and lessons learned |
| Security Assessment | `api/assessments.py`, `services/assessment.py`, `assessment_engine.py` | Security Assessment | Deterministic, evidence-cited asset assessments stored as immutable snapshots |
| Assets and threat intelligence | `api/assets.py`, `api/threat_intelligence.py` | Assets, Threat Intelligence | Read-only inventory, vulnerabilities and indicators (no create API) |
| Dashboard | `api/dashboard.py`, `api/health.py` | Command Center | Aggregate statistics and health checks |

## 5. Dataset ingestion, validation, deduplication and provenance

Full reference: [docs/DATASET_IMPORTS.md](docs/DATASET_IMPORTS.md).

- **Preview:** `POST /api/imports/preview` detects encoding, delimiter and suggested field mappings
  and records nothing.
- **Upload:** `POST /api/imports` (multipart: one `.csv` file part `file`, one field `profile` and,
  for `security-csv`, one JSON field `mapping`).
  It requires authentication and the `operate_workflow` permission, and is limited to 10 uploads per
  user per minute. The default caps are 25 MiB and 100,000 rows (`IMPORT_MAX_UPLOAD_BYTES`,
  `IMPORT_MAX_ROWS`).
- **Profiles:**
  - `security-csv` (v1) maps any column names and order to NETRA's event fields (timestamp, event
    type, IPs, ports, protocol, severity, message, outcome, label) as `security_event` or
    `network_flow` records. It supports comma/semicolon/tab/pipe delimiters, UTF-8/UTF-16/Windows-1252
    and ISO 8601, day/month, month/day, RFC 2822 and Unix timestamps. Accepted rows are stored as
    `info` events; the file's severity and labels are kept for reference only.
  - `generic-csv` checks structure only and stores no rows.
  - `cic-ids2017` (v1) requires the exact 85-column CIC-IDS2017 header in order; `Fwd Header Length`
    appears at both columns 41 and 62. It validates addresses, ports, protocol, timestamp, label and
    numeric features.
- **Validation report:** row, column and rule for each issue, never cell contents. A sample of up
  to 100 issues is stored with the true total.
- **Normalisation (CIC-IDS2017; `security-csv` is analogous, see the reference):** rows that passed validation in a validated batch become
  `security_events` with:
  - `source = dataset_import`, `event_type = network_flow` and **severity `info`**;
  - `import_batch_id` and `source_row`, both set;
  - all 85 source fields kept in `raw_data`.

  The dataset's `Label` is kept as **ground truth, not as a detection**. The batch and its events are
  committed in one transaction.
- **Deduplication:**
  - A file (by SHA-256) is validated at most once per profile version; a re-upload returns `409`.
  - Rejected files do not reserve their hash.
  - A row identical to an already stored event is counted in `duplicateRows` instead of being stored
    again.
- **Asset linking:** at import time only, when exactly one asset's IP equals the row's source or
  destination IP (rule `exact-ip-match-v1`). The outcome is recorded on the event.
- **Timestamp assumptions:** CIC-IDS2017 timestamps have no AM/PM or time zone. NETRA reads them on
  a 12-hour clock (1–5 = afternoon) in UTC−03:00. Both readings are **unverified assumptions**,
  recorded on every event.

## 6. Evidence-backed findings and explainable assessment

- **Security Assessment** (`POST /api/assessments`) scores one asset with methodology
  `assessment-v2`:
  - it starts at 100 and deducts by severity (critical 25, high 15, medium 8, low 3, info 0);
  - grades are A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, otherwise F.
- **What it checks:** asset exposure and criticality, open vulnerabilities, missing CVSS scores,
  accepted-risk exposure, active incidents, recent high-severity events, matches against active
  IP threat indicators, inventory completeness, and activity on inactive assets.
- **Evidence:** every finding stores the vulnerability, incident and event IDs it relied on, with
  totals when lists are capped at 100, plus `missingEvidence` for information that was not available.
- **Time window:** events are read from the 7 days ending at `asOf`. `asOf` defaults to now; the
  Assessment page's optional "Event window ends (UTC)" field sets it, so a historical dataset
  (CIC-IDS2017 is July 2017) can be assessed in its own time.
- **Incident risk** (`POST /api/incidents/{id}/risk-score`) is a weighted, documented heuristic:
  asset criticality 0.25, vulnerability 0.20, anomaly 0.20, detection confidence 0.15, threat
  intelligence 0.10, attack context 0.10. Each factor's rationale is returned.
- **Risk evaluation history:** each successful calculation also stores an append-only
  `risk_evaluations` row (migration `0006_add_risk_evaluations`) in the same transaction as the score:
  score, level, methodology version (`risk-v1`), factor breakdown, missing evidence, matched active
  indicators, trigger and actor. `GET /api/incidents/{id}/risk-evaluations` (any signed-in user)
  returns them oldest first, read-only and never recalculated; an empty list before the first
  calculation, `404` for an unknown incident and `401` without a token. Incident details show them
  in the "Risk evaluations" panel.

## 7. Assessment history and persistence

Each run stores an **immutable snapshot** (`security_assessments` + `assessment_findings`) with its
methodology version, `asOf`, score, grade, input counts and findings. Earlier snapshots are never
recalculated. `GET /api/assessments` (filters and paging) and `GET /api/assessments/{id}` return the
stored result, so results are the same after a page refresh.

## 8. Authentication, authorisation and controlled response

- **Login:** `POST /api/auth/login` returns a JWT (HS256, 60-minute default lifetime). Passwords
  are hashed with Argon2.
- **Every request:** the user's role and active status are re-read from the database, so a
  deactivation or role change applies immediately.
- **Self-registration** is **off by default** (`ALLOW_PUBLIC_REGISTRATION=false`); when enabled, it
  always creates `operator` accounts. Administrators create accounts and assign roles with
  `backend/scripts/netra_users.py` (see [docs/DEMO_DATA.md](docs/DEMO_DATA.md#accounts-and-roles)).
- **Roles** (`backend/app/core/permissions.py`):

  | Role | Permissions |
  |---|---|
  | `operator` | `operate_workflow`, `request_authorization`, `execute_containment` |
  | `approver`, `admin` | all of the above plus `resolve_authorization` (approve/reject) |

- **Separation of duties:** an authorisation must be approved by someone other than the requester.
- **Containment is simulated.** `POST /api/authorizations/{id}/contain` records a simulated action
  (`"simulated": true`); no host, firewall or account is changed. Verification and Cyber Memory
  complete the lifecycle.
- **Password reset** works by email (`EMAIL_*` settings). Until it is configured,
  `/api/auth/forgot-password` returns `503`.

## 9. Local prerequisites and setup

**Prerequisites:** Windows 10/11 (commands below are PowerShell), Python 3.13, Node.js 22,
PostgreSQL 18 (16 or later recommended), Git.

```powershell
# Backend
cd backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env        # then edit .env (see section 10)

# Frontend
cd ..\frontend
npm install
Copy-Item .env.example .env.development.local   # then set VITE_API_BASE_URL (see section 10)
```

## 10. Environment variables, migrations and safe local database setup

**`backend/.env`** (never commit it; `.gitignore` excludes `.env.*` except `.env.example`):

| Variable | Required | Notes |
|---|---|---|
| `DATABASE_URL` | yes | `postgresql+psycopg://<user>:<password>@localhost:5432/netra`. **URL-encode special characters in the password** (e.g. `@` → `%40`). |
| `JWT_SECRET_KEY` | yes | Random secret, at least 32 characters. |
| `JWT_ALGORITHM`, `ACCESS_TOKEN_EXPIRE_MINUTES` | no | Defaults `HS256`, `60`. |
| `CORS_ORIGINS` | no | JSON list. Default `["http://localhost:5173","http://127.0.0.1:5173"]`. |
| `ALLOW_PUBLIC_REGISTRATION` | no | Default `false`. |
| `EMAIL_HOST`, `EMAIL_PORT`, `EMAIL_USERNAME`, `EMAIL_PASSWORD`, `EMAIL_FROM`, `FRONTEND_BASE_URL`, `PASSWORD_RESET_TOKEN_EXPIRE_MINUTES` | no | Password-reset email. |
| `IMPORT_MAX_UPLOAD_BYTES`, `IMPORT_MAX_ROWS` | no | Upload caps (defaults 25 MiB, 100,000 rows). |

**`frontend/.env.development.local`:** `VITE_API_BASE_URL=http://127.0.0.1:8001` (the backend URL
without `/api`; the dev default is `http://127.0.0.1:8000`) and `VITE_USE_MOCKS=false`. Setting
`VITE_USE_MOCKS=true` runs the UI on bundled demo data with no backend. Security Assessment and
Dataset Import have no mock mode.

**Schema ownership: read before running Alembic.** Migration `0001` creates only `users`. The core
tables (assets, events, incidents, decisions and so on) are created by `app.db.init_db`, and
migrations `0002`–`0006` add the remaining tables and columns with guards for tables that already
exist. Therefore:

```powershell
cd backend
# Fresh, empty local database "netra" (create it first, e.g. with createdb or pgAdmin):
.\.venv\Scripts\python.exe -m app.db.init_db           # creates every table from the models
.\.venv\Scripts\python.exe -m alembic stamp head       # records the schema version; runs no DDL

# Existing database tracked by Alembic: back it up first, then
.\.venv\Scripts\python.exe -m alembic current
.\.venv\Scripts\python.exe -m alembic upgrade head     # head = 0006_add_risk_evaluations
```

**Safety:**
- Run these commands from `backend\` so `.env` is the configuration used; a `DATABASE_URL` set in
  the shell wins over `.env`.
- Online Alembic runs against a non-local host (for example Neon) are refused before connecting unless
  `NETRA_MIGRATION_CONFIRM_TARGET` names that exact `host:port/database` (`app/db/migration_guard.py`).
  Local targets are unaffected. Backend tests run only through `scripts\netra_e2e_pytest.py run`; any
  other pytest invocation is refused before it can reach a database (`tests/_launch_guard.py`).
- Back up with `pg_dump -Fc` before any migration, and verify the archive with `pg_restore --list`.
- Never point these commands at a shared or production database. Alembic revision IDs must be at
  most 32 characters (a regression test enforces this).

**Optional demo data** (dry run by default; `--apply` writes):

```powershell
.\.venv\Scripts\python.exe -m app.db.seed_demo                       # fictional demo incidents/assets
.\.venv\Scripts\python.exe -m app.db.seed_dataset_context            # CIC-IDS2017 demo asset + indicator
.\.venv\Scripts\python.exe -m app.db.seed_dataset_context --apply --confirm-target localhost:5432/netra
.\.venv\Scripts\python.exe scripts\netra_users.py list               # accounts (read-only)
```

## 11. Starting the application

```powershell
# Terminal 1: backend (from backend\)
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8001
# Health: http://127.0.0.1:8001/api/health and /api/health/db; OpenAPI docs: http://127.0.0.1:8001/docs

# Terminal 2: frontend (from frontend\)
npx vite --host 127.0.0.1 --port 5173 --strictPort    # or: npm run dev
# Open http://127.0.0.1:5173
```

If the UI reports "Cannot reach the NETRA API", check that the backend is running and that the page's
origin (for example `http://127.0.0.1:5173`) is listed in `CORS_ORIGINS`.

## 12. Tests and test-database safeguards

**Frontend** (from `frontend\`):

```powershell
npm test                                   # node --test tests/*.test.ts
npx tsc -p tsconfig.app.json --noEmit      # type check
npm run lint                               # oxlint
npm run build                              # tsc -b && vite build
```

**Backend: never run plain `pytest` from `backend\`.** The tests create throwaway PostgreSQL
schemas (always rolled back) on whatever database the settings resolve to. Settings come from
environment variables first, then `.env` in the current directory, so plain `pytest` would run
against the development database. Backend tests must run only against the isolated local database
**`netra_e2e`**:

1. Create `backend/.env.e2e` with the same keys as `.env`, `DATABASE_URL` pointing to
   `localhost:5432/netra_e2e`, and a **different** `JWT_SECRET_KEY`. It is gitignored.
2. Prepare and check it with the repository guard (it refuses any target other than local
   `netra_e2e`):
   ```powershell
   .\.venv\Scripts\python.exe scripts\netra_e2e.py check
   .\.venv\Scripts\python.exe scripts\netra_e2e.py create-db
   .\.venv\Scripts\python.exe scripts\netra_e2e.py init-schema
   .\.venv\Scripts\python.exe scripts\netra_e2e.py stamp
   .\.venv\Scripts\python.exe scripts\netra_e2e.py status
   ```
3. Run the tests **only** through the guarded launcher `backend/scripts/netra_e2e_pytest.py`, from
   `backend\`, with the virtual environment's interpreter and always with `-I -B`. It refuses
   anything else.
   ```powershell
   .\.venv\Scripts\python.exe -I -B scripts\netra_e2e_pytest.py selftest   # synthetic guard checks; reads no credential file
   .\.venv\Scripts\python.exe -I -B scripts\netra_e2e_pytest.py check      # validates .env.e2e offline; no connection
   .\.venv\Scripts\python.exe -I -B scripts\netra_e2e_pytest.py run -q     # whole backend/tests suite
   .\.venv\Scripts\python.exe -I -B scripts\netra_e2e_pytest.py run --path tests/test_dataset_normalization.py -v
   ```
   - **`run` options:** `--path` (repeatable, must stay inside `backend/tests`, `::node` allowed),
     `-x`, `-q`, `-v`, `-k EXPR`, and `--pg-bin DIR`. The default PostgreSQL bin directory is
     `C:\Program Files\PostgreSQL\18\bin`; `NETRA_PG_BIN` overrides it.
   - **Target checks:** before any test, `run` reuses the checks in `scripts/netra_e2e.py` (local
     host, database exactly `netra_e2e`, a JWT secret different from `.env`) and only allows port 5432.
   - **Child environment:** pytest starts in a child process whose environment is the `.env.e2e`
     settings alone, with every `PG*`, `PYTEST_*` and `PYTHON*` variable removed.
   - **No `.env` in reach:** the child works in `%TEMP%\netra_e2e_pytest_run`, outside the
     repository, and the launcher refuses a run folder inside the repo or one holding anything other
     than its empty `pytest.ini`.
   - **Local server only:** it proves the target is a local `postgres.exe`, from the Windows
     listener table and the connected server process. Port forwards, SSH tunnels and Docker or WSL
     PostgreSQL are refused. The launcher is Windows-only.

The latest recorded full run through this launcher, on 2026-10-12, was **761 passed, 1 skipped**.
The skipped test needs the real CIC-IDS2017 files via `NETRA_CIC_DATASET_DIR`. The launcher's
`selftest` reports 92 passed. The latest frontend run was **78/78 passed**.

## 13. Demo instructions and known limitations

**Demo:** follow [docs/DEMO_AND_VIVA.md](docs/DEMO_AND_VIVA.md). It covers dataset upload, the
import summary, source-row provenance, an assessment with a historical event window, cited
findings, and saved history.

**Known limitations**

- **Detections:** NETRA has no detection rules of its own over imported flows. Imported rows are
  `info` events, and dataset labels are ground truth, not detections.
- **Assessment evidence:** imported events reach findings only through existing evidence rules
  (for example, a match with an active IP threat indicator) and only if an asset with the row's IP
  existed **before** the upload.
- **No create API:** there is no API for creating assets or threat indicators. Demo context comes
  from guarded seed modules.
- **Timestamps:** the CIC-IDS2017 time-zone and AM/PM readings are unverified assumptions.
- **Large files:** uploads are processed within the request, with no background jobs or progress.
  Full CIC-IDS2017 files exceed the default caps; upload extracts. The Security Events page loads
  the most recent 2,000 events and says so when it truncates.
- **Containment** is simulated. There are no live SIEM/EDR or live-feed integrations.
- **Not yet measured:** precision/recall and throughput evaluations (PDF §10).
- **Testing and deployment:**
  - the guarded backend test launcher supports Windows and a native local PostgreSQL only;
  - there is no CI;
  - production deployment (Vercel/Render/Neon) and migration parity have not been verified for this
    version.

## Repository layout

```
backend/    FastAPI app (app/api, app/services, app/models, app/schemas, app/db), Alembic migrations, scripts, tests
frontend/   React + TypeScript SPA (src/pages, src/services, src/lib, src/components), tests
docs/       Project, dataset-import, demo-data, assessment-migration and demo/viva documentation
GeneratedLabelledFlows/   Local CIC-IDS2017 CSVs (gitignored; obtain from the official CIC source)
```
