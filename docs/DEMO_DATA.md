# NETRA demo dataset

`backend/app/db/seed_demo.py` creates a small, fictional dataset (`netra-demo-v1`) that walks
NETRA's intelligence workflow end to end. It is safe to run repeatedly: existing records are
reused, never updated or deleted, and a conflicting record stops the run before anything is written.

## Commands

Run from `backend/` with the virtual environment active.

```powershell
python -m app.db.seed_demo           # dry run: read-only report (default)
python -m app.db.seed_demo --apply   # create missing demo records and advance incidents
```

The first line of output names the target as `local PostgreSQL` or `remote PostgreSQL (*.neon.tech)`.
The connection string is never printed. Check that line before running `--apply`.

To target Neon without changing `backend/.env`, keep the Neon `DATABASE_URL` (with `sslmode=require`)
and `JWT_SECRET_KEY` in `backend/.env.neon`, which is gitignored, and load it for one command:

```powershell
.\.venv\Scripts\python.exe -m dotenv -f .env.neon run -- .\.venv\Scripts\python.exe -m app.db.seed_demo
.\.venv\Scripts\python.exe -m dotenv -f .env.neon run -- .\.venv\Scripts\python.exe -m app.db.seed_demo --apply
```

Use the virtual environment's interpreter on both sides of `run --`: a bare `python` after
`run --` can resolve to a different Python installation without NETRA's dependencies.

Prerequisite: the NETRA tables must already exist. The seed checks for them and stops if any are
missing; it never creates or migrates schema.

## What it creates

| Type | Records |
|---|---|
| Assets | `DEMO-DB-01` Customer DB (critical, internal), `DEMO-WEB-01` Public portal (high, internet-facing), `DEMO-WS-07` Analyst workstation (medium, internal) |
| Vulnerabilities | `DEMO-CVE-2026-0001` (CVSS 9.8), `-0002` (7.5), `-0003` (5.4), all fictional and open |
| Threat indicators | `203.0.113.45`, `198.51.100.77`, `c2.netra-demo.example`, source `NETRA Demo Feed` |
| Events | 9, `event_uid` prefix `netra-demo-`, `raw_data` contains `{"netra_demo": true, "dataset": "netra-demo-v1"}` |
| Incidents | 3, keys `INC-DEMO-0001` to `-0003`, titles prefixed `[NETRA DEMO]` |

All addresses come from reserved documentation ranges (`203.0.113.0/24`, `198.51.100.0/24`) or
private `10.250.0.0/16`; hostnames use `*.netra-demo.example`. Workflow steps record the actor
`netra-demo-seed`. Containment uses the existing simulation only.

## Scenarios

| Incident | Seeded to | Risk | Decision | Use in the demo |
|---|---|---|---|---|
| `INC-DEMO-0001` | LEARNED | 75.9 | ISOLATE_HOST | Complete trail: every stage, timeline and Cyber Memory |
| `INC-DEMO-0002` | VERIFIED, authorization PENDING | 60.95 | BLOCK_IP | Live: Approve → Contain → Verify containment → Cyber Memory in the UI |
| `INC-DEMO-0003` | PRIORITISED | 32.8 | INVESTIGATE | Contrast: NETRA does not escalate everything |

Event times are set relative to the first `--apply` (within the previous two hours), so seed
within 24 hours of a demo if the Dashboard's 24-hour counters should include them. Re-runs never
move timestamps.

## Re-running

- A second `--apply` reports `Created: 0 records; workflow steps run: 0`.
- An interrupted run resumes the missing workflow steps on the next `--apply`.
- An incident already past its seed target (for example `INC-DEMO-0002` after the live demo) is
  reported and left as is. The seed has no reset mode; a consumed live incident stays consumed.

Exit codes: `0` success, `1` a workflow step failed (details printed), `2` blocked by missing
tables or conflicting records (nothing written).
