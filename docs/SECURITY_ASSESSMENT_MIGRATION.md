# Security Assessment: migration 0003 readiness

Migration `0003_add_security_assessments` adds the two tables behind Security Assessment:
`security_assessments` (one append-only snapshot per run) and `assessment_findings` (nine findings
per snapshot). It creates nothing else and alters no existing table.

Status: last reported states, recorded 2026-10-12. These are not fresh observations: no production
database was queried when this was written. Re-run the read-only checks below before acting on them.

| Database | Last reported Alembic revision | Notes |
|---|---|---|
| Neon test branch | `0004_add_import_batches` (head) | 0003 and 0004 applied to the test branch. |
| Neon production | `0002_add_password_reset_tokens` | 0003 **not** applied. |
| Local `netra_e2e` | Not recorded here | Set up by `backend/scripts/netra_e2e.py`: `init-schema` (`app.db.init_db`), then `stamp` (`alembic stamp head`). |

No production backup or production Neon branch is recorded in this repository. Take one, and record
it, before the upgrade below.

## What the migration needs

| Prerequisite | Why |
|---|---|
| `assets` table | Foreign key `security_assessments.asset_id → assets.id`. `assets` is created by `python -m app.db.init_db`, not by Alembic, so an Alembic-only database cannot run 0003. |
| `users` table | Foreign key `security_assessments.requested_by_id → users.id` (created by 0001 or `init_db`). |
| Alembic at `0002_add_password_reset_tokens` | 0003's `down_revision`. 0001 has no existence guard, so `alembic upgrade head` on a database with no `alembic_version` table fails at 0001 because `users` already exists. |
| PostgreSQL 16 or later (recommended) | Assessments use `pg_input_is_valid` to fetch only threat indicators that can match. On older servers the code falls back to loading every active IP indicator: results are identical, only slower. Not required for the migration itself. |

Each table is guarded by an existence check, so 0003 skips a table that already exists. A table
created from an older draft of 0003 would therefore be skipped as-is: the final schema includes
`vulnerability_total`, `incident_total` and `event_total` on `assessment_findings`.

## Read-only checks to run first

Run these in the Neon SQL editor (or any read-only session) and record the answers. They read
metadata only.

```sql
SHOW server_version;

SELECT to_regclass('public.alembic_version') IS NOT NULL AS has_alembic_version;
SELECT version_num FROM alembic_version;           -- only if the previous query returned true

SELECT table_name
FROM information_schema.tables
WHERE table_schema = 'public'
  AND table_name IN ('assets', 'users', 'password_reset_tokens',
                     'security_assessments', 'assessment_findings')
ORDER BY table_name;
```

If `security_assessments` or `assessment_findings` already exists, also compare its columns with
the model before going further:

```sql
SELECT table_name, column_name, data_type, is_nullable
FROM information_schema.columns
WHERE table_schema = 'public' AND table_name IN ('security_assessments', 'assessment_findings')
ORDER BY table_name, ordinal_position;
```

## Choosing the upgrade path

| What the checks show | Path |
|---|---|
| `alembic_version` = `0002_add_password_reset_tokens`; `assets` and `users` exist; neither assessment table exists | `alembic upgrade head` |
| `alembic_version` = `0001_add_users_table`; `password_reset_tokens` exists | `alembic upgrade head` (0002 sees the table and skips it, then 0003 runs) |
| No `alembic_version` table; `assets`, `users`, `password_reset_tokens` exist | Do not run `upgrade head`. Either `alembic stamp 0002_add_password_reset_tokens` then `alembic upgrade head`, or `python -m app.db.init_db` (creates only missing tables) then `alembic stamp head`. Decide which tool owns the schema going forward. |
| An assessment table already exists | Compare columns with the model. If they differ, stop: 0003 would skip the table and leave the old shape. |
| `assets` missing | Stop: the core schema is not in place. |

Before writing anything, take a Neon branch (or backup) and run the chosen path against the branch
first; then repeat on the production branch.

## Order of operations

1. Run the read-only checks and choose the path above.
2. Apply the migration (branch first, then production).
3. Deploy the backend. The assessment endpoints need the new tables; other endpoints are unaffected
   if the backend is deployed first, but `/api/assessments` would return errors until the tables exist.
4. Deploy the frontend (`/assessments` page and the Assets drawer's vulnerability list).
5. Run one assessment on any asset and confirm `GET /api/assessments` lists it. A run only adds a
   snapshot; it never changes assets, events, incidents or demo records.

## Rolling back

`alembic downgrade 0002_add_password_reset_tokens` drops both tables and every stored snapshot.
Snapshots are append-only history, so export them first if they matter. Rolling back the code
without dropping the tables is harmless: nothing else reads them.
