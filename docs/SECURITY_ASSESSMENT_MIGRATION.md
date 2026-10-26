# Security Assessment: migration 0003 readiness

Migration `0003_add_security_assessments` adds the two tables behind Security Assessment:
`security_assessments` (one append-only snapshot per run) and `assessment_findings` (nine findings
per snapshot). It creates nothing else and alters no existing table.

Status: recorded 2026-10-26. Re-run the read-only checks below before acting on any of these states.

| Database | Alembic revision | Notes |
|---|---|---|
| Neon production | `0007_event_attack_techniques` (migrated 2026-10-26 from `0005_dataset_event_provenance`; PostgreSQL 18.6) | 0003 is applied. `0006_add_risk_evaluations` and `0007_event_attack_techniques` were applied in the Neon SQL Editor and verified: both tables exist, all five expected indexes are present, 3 incidents and 9 security events were kept, and both new tables were empty. See [PRODUCTION_BACKUP.md](PRODUCTION_BACKUP.md#production-migration-record-2026-10-26). |
| Neon rehearsal branches | `0007_event_attack_techniques` | `netra-migration-test` and `netra-migration-test-2`, created from production; the production SQL was rehearsed on `netra-migration-test-2` first. |
| Local `netra_e2e` | Not recorded here | Set up by `backend/scripts/netra_e2e.py`: `init-schema` (`app.db.init_db`), then `stamp` (`alembic stamp head`). |

*Historical (2026-10-12, superseded):* the Neon test branch was recorded at `0004_add_import_batches`
and production at `0002_add_password_reset_tokens`; production was later verified at `0005` on
2026-10-26, before the migration above.

Before the 2026-10-26 migration, a manual Neon snapshot of production was taken and a separate backup
branch exists. These are Neon-side restore points, **not** a verified logical backup: no `pg_dump`
archive has been taken and no restore has been tested. Before any further production upgrade, follow
[PRODUCTION_BACKUP.md](PRODUCTION_BACKUP.md) (verified backup and a local restore rehearsal, then stop for
review).

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

## Non-local targets need explicit confirmation

Alembic resolves its database exactly as the application does: a `DATABASE_URL` set in the shell first,
then `backend/.env`. To stop a shell variable left pointing at Neon from being migrated by accident,
`backend/migrations/env.py` checks the target before it creates any engine (`app/db/migration_guard.py`):

- **Local targets** (`localhost`, `127.0.0.1`, `::1`) run as before, including `scripts/netra_e2e.py stamp`.
- **Any other host, including every Neon branch,** is refused unless `NETRA_MIGRATION_CONFIRM_TARGET` names
  that exact `host:port/database`. Only the host, port and database are compared and printed, never the user
  name or password. A confirmation for a different branch or database is refused.
- **Always refused:** URL options that could redirect the connection (`host`, `hostaddr`, `port`, `dbname`,
  `service`, `servicefile`) and libpq variables (`PGHOST`, `PGHOSTADDR`, `PGPORT`, `PGDATABASE`, `PGSERVICE`,
  `PGSERVICEFILE`).
- **Offline** (`--sql`) runs never connect and are not checked.

For an approved run against a Neon branch, set the confirmation in the same shell only for that command,
using the exact `host:port/database` the refusal message prints, then remove it:

```powershell
# DATABASE_URL already set (without printing it) to the approved Neon branch
$env:NETRA_MIGRATION_CONFIRM_TARGET = '<host>:5432/<database>'   # exactly as printed by the refusal
.\.venv\Scripts\python.exe -m alembic current                     # read-only check first
.\.venv\Scripts\python.exe -m alembic upgrade head
Remove-Item env:NETRA_MIGRATION_CONFIRM_TARGET
```

The guard only checks that the target is the one you meant; it does not replace the backup, the branch-first
run or the approval each production write needs.

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
