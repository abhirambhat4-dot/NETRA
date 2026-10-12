# NETRA: Demonstration and Viva Guide

This guide covers a 5–7 minute live demonstration, the screenshots worth capturing, likely viva
questions with answers, and a clear statement of what is implemented, simulated or planned.

**Expected results are labelled "Expected".** They come from the validator, the regression tests
and earlier local runs. They are not guaranteed for every database state; for example, a file that
was already uploaded is refused as a duplicate.

---

## 1. Before the demonstration (about 10 minutes beforehand)

1. **Backend** (from `backend\`):
   ```powershell
   .\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8001
   ```
   Check http://127.0.0.1:8001/api/health/db: expect `"database":"connected"`.
2. **Frontend** (from `frontend\`):
   ```powershell
   npx vite --host 127.0.0.1 --port 5173 --strictPort
   ```
   Open http://127.0.0.1:5173. `frontend/.env.development.local` must contain
   `VITE_API_BASE_URL=http://127.0.0.1:8001` and `VITE_USE_MOCKS=false`.
3. **Demo context** (local database only; dry run first, then `--apply`):
   ```powershell
   .\.venv\Scripts\python.exe -m app.db.seed_dataset_context
   .\.venv\Scripts\python.exe -m app.db.seed_dataset_context --apply --confirm-target localhost:5432/netra
   ```
   - It creates the asset `CIC-DEMO-WEB-50` (192.168.10.50) and an analyst-entered IP indicator for
     172.16.0.1.
   - It must exist **before** the upload, because events are linked to assets only at import time.
   - If it's already present, the script reports "nothing to write".
4. **Upload file:** a small extract of **real, unmodified** rows from
   `GeneratedLabelledFlows/TrafficLabelling/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`: the
   original header plus rows involving 192.168.10.50.
   - The prepared extract is `netra_cic_ids2017_friday_ddos_extract.csv` (in the presenter's
     Downloads folder): 14 rows. Eight flows go from 172.16.0.1 to .50 (labelled DDoS), two reply
     flows go from .50 to 172.16.0.1 (labelled BENIGN), and four internal flows go from
     192.168.10.12 to .50 (labelled BENIGN).
   - **If this file was already uploaded, uploading it again is refused with `409`** (duplicate
     protection). In that case, open the existing batch from Import history instead, or prepare a
     different extract.
5. **Sign in** with an existing account; the `operator` role is enough for this flow. Accounts are
   created with `backend\scripts\netra_users.py`, never in the UI.

## 2. Demonstration sequence (5–7 minutes)

| Time | Where | What to do | Expected | What to say |
|---|---|---|---|---|
| 0:00–0:45 | Landing → **Sign in** | Sign in. Point out the sidebar groups Intake, Operations, Intelligence and Knowledge. | Command Center loads with live counts. | "NETRA answers: what should be investigated first, why, and what is a sensible next step, using only the evidence it has." |
| 0:45–2:00 | Sidebar → **Intake → Dataset Import** | Profile **CIC-IDS2017 labelled flows (v1)**, choose the extract, click **Validate file**. | Status **Validated**; 14 of 14 rows accepted; **Events stored 14**, **Duplicates 0**. | "The file must match the exact 85-column header. Rows that fail would be listed by row, column and rule, never by cell content." |
| 2:00–2:45 | Same page → click the new batch in **Import history** | Show the batch detail: SHA-256, profile and version, row counts, issues. | The counts above; a note that rejected rows are never stored. | "Each upload is an import batch with a file hash. The same file can't be validated twice." |
| 2:45–3:30 | Batch detail → **View the 14 events this batch stored** | Opens **Security Events** filtered to this batch. Open one event. | Source shows **Dataset import**, severity **INFO**. **Source record** shows "File row N" and a link to the import batch. **Affected asset** shows the demo server. | "Every imported event points back to its file row. The dataset's label is kept as ground truth, not as a NETRA detection, so these are INFO." |
| 3:30–4:45 | Sidebar → **Intelligence → Security Assessment** | Asset **[DATASET DEMO] CIC-IDS2017 server 192.168.10.50**; **Event window ends (UTC)** = **2017-07-08**; click **Run assessment**. | A toast with the grade and score; the result opens. | "CIC-IDS2017 is from July 2017, so the 7-day event window must end then. Only events are time-bounded." |
| 4:45–5:45 | Assessment detail → **Events matching active threat indicators** | Expand the finding and click an event ID. | **10 events** cited: 8 DDoS-labelled and 2 BENIGN-labelled flows that involve 172.16.0.1; the 4 internal flows are not cited. The event opens with its source record. | "The finding cites events because their address matches an indicator, regardless of label. Every cited ID traces back to a batch and a row." |
| 5:45–6:30 | **Security Assessment** → reload the browser → open the run from history | — | The same grade, findings and evidence IDs. | "Assessments are immutable snapshots; nothing is recalculated." |
| 6:30–7:00 | **Operations → Incidents** → `INC-DEMO-0001` | Show the timeline: verify → decision → authorisation → contained → learned, and Cyber Memory. | The seeded incident shows the full lifecycle. | "Approval requires a different person with the approver role; containment is a simulation, recorded as such." |

> The incident step uses the fictional seeded incident (`python -m app.db.seed_demo --apply`).
> Approving a live request needs a second account with the `approver` role, which is assigned
> through `scripts\netra_users.py`.

## 3. Screenshots worth capturing

1. Dataset Import: the upload panel with the CIC-IDS2017 profile selected.
2. Import batch detail: counts (data rows, accepted, rejected, issues, events stored, duplicates)
   and the SHA-256.
3. A rejected-file example: header issue at a named column position (for example, a file with
   `Fwd Header Length.1`).
4. Security Events filtered to one batch ("Import batch …" filter shown).
5. Event detail: the **Source record** section (file row and batch link) and **Affected asset**.
6. Security Assessment run panel with **Event window ends (UTC)** set.
7. Assessment detail: grade, score, input counts and the threat-indicator finding with cited event
   IDs.
8. Assessment history after a browser reload.
9. Incident detail: risk factors with rationales.
10. Incident timeline: authorisation (approver ≠ requester) and simulated containment.
11. Cyber Memory entry.
12. Terminal, from `backend\`: `.\.venv\Scripts\python.exe -I -B scripts\netra_e2e_pytest.py run -q`.
    Capture the lines "locality proven: netra_e2e on loopback…" and `761 passed, 1 skipped`. Also
    capture the launcher `selftest` (`92 passed, 0 failed`) and frontend `npm test` (`78 pass`).

## 4. Implemented, simulated or planned

| Area | Status | Honest description |
|---|---|---|
| Authenticated CIC-IDS2017 upload, validation, issue report | **Implemented, tested** | Exact header, per-row rules, capped issue sample, file-hash duplicate refusal |
| Normalisation to events with batch/row provenance | **Implemented, tested** | Accepted rows only; one transaction; content-hash duplicates counted |
| Asset linking | **Implemented (rule-based)** | Exact single IP match at import time; recorded on the event |
| Detection over imported flows | **Not implemented** | Imported rows are INFO; labels are ground truth only |
| Correlation, enrichment, incident risk | **Implemented, tested** | Deterministic documented rules and weights |
| Security Assessment with cited evidence and snapshots | **Implemented, tested** | `assessment-v2`, 9 checks, `asOf` for historical evidence |
| Authorisation with separation of duties | **Implemented, tested** | Approver/admin role and a different person than the requester |
| Containment | **Simulated** | Records `simulated: true`; changes no host, firewall or account |
| Cyber Memory | **Implemented** | Stores outcomes and lessons; does not change future scores |
| Demo asset and indicator | **Seeded context** | Clearly labelled; analyst-entered, not a threat feed; guarded seed module |
| Background processing, live feeds, SIEM/EDR, UNSW-NB15, detection metrics | **Planned** | Not built |
| CIC-IDS2017 time zone (UTC−03:00) and AM/PM reading | **Assumption** | Recorded on every event; unverified |

## 5. Likely viva questions and answers

1. **What problem does NETRA solve?** It brings events, assets, vulnerabilities and indicators
   together so an analyst can see what to investigate first and why, with every finding citing its
   evidence and stating what is missing.

2. **Why CIC-IDS2017?** It's a public, documented intrusion-detection dataset with labelled flows and
   a stable 85-column schema. One dataset with an exact profile was the PDF's chosen starting point.

3. **How is an upload validated?** The header must match 85 names position by position. Each row is
   then checked for IPs, ports (0–65535), protocol (0–255), timestamp shape and range, a known label,
   numeric features (including `Infinity`/`NaN` as written) and Flow ID consistency. Issues record
   row, column and rule only.

4. **Why are some rows rejected but the batch is still "validated"?** File-level problems (header,
   encoding, binary content) reject the file. Row problems reject only those rows; the batch reports
   accepted, rejected and total counts, which always reconcile.

5. **How do you handle duplicates?** At two levels. A file is identified by its SHA-256 and can be
   validated once per profile version; a partial unique index makes concurrent uploads safe. Each
   row's content hash is the event UID, so a row identical to a stored event is counted in
   `duplicateRows` instead of being stored again.

6. **What is "provenance" here?** Every imported event stores `import_batch_id` and `source_row`, and
   a database constraint requires both or neither. All 85 original fields, the file hash and the
   asset-link outcome are kept in `raw_data`. The UI links an event to its batch and a batch to its
   events.

7. **Do you treat the dataset label as an attack detection?** No. Labels are ground truth for
   evaluation. Imported events are stored as INFO, and findings cite them only through implemented
   rules such as an indicator match.

8. **How do imported events reach an assessment?** An event is linked to an asset when exactly one
   asset's IP matches its source or destination at import time. The assessment reads linked events in
   a 7-day window ending at `asOf` and cites them in findings, for example when they match an active
   IP threat indicator.

9. **Why do you need `asOf`?** The dataset is from July 2017. A window ending now would contain none
   of its events. `asOf` bounds only events; other evidence is its current state, which is stated in
   the UI and the docs.

10. **How is the assessment score calculated?** It starts at 100 and deducts per finding by severity
    (critical 25, high 15, medium 8, low 3). Grades are A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, otherwise F.
    Methodology v2 makes sure one event is never deducted twice.

11. **Is the assessment reproducible?** Yes. The engine is pure and deterministic: no database
    queries, clock reads or network calls inside it. Each run is stored as an immutable snapshot with
    its methodology version and `asOf`, and old snapshots are never recalculated.

12. **How is incident risk explained?** Six weighted factors: asset criticality 0.25, vulnerability
    0.20, anomaly 0.20, detection confidence 0.15, threat intelligence 0.10, attack context 0.10. Each
    factor returns its value and a written rationale.

13. **How is a response decided?** Deterministic thresholds:
    - `ISOLATE_HOST` for high risk (≥ 75) on a high or critical asset with at least two events;
    - `BLOCK_IP` for a strong indicator match on a source IP;
    - `INVESTIGATE` for risk ≥ 50 or repeated events;
    - otherwise `MONITOR`.

    Each recommendation carries its rationale.

14. **What stops one person from approving their own action?** Approval needs the
    `resolve_authorization` permission (approver/admin), and the service rejects an approval from the
    requester. Roles are re-read from the database on every request.

15. **Does NETRA actually block IPs or isolate hosts?** No. Containment is a controlled simulation,
    recorded with `simulated: true`. Real changes would need secure integrations, approval controls,
    audit and rollback, which are out of scope.

16. **How are credentials and secrets protected?**
    - Argon2 password hashes and short-lived JWTs.
    - Reset tokens are stored as SHA-256 hashes.
    - Secrets live in gitignored `.env` files and are typed as `SecretStr`.
    - Scripts print only `host:port/database`, never credentials.

17. **How did you test it, and how do you avoid damaging real data?** 761 backend tests run in
    throwaway PostgreSQL schemas on an isolated `netra_e2e` database, never the development database,
    plus 78 frontend tests, type checks and a build.
    - The backend suite runs only through `scripts/netra_e2e_pytest.py` (`selftest`, `check`, `run`).
    - It refuses any target other than a local `netra_e2e` on port 5432, and starts pytest with
      settings from `.env.e2e` only, in a folder with no `.env`.
    - It proves the server is the local PostgreSQL process, so a port forward can't redirect the
      tests.
    - Its own self-test checks 92 refusal cases.

    Migrations were applied locally only after a verified `pg_dump` backup and row-count comparison.

18. **What happens if storing events fails halfway?** The batch and its events are in one
    transaction, so nothing is kept. A regression test simulates a failure after the first chunk and
    checks that no batch and no events remain.

19. **What are the main limitations?**
    - No independent detection on imported flows.
    - Linking happens only at import time.
    - No asset or indicator creation API.
    - The CIC timestamp interpretation is an assumption.
    - Processing happens in the request, with no background jobs.
    - No precision/recall or throughput measurements yet.
    - Production parity is unverified.

20. **What would you do next?**
    - Documented detection rules, evaluated against held-out labels with precision, recall, F1 and a
      confusion matrix.
    - Background processing with progress for full files.
    - A UNSW-NB15 profile.
    - Asset and indicator management APIs.
    - Continuous integration running the guarded backend suite and frontend checks.
    - Verified deployment.

## 6. If something goes wrong during the demo

| Symptom | Likely cause | Action |
|---|---|---|
| "Cannot reach the NETRA API" | Backend not running, or the page origin isn't in `CORS_ORIGINS` | Start the backend; open the UI at `http://127.0.0.1:5173` or `http://localhost:5173` (both are allowed by default) |
| Upload returns 409 | The same file was already validated | Open the existing batch from Import history |
| `header.unexpected_column` at column 62 | The file was re-saved with `Fwd Header Length.1` | Use the original extract; column 62 must be `Fwd Header Length` |
| Assessment shows 0 events | Event window not set to 2017, or the asset didn't exist before the upload | Set **Event window ends** to 2017-07-08; confirm the events show the demo asset |
| Imported events show "No managed asset matched this event" | They were uploaded before the demo asset was created | Linking happens only at import time; upload a new extract |
