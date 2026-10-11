# Dataset imports: validation-only upload and CIC-IDS2017 profile

`POST /api/imports` accepts one CSV file, validates it against a named dataset profile and records
the outcome as an **import batch**. Imports are validation only:

- No CSV rows are stored anywhere.
- Nothing is written to `security_events`, `incidents`, `assets`, `security_assessments` or
  `assessment_findings`. Dashboard, correlation, collector and assessment behaviour are unchanged.
- Two profiles are registered: `generic-csv` (structure only) and `cic-ids2017` v1 (see
  [CIC-IDS2017 profile](#cic-ids2017-profile-cic-ids2017-v1)). Storing dataset rows or turning them
  into security events is not implemented and needs its own, separately approved design.
- Full-size CIC-IDS2017 files exceed the upload limits. They are checked with the
  [local profiler](#local-profiler) instead, which reads files from disk and stores nothing.

## Endpoints

All three require a bearer token (`get_current_user`). There is no role model: any active user can
upload, and each user sees only the batches they uploaded.

| Method | Path | Result |
|---|---|---|
| `POST` | `/api/imports` | `multipart/form-data` with exactly one file part `file` (`.csv`) and one field `profile`. `201` with the batch and its validation report. |
| `GET` | `/api/imports?page=&pageSize=` | The caller's batches, newest first (`pageSize` 1–100, default 25). No error sample. |
| `GET` | `/api/imports/{id}` | One of the caller's batches with its capped error sample; `404` otherwise. |

### Outcomes of `POST /api/imports`

| Response | When | Batch recorded? |
|---|---|---|
| `201`, `status: VALIDATED` | The file was read to the end. Individual rows may still be rejected; see the counts. | Yes |
| `201`, `status: REJECTED` | File-level problem: no header, a header that fails the profile, binary content, invalid encoding, malformed CSV, an over-long line, or no data rows. | Yes |
| `409` | The same bytes were already **validated** with the same profile and profile version. | No |
| `413` | Over the byte limit or the row limit. | No |
| `415` | Not `multipart/form-data`, or the file part is not a `.csv` file. | No |
| `422` | Wrong form shape (extra fields, more than one file, missing file) or a missing or unknown profile. | No |
| `429` | More than 10 uploads per user per minute (in-process limiter). | No |
| `401` | Missing or invalid token. The body is not read. | No |

## Validation reports never echo cell contents

Each issue has `rule`, `message`, `row`, `column` and `columnIndex`:

- `row` counts the header as row 1, so the first data row is row 2. Blank lines are skipped but keep
  their row numbers.
- `column` is only ever a name defined by the profile. Columns found in the file (duplicate or
  empty headers) are identified by `columnIndex` (1-based) only.
- Messages are fixed text per rule. `csv` parser messages and decoder messages are not passed through.

The first 100 issues are stored in `error_sample`; `error_total` counts all of them, and
`errorSampleTruncated` is true when the sample was capped.

## Duplicate policy

A file is identified by the SHA-256 of its bytes. It can be recorded as `VALIDATED` at most once per
`(dataset_profile, profile_version, file_sha256)`.

- The API checks for an existing validated batch first and answers `409`.
- Two concurrent uploads of the same file can both pass that check. The partial unique index
  `uq_import_batches_validated_file` (`WHERE status = 'validated'`) lets only one insert commit; the
  other gets `409`. This is the concurrency-safe guard.
- `REJECTED` batches do not reserve the hash: a corrected file or a plain retry is never blocked by an
  earlier failure. Each rejected attempt is kept as its own batch for audit.
- Re-uploading a validated file is refused on purpose: identical bytes under identical rules give
  an identical report. When a profile's rules change, its `version` is bumped, which allows the same
  file to be validated again.
- The `409` message includes the existing batch ID only if the caller uploaded it.

## Limits

| Setting | Default | Enforced by |
|---|---|---|
| `IMPORT_MAX_UPLOAD_BYTES` | 26214400 (25 MiB) | The API: declared `Content-Length` check, a cap on the streamed request body (limit + 64 KiB for multipart framing), and an exact check on the file's bytes. |
| `IMPORT_MAX_ROWS` | 100000 | The API: counted while streaming; parsing stops at the first row over the limit. |
| Line length | 1 MiB characters | The API (`MAX_LINE_CHARACTERS`). Bounds per-row memory. |
| Field size | 131072 characters | Python's `csv` default. |
| Columns | 512 | The profile header check (`MAX_COLUMNS`). |

The upload is parsed with Starlette's multipart parser fed from the capped stream. The file spools
to a temporary file (memory use up to 1 MiB, then disk, bounded by the byte cap). Hashing and
validation read it in fixed-size chunks and lines. The temporary file is closed, which deletes it,
after the response on success and immediately on any parse error.

### Limits code cannot enforce

- **Reverse proxy or platform limits.** Whatever sits in front of the API (a hosting platform's
  edge, Nginx `client_max_body_size` (default 1 MiB), a load balancer) has its own request-size limit
  and request timeout. It must allow at least `IMPORT_MAX_UPLOAD_BYTES` + 64 KiB, or uploads fail
  there with that layer's own error. The frontend's `vercel.json` only rewrites SPA routes; API calls
  go directly to `VITE_API_BASE_URL`, so the backend host's limits apply.
- **Uvicorn** has no request-body size limit of its own. The API's cap is the only one in the app.
- **Temporary disk space.** Concurrent uploads each use up to the byte cap in the system temp
  directory.
- **Rate limiting** is per API process and resets on restart.

## Schema: migration `0004_add_import_batches`

Creates only `import_batches` (down revision `0003_add_security_assessments`). It alters no
existing table or constraint. Like 0002 and 0003, it skips the table if `app.db.init_db` already
created it.

| Column | Notes |
|---|---|
| `id` | UUID primary key |
| `dataset_profile`, `profile_version` | Profile identifier and rules version used |
| `original_filename` | Base name only, control characters removed, at most 255 characters |
| `file_sha256` | Lower-case hex; `CHECK` format |
| `file_size_bytes` | `BIGINT`, `>= 0` |
| `uploaded_by_id` | FK `users.id`, `ON DELETE SET NULL` |
| `status` | `validated` or `rejected` (`CHECK`) |
| `total_rows`, `accepted_rows`, `rejected_rows` | `CHECK accepted + rejected = total` |
| `error_total`, `error_sample` | Count of all issues; JSONB list of at most 100 |
| `created_at`, `completed_at` | Transaction time; time validation finished |

Indexes: `ix_import_batches_status`, `ix_import_batches_uploaded_by_id_created_at`, and the partial
unique `uq_import_batches_validated_file`.

**Not applied to `netra` or Neon.** The migration has run only in throwaway test schemas; the
isolated `netra_e2e` setup (`backend/scripts/netra_e2e.py`) creates tables with `app.db.init_db`
and stamps the version. Neon has not yet received 0003 either (see
`SECURITY_ASSESSMENT_MIGRATION.md`). Apply 0003 by its documented path first, then
`alembic upgrade head` applies 0004. `alembic downgrade 0003_add_security_assessments` drops
`import_batches` and every recorded batch. The CIC-IDS2017 profile added no schema change.

## CIC-IDS2017 profile (`cic-ids2017` v1)

For the `GeneratedLabelledFlows/TrafficLabelling` CSVs. Defined in
`backend/app/services/dataset_profiles.py` (`CicIds2017Profile`). Validation only: no value is
converted, and no row is stored.

**Header.** Positional: the header must equal the 85 expected names exactly, in order, after
trimming surrounding whitespace (70 of the 85 names start with a space in the files). A wrong
column count gives `header.column_count`; a wrong name at a position gives `header.unexpected_column`
with that position. `Fwd Header Length` is expected at both column 41 and column 62; the two are
kept under distinct keys, `fwd_header_length` and `fwd_header_length_2`, so neither is merged or
dropped. A repeat anywhere else is rejected. `generic-csv` is unchanged and still rejects this
header because of the repeated name.

**Encoding.** Windows-1252 (`cp1252`), strict. Bytes undefined in Windows-1252 reject the file
(`file.encoding`); no other encoding is tried.

**Row rules.** Issues name the row, the profile's column name and position, and the rule; never
the cell value.

| Rule | When |
|---|---|
| `row.empty_record` | All 85 fields are empty or whitespace. Counted as one rejected row. |
| `row.missing_value` | One field is empty in an otherwise non-empty record. |
| `row.invalid_ip` | `Source IP` or `Destination IP` is not an IPv4 or IPv6 address. |
| `row.invalid_port` | A port is not an integer from 0 to 65535. |
| `row.invalid_protocol` | `Protocol` is not an integer from 0 to 255. |
| `row.invalid_timestamp` | `Timestamp` is not `D/M/YYYY H:MM` or `DD/MM/YYYY HH:MM:SS`, is not a valid day/month/year date, or has a minute or second over 59. |
| `row.timestamp_out_of_range` | The date, read as day/month/year, is outside 3–7 July 2017. |
| `row.timestamp_hour_unverified` | The hour is not 1–5 or 8–12 (see [timestamps](#timestamps)). |
| `row.unknown_label` | `Label` is not exactly one of the 15 labels listed below. |
| `row.invalid_number` | A feature column (columns 8–84) is not a decimal number, `Infinity`, `-Infinity` or `NaN`. |
| `row.duplicate_column_mismatch` | The two `Fwd Header Length` columns differ. |
| `row.invalid_flow_id` | `Flow ID` does not have five `-`-separated parts. |
| `row.flow_id_mismatch` | `Flow ID` does not equal the row's addresses, ports and protocol in either order. |

`Infinity`, `-Infinity` and `NaN` are accepted as recorded dataset values; they are never converted
to zero. Negative numbers are accepted. Flow ID is checked for consistency only: it is not unique,
and its endpoint order does not establish connection direction, so the profile infers none.

### Full-dataset findings (all 8 files)

Measured by the [local profiler](#local-profiler) over every record of every file, not a sample.

| File | Bytes | Records | Accepted | Rejected | Line endings |
|---|---:|---:|---:|---:|---|
| `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | 96,101,069 | 225,745 | 225,745 | 0 | LF |
| `Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv` | 101,874,777 | 286,467 | 286,467 | 0 | CRLF |
| `Friday-WorkingHours-Morning.pcap_ISCX.csv` | 75,386,737 | 191,033 | 191,033 | 0 | CRLF |
| `Monday-WorkingHours.pcap_ISCX.csv` | 268,649,908 | 529,918 | 529,918 | 0 | LF |
| `Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv` | 108,723,183 | 288,602 | 288,602 | 0 | CRLF |
| `Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv` | 92,030,223 | 458,968 | 170,366 | 288,602 | CRLF |
| `Tuesday-WorkingHours.pcap_ISCX.csv` | 174,696,560 | 445,909 | 445,909 | 0 | CRLF |
| `Wednesday-workingHours.pcap_ISCX.csv` | 285,642,925 | 692,703 | 692,703 | 0 | CRLF |
| **All 8 files** | **1,203,105,382** | **3,119,345** | **2,830,743** | **288,602** | |

**Confirmed across all records:**

- **Headers:** all 8 files match the profile's 85-column header.
- **Rejections:** all 288,602 rejected records are `row.empty_record`, all in the Thursday
  WebAttacks file. No other rule rejected any record in any file.
- **Encoding:** the only non-ASCII byte is `0x96` (en dash in Windows-1252), 2,180 times, all in the
  WebAttacks file. No byte undefined in Windows-1252 occurs. No NUL bytes.
- **Repeated column:** the two `Fwd Header Length` columns are equal in all 2,830,743 non-empty
  records.
- **Timestamp formats:** `D/M/YYYY H:MM` 1,521,014 · `D/M/YYYY HH:MM` 779,811 ·
  `DD/MM/YYYY HH:MM:SS` 529,918 (the Monday file).
- **Dates (read as day/month/year):** only 3–7 July 2017. 2017-07-03: 529,918 · 2017-07-04: 445,909 ·
  2017-07-05: 692,703 · 2017-07-06: 458,968 · 2017-07-07: 703,245.
- **Hours as written:** only 01–05 and 08–12. 01: 236,444 · 02: 434,370 · 03: 397,052 ·
  04: 394,278 · 05: 9,572 · 08: 16,607 · 09: 330,717 · 10: 562,859 · 11: 315,230 · 12: 133,614.
  No 00, 06, 07 or 13–23.
- **Labels (15):** BENIGN 2,273,097 · DoS Hulk 231,073 · PortScan 158,930 · DDoS 128,027 ·
  DoS GoldenEye 10,293 · FTP-Patator 7,938 · SSH-Patator 5,897 · DoS slowloris 5,796 ·
  DoS Slowhttptest 5,499 · Bot 1,966 · Web Attack – Brute Force 1,507 · Web Attack – XSS 652 ·
  Infiltration 36 · Web Attack – Sql Injection 21 · Heartbleed 11.
- **Non-finite values:** `Flow Packets/s = Infinity` 2,867 · `Flow Bytes/s = Infinity` 1,509 ·
  `Flow Bytes/s = NaN` 1,358. No `-Infinity`.
- **Negative values (records with a value below zero):** Init_Win_bytes_backward 1,441,552 ·
  Init_Win_bytes_forward 1,001,189 · Flow IAT Min 2,891 · Flow Duration 115 · Flow Packets/s 115 ·
  Flow IAT Mean 115 · Flow IAT Max 115 · Flow Bytes/s 85 · Fwd Header Length 70 ·
  min_seg_size_forward 35 · Bwd Header Length 22 · Fwd IAT Min 17.
- **Protocols:** 6: 1,829,554 · 17: 999,493 · 0: 1,696.
- **Flow ID order:** destination columns first 1,556,677 · source columns first 1,274,066 ·
  matching neither order 0.
- **Upload limits:** every file exceeds both default upload limits, 25 MiB (26,214,400 bytes) and
  100,000 rows, so none can be uploaded whole through `POST /api/imports`.

**Observed, not explained.** The WebAttacks file's 288,602 empty records form one contiguous block
starting at row 170,368 and running to the end of the file. That count equals the Infiltration
file's record count exactly. This could be an artefact of how the files were exported, but the
cause is not established.

#### Timestamps

The hour set (1–5 and 8–12, never 0, 6, 7 or 13+) is consistent with a 12-hour clock written
without AM/PM: morning files contain 8–12, afternoon files 1–5. That reading is an inference from
the data, not something the files state. The profile does not convert timestamps; it rejects any
hour outside that set so a contradicting value would surface rather than be guessed at.

**The time zone is unconfirmed.** The files carry no offset or zone. Public descriptions place the
capture in New Brunswick, Canada, but that has not been verified against these files, so no UTC
conversion should be designed until it is.

## Local profiler

Streams CSV files through a profile and prints aggregate facts. Run from `backend/` with the
virtual environment:

```powershell
.\.venv\Scripts\python.exe -m app.services.dataset_profiler --profile cic-ids2017 ..\GeneratedLabelledFlows\TrafficLabelling
```

| Argument | Meaning |
|---|---|
| `paths` (one or more) | `.csv` files, or folders whose `.csv` files are profiled in name order. Anything else stops with an error. |
| `--profile` | Required. A registered profile identifier: `cic-ids2017` or `generic-csv`. |
| `--json` | Print machine-readable JSON instead of the text report. |

In text mode, progress (`<file>: N records`) is written to stderr every 250,000 records.

**What it does:** for each file, a byte pass (SHA-256, size, CRLF/LF-only line counts, NUL bytes,
non-ASCII byte values), then a record pass through the same `open_csv` / `check_record` code that
uploads use. It reports per-file and combined counts: records, accepted and rejected rows, issues
by rule and column with the first row each occurred at, and profile facts. For `cic-ids2017` those
facts are labels, timestamp shapes, hours and dates, protocols, Flow ID order, `Fwd Header Length`
agreement, non-finite values and negative values. It also says how many files exceed the default
upload limits.

**Safe by construction:**

- **Read-only and offline.** It opens the given files for reading only. It makes no network calls,
  does not connect to a database, needs no `.env` settings, uploads nothing, stores no rows and
  writes no files. Output goes to stdout.
- **Bounded memory.** Files are streamed in 1 MiB chunks and line by line, with lines capped at
  1 MiB characters as for uploads. Each tally keeps at most 300 distinct keys; further new keys are
  counted as "other values". During the full 8-file run (1.2 GB), which took 11 min 25 s on the
  development machine, the process's memory was observed at about 69 MB (two spot checks, not a
  measured peak).
- **No rows, only categories.** Output holds counts, rule names, row numbers and categorical values.
  Three come from cell text: the `Label` value, the `Protocol` value, and the `Timestamp` with every
  digit replaced by `9`. Each is printed escaped and truncated to 80 characters, so an unexpected
  value in one of those columns would appear as a category. Hours and dates are printed only after
  parsing. Feature values and all other cells are never printed.
- The upload row cap does not apply: the profiler reads every record.

## Adding a dataset profile

Profiles live in `backend/app/services/dataset_profiles.py` and are registered in `PROFILES`.

- **By name** (`DatasetProfile`): set `identifier`, `version`, `title`, `encoding` and
  `required_columns`, and override `check_row` if needed. Columns are found by name; repeated names
  are rejected. `check_row` receives the required columns keyed by their profile names.
- **By position** (`PositionalProfile`): set `columns` to the exact expected header. Each position
  gets its own key (a repeated name gets a `_2` suffix), and `check_row` receives every column.
- Optionally override `describe_record` to give the local profiler facts to tally.

Issues must never contain cell contents. Bump `version` whenever rules change. Base rules on the
inspected files and verify them with the local profiler, not on assumptions.
