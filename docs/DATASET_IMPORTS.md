# Dataset imports: validated upload, Security CSV mapping, CIC-IDS2017 profile and event normalisation

`POST /api/imports` accepts one CSV file, validates it against a named dataset profile and records
the outcome as an **import batch**.

- Three profiles are available: `security-csv` v1, which imports any security CSV through a
  user-confirmed field mapping (see [Security CSV profile](#security-csv-profile-security-csv-v1));
  `generic-csv`, which checks structure only and is **validation only** (no row is stored); and
  `cic-ids2017` v1 (see [CIC-IDS2017 profile](#cic-ids2017-profile-cic-ids2017-v1)).
- For `security-csv` and `cic-ids2017`, the rows of a `VALIDATED` batch that passed every check are
  stored as **security events** in the same transaction as the batch (see
  [Normalisation to security events](#normalisation-to-security-events-cic-ids2017)). Rejected rows
  are reported in the batch and never stored. A `REJECTED` file stores nothing.
- Nothing is written to `incidents`, `assets`, `security_assessments` or `assessment_findings`.
  Imported events reach Security Assessment only through its existing evidence rules (see
  [From imported events to assessment findings](#from-imported-events-to-assessment-findings)).
- Full-size CIC-IDS2017 files exceed the upload limits. They are checked with the
  [local profiler](#local-profiler) instead, which reads files from disk and stores nothing.

## Endpoints

All four require a bearer token for an active account. Uploading and previewing (`POST`) also require
the `operate_workflow` permission, which the `operator`, `approver` and `admin` roles all hold; any
other role gets `403`. The two `GET` endpoints need only a valid token. Each user sees only the
batches they uploaded. Roles are defined in `backend/app/core/permissions.py` (see `DEMO_DATA.md` for
creating accounts).

| Method | Path | Result |
|---|---|---|
| `POST` | `/api/imports/preview` | `multipart/form-data` with one file part `file` (`.csv`) and optional `encoding` / `delimiter` overrides. `200` with the detected format, sample rows and suggested field mappings. **Records nothing.** 30 previews per user per minute. |
| `POST` | `/api/imports` | `multipart/form-data` with exactly one file part `file` (`.csv`), one field `profile` and, for `security-csv` only, one field `mapping` (JSON, at most 16 KiB). `201` with the batch, its validation report and, when events were stored, `normalization` and `eventCoverage`. |
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
| `422` | Wrong form shape (extra or repeated fields, more than one file, missing file), a missing or unknown profile, a missing or invalid `mapping` for `security-csv`, or a `mapping` sent with another profile. Mapping errors name the field and rule, never the submitted value. | No |
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

**Production state:** Neon production was migrated on 2026-10-26 from `0005_dataset_event_provenance`
to `0007_event_attack_techniques` (PostgreSQL 18.6), so 0003, 0004 and 0005 are applied
(record: [PRODUCTION_BACKUP.md](PRODUCTION_BACKUP.md#production-migration-record-2026-10-26)). The
2026-10-12 record (test branch at 0004, production at `0002`) is historical and superseded. The isolated
`netra_e2e` setup (`backend/scripts/netra_e2e.py`) creates tables with `app.db.init_db` and stamps the
version. A Neon snapshot and backup branch exist from before that migration, but no verified logical
backup (`pg_dump` archive with a tested restore) is recorded; before any further production migration,
follow [PRODUCTION_BACKUP.md](PRODUCTION_BACKUP.md). For a database still below 0004, take and record a backup or Neon branch, apply 0003 by its documented path
(`SECURITY_ASSESSMENT_MIGRATION.md`), then `alembic upgrade head` applies 0004. `alembic downgrade 0003_add_security_assessments` drops
`import_batches` and every recorded batch. The CIC-IDS2017 profile added no schema change.

## Security CSV profile (`security-csv` v1)

Implemented in `backend/app/services/security_csv.py` (mapping, rules and normalisation) and
`backend/app/services/csv_preview.py` (detection). It needs **no schema change**: it reuses
`import_batches`, the provenance columns from migration 0005 and the same storage path as
`cic-ids2017`.

**Flow.** The UI (Dataset Import → *Security CSV (map your columns)*) first calls
`POST /api/imports/preview`. The preview suggests a mapping, which the user confirms or corrects, and
the UI then sends that mapping with `POST /api/imports`. **The server never imports with a guessed
mapping:** `security-csv` without a `mapping` field is refused with `422`.

### Supported formats

| Aspect | Supported |
|---|---|
| Delimiters | comma, semicolon, tab, pipe (detected; overridable) |
| Quoting | standard CSV double quotes, including delimiters and newlines inside quoted cells |
| Encodings | `utf-8` (BOM optional), `utf-16` (BOM required to detect), `cp1252`, `iso-8859-1`. The preview reports a non-UTF-8 guess as not confident. |
| Timestamps | `iso8601` (`2024-05-01T13:45:00Z`, `2024-05-01 13:45`, `2024/05/01 13:45:07.250+02:00`, date only), `dmy` / `mdy` (`01/05/2024 13:45[:SS]`, 12-hour with AM/PM allowed, `/` `.` `-` separators), `rfc2822`, `epoch_seconds`, `epoch_millis` |
| Time zones | A zone in the value (`Z`, `UTC`, `±HH:MM`) is used. A value without one is read in the mapping's `utcOffset` (default `+00:00`), and that reading is recorded on every event. |
| Columns, order | Any names and any order. Mapped names are matched ignoring case and surrounding spaces. |

### Canonical fields and record types

| Field | Kind | Notes |
|---|---|---|
| `occurred_at` | timestamp | Required for every record type. |
| `event_type` | text ≤ 100 | Required for `security_event`: map a column, or give `defaultEventType` for every row. For `network_flow` it is optional and defaults to `network_flow`. |
| `src_ip`, `dest_ip` | IPv4/IPv6 | Both required for `network_flow`. Zone indices (`fe80::1%eth0`) are rejected. |
| `src_port`, `dest_port` | 0–65535 | `443.0` (pandas export style) is read as 443. |
| `protocol` | number 0–255 or short name | 1/6/17/58/132 become `icmp`/`tcp`/`udp`/`ipv6-icmp`/`sctp`; names are lower-cased. |
| `severity` | text ≤ 64 | **Reference only.** Kept as `raw_data.reportedSeverity` (as written plus a normalised word). The event's severity stays `INFO`. |
| `message` | text ≤ 4,096 | Kept as `raw_data.message`. Never stored as `signature`, so free text never feeds correlation keyword matching. |
| `outcome` | text ≤ 256 | Kept as `raw_data.outcome`. |
| `label` | text ≤ 256 | Ground truth of a labelled dataset: `raw_data.groundTruthLabel`, **never a detection**. |

`security_event` covers any timestamped security record (authentication, alert, audit, endpoint or
application rows). `network_flow` covers connection and flow records. Every field that is not
required is optional. The preview lists the fields and requirements, and the UI marks them.

### Suggestions and confidence

A column is suggested for a field from its header name (a synonym list per field, e.g. `src`,
`id.orig_h`, `Source Address` for `src_ip`) **and** from its sampled values (the first 200 rows within
1 MiB).

- `high`: the name and at least 90 % of the sampled values agree. This is the only level the UI
  preselects.
- `low`: the name matches but the values do not, or (for timestamps and IPs only) the values match
  but the name does not. It is shown as a "possible match" for the user to accept.
- `ambiguous`: several columns match equally well; the candidates are listed and none is chosen.
- Epoch numbers count as timestamps only in a column whose name says it is a time, because any small
  integer is a valid Unix time.
- Dates that every sample allows as either day/month or month/day leave the format unchosen.
- `needsReview` is true when a required field, the timestamp format, the encoding or the delimiter is
  not confidently detected.
- A header identical to CIC-IDS2017 is recognised, and the UI offers the `cic-ids2017` profile instead.

### Validation rules (per row unless stated)

| Rule | Meaning |
|---|---|
| `header.missing_column` / `header.ambiguous_column` | File-level: a mapped column is absent, or its name appears twice. The file is `REJECTED`. |
| `row.column_count` | The row has a different number of fields than the header. |
| `row.missing_value` | A required field is empty. |
| `row.invalid_timestamp`, `row.timestamp_out_of_range` | Does not parse under the chosen format, or falls outside 1970-01-01 to one day from now. |
| `row.invalid_ip`, `row.invalid_port`, `row.invalid_protocol` | A **present** value is malformed. Optional fields are validated too, so a bad optional IP rejects the row instead of being silently dropped. Unmap the column to import without it. |
| `row.value_too_long`, `row.invalid_text` | Over the field's length, or contains control characters (`message` may contain tabs and line breaks). |
| `row.binary_content` | A decoded NUL character (UTF-16 files; other encodings reject NUL bytes at file level as `file.not_text`). |

A record whose cells are **all empty** (`,,,,` from spreadsheet exports) is skipped like a blank
line and not counted as data. Issues name the canonical field (`column`) and its 1-based position
(`columnIndex`), never cell contents.

**Statistics.** `acceptedRows`, `rejectedRows` (with the capped issue sample) and `duplicateRows`.
`duplicateRows` counts rows that were accepted but skipped because an identical event already
exists. `eventsCreated + duplicateRows = acceptedRows`.

### What is stored

Each accepted row becomes one `security_events` row with `source = dataset_import`,
`severity = INFO`, `signature = NULL`, the batch and file row (`import_batch_id`, `source_row`),
and `raw_data` containing:
`dataset` (profile, version, record type, the full `fieldMapping`, timestamp format, UTC offset,
encoding, delimiter, default event type), `timestampAsWritten`, `occurredAtInterpretation`,
`eventTypeSource`, `sourceFields` (**every column as written, keyed by its original header name**;
blank names become `column N` and repeats get ` (2)`), `unmappedColumns`, the optional `message`,
`outcome`, `groundTruthLabel` and `reportedSeverity`, `protocolAsWritten`, `formulaNeutralized`, and
the same `importBatchId`, `sourceRow`, `fileSha256` and `assetLink` as CIC-IDS2017 events.

**Duplicates.** The event uid is `dataset:security-csv:<sha256>`, where the hash covers the row's
(column name, value) pairs **sorted by name**. The same data with its columns in another order, or
with another delimiter, is therefore recognised as a duplicate and counted, not stored again. The
file-level rule is unchanged: identical bytes validated once per profile version (`409`).

**Formula injection.** Cells starting with `=`, `+`, `-`, `@`, tab or carriage return are formulas
to a spreadsheet unless they are plain numbers. The preview returns such cells with a leading
apostrophe, and a formula-like `event_type` (a displayed column) is stored with one too. The
original stays unchanged in `sourceFields`. Nothing uploaded is executed: markup such as `<script>` is
stored as text and rendered as text.

### Integration and readiness

- **Live Event Collector.** `GET /api/collector/status` adds `importedEventsTotal` and
  `recentImportedEvents` (newest import first). The Collector page shows them under its *Imports*
  toggle. They are never counted as collector submissions.
- **Events.** `GET /api/events?importBatchId=<id>` and `?source=DATASET_IMPORT` list them, as for
  CIC-IDS2017.
- **Assessment readiness.** Batch responses with stored events include `eventCoverage`:
  `linkedToAsset`, `addressWithoutAsset` (an IP that no single asset matches) and `withoutAddress`.
  Security Assessment reads only asset-linked events (rule `exact-ip-match-v1`). Events without an
  IP address are recorded with the reason `event has no IP address to match`, and the UI says they
  cannot inform an assessment, instead of producing one.
- **Correlation.** Imported events can be selected into an incident like any event. Because severity
  stays `INFO` and `signature` stays empty, no file content raises risk or matches techniques on its
  own; the event type is used as written.

### Limitations

- No per-batch deletion (as for CIC-IDS2017). A wrong mapping cannot be "re-imported": identical
  bytes are refused with `409`, and a corrected copy's rows are content-duplicates of the first
  import. Review the preview carefully before importing.
- Separate date and time columns are not combined; the timestamp must be one column.
- Syslog-style timestamps without a year, Excel serial dates and other formats are not supported.
- UTF-16 is detected only with a byte order mark; other encodings must be chosen explicitly.
- No username or hostname canonical field: such columns are kept in `sourceFields` only.
- Processing is synchronous within the upload limits (25 MiB / 100,000 rows); there is no background
  processing and no SIEM/EDR connector.

## CIC-IDS2017 profile (`cic-ids2017` v1)

For the `GeneratedLabelledFlows/TrafficLabelling` CSVs. Defined in
`backend/app/services/dataset_profiles.py` (`CicIds2017Profile`). Validation never converts a
value; rows that pass are then normalised to events as described in
[Normalisation to security events](#normalisation-to-security-events-cic-ids2017).

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
capture in New Brunswick, Canada, but that has not been verified against these files. Validation
still never converts a timestamp. Normalisation has to produce `occurred_at`, so it applies both
readings as explicit, recorded **assumptions** (12-hour clock; UTC-03:00); see
[Normalisation to security events](#normalisation-to-security-events-cic-ids2017). Confirming or
correcting them remains open.

## Normalisation to security events (`cic-ids2017`)

Implemented in `backend/app/services/dataset_normalization.py` and
`CicIds2017Profile.normalize_row`. Schema: migration `0005_dataset_event_provenance` (file `0005_add_dataset_event_provenance.py`).

**What is stored.** Each row that passed validation in a `VALIDATED` batch becomes one
`security_events` row, inserted in bounded chunks (1,000 rows) inside the batch's transaction: the
batch and all its events are committed together or not at all.

| Event field | Value |
|---|---|
| `source` | `dataset_import` (reserved: `POST /api/events/ingest` refuses it) |
| `event_type` | `network_flow` |
| `severity` | `info` for every row. The dataset's `Label` is **ground truth for evaluation, not a NETRA detection**, so it never sets severity or creates a finding. |
| `src_ip`, `dest_ip`, `src_port`, `dest_port` | As written (validated). |
| `protocol` | `tcp` for 6, `udp` for 17, otherwise the number as written. |
| `occurred_at` | Derived from `Timestamp` under two **assumptions** (below). |
| `import_batch_id`, `source_row` | The batch and the file row (header = row 1). Unique together. |
| `raw_data` | `groundTruthLabel`, `timestampAsWritten`, `occurredAtInterpretation`, `protocolAsWritten`, `sourceFields` (all 85 columns as written, keyed by profile key), `importBatchId`, `sourceRow`, `fileSha256`, `assetLink`. |
| `asset_id` | Set only by the asset rule below. |

**Timestamp assumptions (unverified).** `occurred_at` needs a 24-hour, zoned instant that the files
do not state. Normalisation reads the hour on a 12-hour clock without AM/PM (8-11 morning, 12 noon,
1-5 afternoon, i.e. 13:00-17:00) in assumed capture-local time **UTC-03:00** (Atlantic Daylight
Time; the capture is publicly described as taking place in New Brunswick, Canada). Neither reading is
confirmed by the files. Both are recorded on every event (`occurredAtInterpretation`, with the
original in `timestampAsWritten`), so events can be found and re-derived if either is corrected. The
constants are `CIC_IDS2017_ASSUMED_UTC_OFFSET` and `CIC_IDS2017_TIME_INTERPRETATION`.

**Duplicates.** The event uid is `dataset:cic-ids2017:<sha256 of the row's cells as written>`. A row
identical to one already stored, earlier in the same file or in an earlier batch, is not stored
again. It is counted in the batch's `duplicateRows`, and the stored event keeps the provenance of the
first occurrence. `eventsCreated + duplicateRows = acceptedRows` for a normalised batch. Re-uploading
an identical file is still refused with `409` (see [Duplicate policy](#duplicate-policy)).

**Asset linking (rule `exact-ip-match-v1`).** An event is linked to an asset only when exactly one
asset's `ip_address` equals the row's source or destination address. With no match, or with more
than one matching asset, `asset_id` stays empty. An event with no address at all (possible with
`security-csv`) records `event has no IP address to match`. The outcome, including candidates when
ambiguous, is recorded in `raw_data.assetLink`. No asset is created or changed by an import.

**API.** Batch responses add `eventsCreated` and `duplicateRows`. Event responses add `importBatchId`
and `sourceRow`. `GET /api/events?importBatchId=<id>` lists a batch's events, and
`GET /api/events?source=DATASET_IMPORT` lists all imported events.

### From imported events to assessment findings

Security Assessment reads events linked to the assessed asset within a 7-day window ending at the
assessment's `asOf`. `POST /api/assessments` accepts an optional `asOf` (zoned, not in the future;
default now). This lets a historical dataset such as CIC-IDS2017 (July 2017) be assessed in its own
time. Only events are bounded by `asOf`; vulnerabilities, incidents and threat indicators are their
current state.

Imported events are cited in findings only through the engine's existing rules: as matches of
active IP threat indicators (`threat_intel_matches`, any severity) or as activity on an inactive
asset. Because imported rows are `info`, they are never counted as high-severity events. Every cited
event ID traces back to `import_batch_id` and `source_row`; this is covered end to end by
`backend/tests/test_dataset_normalization.py::test_imported_rows_trace_into_assessment_findings`.

**Preconditions for a demonstration.** The asset must exist with the dataset's IP address **before
the upload**, because links are made only at import time, and a threat indicator must exist for the
IP of interest. Neither is created by an import, and neither can be created through the API. For a
local demonstration, `python -m app.db.seed_dataset_context` (run from `backend/`) creates exactly
two clearly labelled records: asset `CIC-DEMO-WEB-50` (192.168.10.50, environment `test`) and an
active IP indicator for 172.16.0.1 whose source reads "NETRA dataset demo (analyst-entered, not a
threat feed)". Choosing 172.16.0.1 was informed by the dataset's labels, so the indicator is
analyst-entered context, not an independent detection. The default is a read-only dry run.
`--apply --confirm-target localhost:5432/netra` writes, and only to a local database. Existing records
are never changed. Then upload a CIC-IDS2017 extract whose rows involve 192.168.10.50, and assess
`CIC-DEMO-WEB-50` with an event window ending on 2017-07-07 or later (the Assessment page's
"Event window ends (UTC)" field, i.e. `asOf`).

**Not implemented yet.** NETRA's own detection rules over imported flows; background processing for
large files (uploads are processed in the request, within the 25 MiB / 100,000-row limits); and
per-batch removal of imported events (`import_batch_id` has no `ON DELETE`, so a batch with events
cannot be deleted by accident).

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
