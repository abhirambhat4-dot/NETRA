# ThreatFox threat intelligence

NETRA can import indicators of compromise from [ThreatFox](https://threatfox.abuse.ch/) (abuse.ch) into its
existing `threat_indicators` table, which event correlation, risk scoring and Security Assessment already read.
Indicators are reference data for matching events; they are never stored as NETRA security events.

## How data arrives

- **Manual sync only:** `backend/scripts/netra_threatfox_sync.py`. A dry run (the default) fetches, maps and
  counts in a read-only transaction that is rolled back; `--apply` writes. There is no scheduler.
- **Local `netra_e2e` only, in both modes:** before any connection or ThreatFox request, the target must be
  PostgreSQL on `localhost`/`127.0.0.1`/`::1` with database `netra_e2e`, with no URL options or libpq
  variables that could redirect it; after connecting, and still before any request, the server must report
  `netra_e2e` on a loopback address. Anything else is refused. `--apply` also needs
  `--confirm-target host:port/database`, which cannot authorise any other target. Syncing into another
  database, including production, would need a separately approved change.
- **Window:** ThreatFox `get_iocs` with `days` 1–7 (default 1) returns indicators *first reported* in that
  window. This is recent history imported on demand, not real-time monitoring.
- **Key:** `THREATFOX_AUTH_KEY`, backend configuration only (`backend/.env` or `backend/.env.e2e`, or Render's
  environment). It is sent only as the `Auth-Key` header and is never printed, logged, stored or sent to the
  browser. Live Tracking reads stored indicators through `GET /api/threat-intelligence`; it never calls ThreatFox.
- **Output:** counts only: received by ThreatFox type, mappable by NETRA type, `is_compromised` true/false/missing,
  skipped by reason, and new/updated/unchanged/expired/reactivated. Never indicator values.

## Provenance and mapping

| ThreatFox | NETRA | Notes |
|---|---|---|
| `ip:port` | `ip` | Address only; the port has no column. One address on several ports becomes one row (highest confidence, earliest first seen, latest last seen). Non-public addresses are rejected. |
| `domain` | `domain` | Normalised exactly as correlation normalises domains. |
| `url` | `url` | http/https only; case-folded, trailing `/` removed (as correlation matches). |
| `md5_hash`, `sha1_hash`, `sha256_hash` | `hash` | Lower-case hex of the exact length. |
| anything else | not stored | Counted as `unsupported_type`. |

- **Source:** every row is attributed to `ThreatFox (abuse.ch)`; the sync never reads for update, expires or
  deletes rows from any other source.
- **Confidence:** ThreatFox `confidence_level` ÷ 100 (0–1).
- **Severity:** ThreatFox has none. New rows get `medium`, a NETRA-assigned value; an existing row's severity
  is never changed. Risk scoring combines 70% confidence and 30% severity for each match.
- **Not stored:** ThreatFox `id`, malware family, tags, reporter and reference (no columns exist).

## Compromised assets

ThreatFox marks some indicators `is_compromised: true`: legitimate infrastructure that was compromised, where
treating the indicator as malicious could affect a real service. NETRA **fails closed**: only records whose
`is_compromised` is exactly boolean `false` are imported. Until NETRA can store the flag (a later migration),
everything else is skipped and counted:

| `is_compromised` | Outcome | Reason |
|---|---|---|
| `false` | imported | — |
| `true` | skipped | `compromised_asset` |
| missing or `null` | skipped | `compromised_flag_missing` |
| anything else (`"true"`, `"false"`, `1`, `0`, …) | skipped | `compromised_flag_unrecognized` |

Skipped records are dropped before duplicates are merged, so a compromised or unrecognised report of the same
indicator can neither add to nor suppress a valid one.

**Observed in one dry run (2026-10-24, a single `get_iocs` request with `days=1`; nothing was written).** These
are figures from that one snapshot, not permanent totals or a guide to future proportions:

| | Records |
|---|---|
| Received | 1,105 |
| `is_compromised = false` (imported) | 769 |
| `is_compromised = true` (skipped, `compromised_asset`) | 336 |
| Missing or unrecognised flag | 0 |
| Mappable indicators after filtering and de-duplication | 741 |

In that snapshot the compromised records were all domains, URLs or IP addresses (no hashes), and 28 records
were the same IP address on another port, merged into one indicator.

## Expiry

- **Rule (symmetric):** on every sync, each ThreatFox indicator is set active exactly when its `last_seen` is
  trustworthy and within `THREATFOX_EXPIRY_DAYS` (default 90, allowed 1–180; ThreatFox itself stops serving
  indicators after six months). `last_seen` is the latest date ThreatFox reported for it (its `last_seen`, or
  `first_seen` when ThreatFox gave none), after this sync's report is merged in. The window is inclusive:
  `now − expiry_days ≤ last_seen`.
- **Trustworthy dates:** a missing date, or one more than 24 hours in the future, is never treated as fresh.
  Incoming records with a missing or unparsable `first_seen` are skipped (`invalid_timestamp`) and future dates
  are rejected (`future_timestamp`). Stored `first_seen`/`last_seen` are NOT NULL and timezone-aware.
- **Effect:** correlation and Security Assessment match active indicators only, so inactive indicators stop
  matching. They are **never deleted** and keep their provenance. Rows from other sources are never changed.
- **Consistency:** the active state depends only on the stored date, the window and the clock, never on past
  settings. Lowering the window expires rows on the next sync; raising it reactivates rows whose date is back
  inside it, without a fresh report. Dry run and apply compute the same counts; the dry run writes nothing.
- **When a repeated report reactivates an indicator:** only when it moves the stored `last_seen` back inside
  the window (a report never moves `last_seen` backwards). A repeated report with an older or equally stale
  date (for example from an old saved fixture) changes nothing. Equally, an inactive indicator whose stored date
  is inside the window is reactivated on the next sync whether or not it is reported again.

**Limitations**

- ThreatFox gives no `last_seen` for most indicators (1,053 of 1,109 in the first real dry run), and `get_iocs`
  filters by `first_seen`. An indicator ThreatFox still lists, but which is not re-reported, therefore expires
  90 days after it was first reported. Bulk exports could refresh this; they are not used.
- The state is reconciled only when the sync runs. Between runs, an indicator can stay active past its window.
- `is_active` on ThreatFox rows is derived from the date and the window, not an analyst setting: a ThreatFox row
  deactivated by hand (there is no API for it) is set back to active on the next sync if its date is in the
  window. Use a different mechanism, not `is_active`, if analysts need to suppress an indicator.
- Expiry uses the backend's clock; a badly wrong clock would expire or keep indicators wrongly.
- The dashboard's indicator count and Live Tracking's "stored" figure include inactive indicators.

## Terms of use: to be confirmed

From the abuse.ch Terms of Use (<https://abuse.ch/terms-of-use/>, last updated 21 October 2026) and the
ThreatFox API page (<https://threatfox.abuse.ch/api/>):

- Free access is for **not-for-profit** purposes; commercial use of ThreatFox "may require a paid subscription"
  managed by Spamhaus. ThreatFox is not CC0. **Confirm that NETRA's use qualifies as not-for-profit**, and plan a
  subscription before any commercial deployment.
- Usage is subject to unstated query-volume limits; high-volume automated access is prohibited and access can
  be revoked. NETRA's sync is manual, one request per run; do not schedule frequent runs.
- Derivative works need abuse.ch/Spamhaus consent, and the data may not be used to train AI models without
  written consent. NETRA does not train on it. **Confirm that storing indicators for matching is acceptable.**
- No attribution requirement is stated; NETRA attributes every row to `ThreatFox (abuse.ch)` regardless.
- The data comes with no warranty.
