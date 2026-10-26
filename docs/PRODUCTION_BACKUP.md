# Production backup and restore rehearsal

This procedure takes a verified logical backup of production (Neon) and proves it restores, before a
migration. It does not migrate, deploy or write to production.

## Production migration record (2026-10-26)

- **Before:** production verified in the Neon SQL Editor at PostgreSQL **18.6**, Alembic revision
  **`0005_dataset_event_provenance`**.
- **Restore points taken first:** a manual Neon snapshot of production, and a separate backup branch.
  These are Neon-side restore points. They are **not** a verified logical backup: Parts B and C below
  were **not** run, so no `pg_dump` archive exists and no restore has been tested.
- **Rehearsal:** the migration SQL was rehearsed on the Neon branches `netra-migration-test` and
  `netra-migration-test-2` (created from production), then compared with the migration files
  `0006_add_risk_evaluations.py` and `0007_event_attack_techniques.py` (no differences).
- **Migration:** `0006_add_risk_evaluations` and `0007_event_attack_techniques` were applied to production
  in the Neon SQL Editor, as one guarded `DO` block (preconditions: primary, one `alembic_version` row at
  `0005`, base tables present, new tables absent; postcondition: revision `0007`), so a failure would
  have rolled back the whole migration.
- **After (verified):** revision **`0007_event_attack_techniques`**; `risk_evaluations` and
  `event_attack_techniques` exist; all five expected indexes are present; 3 incidents and 9 security
  events were kept; 0 rows in each new table.
- **Still open:** no verified logical backup of production exists. Take one with this procedure before
  the next production migration.

**Validation status:** the two script blocks below have passed a **syntax-only** check with the Windows
PowerShell 5.1 parser. They have **not** been run against any database, and their runtime behaviour is
unverified. Run them for the first time with someone reviewing the output.

**Written for the pre-0006 state (historical).** As written, Part B and Part C expect revision
`0005_dataset_event_provenance` and the absence of `risk_evaluations` and `event_attack_techniques`, so
against today's production (`0007`) they stop at the identity check, before any dump. Before reusing
them, update `$ExpectedRevision`, `$RequiredTables`, `$NotYetTables`, `$CountedTables` and the archive
name (`pre-0006`) for the next migration, have the change reviewed, and syntax-check the blocks again.

## Rules

- **Fail closed.** Each script block stops at the first unexpected result (`throw`). Never re-run a later
  part after an earlier part stopped; fix the cause and start again from Part A.
- **No credential in a command, file, transcript or audit record.** Production credentials are typed only
  into the password prompt of `psql` and `pg_dump` (`--password`). No URL is used anywhere. Never run
  `Get-ChildItem Env:` (or `dir env:`) while a password variable is set: it would print it.
- **Production is read only.** Part B runs one read-only query session and `pg_dump`. Part C restores into
  a local scratch database only, with **local** credentials, never production's.
- **Never weaken TLS.** Part B uses `verify-full` with a reviewed root certificate. If that certificate
  cannot be obtained and verified (Part A), **Part B is blocked**; there is no fallback.
- **Stop for review after Part C.** Migrations (including a rehearsal on a Neon branch) and deployment
  are separate steps that each need their own approval.
- Use Windows PowerShell 5.1 in Windows Terminal or the console, **not** PowerShell ISE (ISE cannot answer
  the tools' password prompts). Run from the repository root.

## What is verified by a machine and what by a person

- **TLS `verify-full` (machine):** proves that the server presented a certificate for the configured host
  name that chains to the root certificate you reviewed. It does **not** prove which Neon project or branch
  that host belongs to.
- **Project and branch (person):** only you can confirm, in the Neon console, that the direct endpoint you
  copy belongs to NETRA's production project and branch. Part B asks you to type the database and branch
  names, but that records your confirmation; it is not a technical proof.
- **Database identity (machine):** after connecting, Part B checks the database name, server version,
  primary (not replica), Alembic revision and the absence of the 0006/0007 tables.

## Part A: manual confirmations and prerequisites (no commands)

Record each answer; Part B asks for some of them again.

- [ ] In the Neon console, the **project** is NETRA's production project.
- [ ] The **branch** is the production branch. Note its exact name. A host name alone does not prove
      the branch: confirm in the console that the compute endpoint you copy belongs to that branch.
- [ ] Connection details with **connection pooling off** (direct endpoint). The host must **not**
      contain `-pooler`. Note the exact host.
- [ ] The **database** NETRA uses on that branch, and a **role** that can read every table (the owner
      role). Note both. Have the role's password ready to type; do not paste it into any file or chat.
- [ ] The Neon SQL Editor, on that same branch and database, still shows
      `SELECT version_num FROM alembic_version;` = `0005_dataset_event_provenance`.
- [ ] **TLS root certificate (prerequisite; Part B is blocked without it).** The local PostgreSQL client's
      OpenSSL has no usable default certificate store on this machine (its configured directory,
      `C:\Program Files\Common Files\SSL`, does not exist), so `PGSSLROOTCERT=system` cannot be relied on.
      You must instead:
      1. identify, from Neon's official documentation, the certificate authority that issues the endpoint's
         TLS certificate;
      2. download that authority's **root** certificate in PEM format from the authority's official site;
      3. obtain the root certificate's **SHA-256 fingerprint** from an authoritative source separate from
         the download, and note it;
      4. save the PEM file at a known local path outside the repository (for example
         `C:\NETRA-backups\trust\`), containing that one certificate only.
      If any of these cannot be done or verified, **stop: Part B is blocked.** Do not lower the TLS mode.
- [ ] `C:\NETRA-backups` exists, is outside the repository, and has free space for the dump (the
      2026-10-12 production dump was about 60 KB; allow far more).
- [ ] For Part C: a local PostgreSQL 18 server on port 5432 and its local superuser (`postgres`) password.
      These are **local** credentials, unrelated to production.

## Part B: verified backup

Fill in the six values at the top, then paste the block into a **new** PowerShell window. It stops at the
first problem, before any connection if a prerequisite fails, and always clears the TLS settings it set.
If `pg_dump` fails, a partial file is renamed `*.incomplete` (never deleted) so it cannot be mistaken for a
backup.

Row counts for nine tables are read in the same read-only session as the identity check. `pg_dump` takes
its own consistent snapshot a little later, so if production is written in between, the counts can
legitimately differ from the archive. Part C compares them and **stops for review** on any difference: a
match is evidence, not proof, that the archive holds the same data.

```powershell
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- From Part A. None of these is a secret. --------------------------------------------------------
$NeonHost       = '<direct-endpoint-host>'     # without -pooler, e.g. ep-...neon.tech
$NeonDatabase   = '<production-database>'
$NeonRole       = '<role>'
$NeonBranch     = '<production-branch-name>'
$RootCertPath   = '<path to the reviewed root CA certificate, PEM>'
$RootCertSha256 = '<its reviewed SHA-256 fingerprint>'
# ----------------------------------------------------------------------------------------------------
$ExpectedRevision    = '0005_dataset_event_provenance'
$ExpectedServerMajor = 18
$Bin       = 'C:\Program Files\PostgreSQL\18\bin'
$BackupDir = 'C:\NETRA-backups'
$RequiredTables = @('alembic_version', 'users', 'password_reset_tokens', 'assets', 'vulnerabilities',
    'security_events', 'incidents', 'incident_events', 'incident_history', 'decisions', 'authorizations',
    'containment_actions', 'cyber_memories', 'threat_indicators', 'security_assessments',
    'assessment_findings', 'import_batches')
$NotYetTables  = @('risk_evaluations', 'event_attack_techniques')
$CountedTables = @('users', 'assets', 'security_events', 'incidents', 'incident_history', 'decisions',
    'authorizations', 'threat_indicators', 'import_batches')

function Stop-Workflow([string]$Reason) { throw "STOPPED: $Reason" }
function Invoke-Native([string]$Exe, [string[]]$Arguments) {
    # Runs a program and checks its exit code at once, before anything else can change $LASTEXITCODE.
    $output = & $Exe @Arguments
    $code = $LASTEXITCODE
    if ($code -ne 0) { Stop-Workflow "$(Split-Path $Exe -Leaf) exited with code $code" }
    return $output
}

$Archive = $null
$dumpStarted = $false
$dumpFinished = $false
try {
    # 1. Values present, a direct Neon endpoint, never a local or scratch target, no inherited overrides.
    foreach ($name in 'NeonHost', 'NeonDatabase', 'NeonRole', 'NeonBranch', 'RootCertPath', 'RootCertSha256') {
        $value = Get-Variable -Name $name -ValueOnly
        if ([string]::IsNullOrWhiteSpace($value) -or $value.StartsWith('<')) { Stop-Workflow "$name is not filled in" }
    }
    if ($NeonHost -match '-pooler') { Stop-Workflow 'pooled endpoint: use the direct endpoint' }
    if ($NeonHost -notmatch '\.neon\.tech$') { Stop-Workflow 'the host is not a Neon host' }
    if ($NeonHost -match '^(localhost|127\.|\[?::1\]?$)') { Stop-Workflow 'local host refused' }
    if ($NeonDatabase -in @('netra', 'netra_e2e', 'postgres') -or $NeonDatabase -like 'netra_restore_check_*') {
        Stop-Workflow 'local, test, maintenance or scratch database name refused'
    }
    $inherited = @(Get-ChildItem Env: | Where-Object { $_.Name -like 'PG*' -or $_.Name -in @('DATABASE_URL', 'NETRA_MIGRATION_CONFIRM_TARGET') } | ForEach-Object Name)
    if ($inherited.Count -gt 0) { Stop-Workflow "remove these environment variables first: $($inherited -join ', ')" }

    # 2. The reviewed root certificate: one PEM certificate, a self-signed root, in date, with the reviewed
    #    fingerprint. Checked before any connection; without it Part B is blocked (Part A).
    $RootCertPath = [IO.Path]::GetFullPath($RootCertPath)
    if (-not (Test-Path -LiteralPath $RootCertPath -PathType Leaf)) { Stop-Workflow 'the root certificate file does not exist' }
    $pem = [IO.File]::ReadAllText($RootCertPath)
    $blocks = [regex]::Matches($pem, '-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END CERTIFICATE-----')
    if ($blocks.Count -ne 1) { Stop-Workflow "the root certificate file must hold exactly one PEM certificate (found $($blocks.Count))" }
    $der = [Convert]::FromBase64String(($blocks[0].Groups[1].Value -replace '\s', ''))
    $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (, $der)
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    $fingerprint = (($hasher.ComputeHash($der) | ForEach-Object { $_.ToString('X2') }) -join '')
    $hasher.Dispose()
    $expectedFingerprint = ($RootCertSha256 -replace '[\s:]', '').ToUpperInvariant()
    if ($fingerprint -ne $expectedFingerprint) { Stop-Workflow 'the root certificate fingerprint does not match the reviewed value' }
    if ($cert.Subject -ne $cert.Issuer) { Stop-Workflow 'the certificate is not a self-signed root' }
    $now = Get-Date
    if ($now -lt $cert.NotBefore -or $now -gt $cert.NotAfter) { Stop-Workflow 'the root certificate is not currently valid' }
    Write-Host "Root certificate: $($cert.Subject), valid to $($cert.NotAfter.ToString('yyyy-MM-dd')), SHA-256 $fingerprint"

    # 3. Explicit human confirmation of the target (not a technical proof; see above).
    Write-Host "Target: host $NeonHost, database $NeonDatabase, role $NeonRole, branch $NeonBranch"
    if ((Read-Host 'Type the database name to confirm this is PRODUCTION') -cne $NeonDatabase) { Stop-Workflow 'database confirmation did not match' }
    if ((Read-Host "Type the branch name after confirming in the Neon console that this endpoint belongs to it") -cne $NeonBranch) { Stop-Workflow 'branch confirmation did not match' }

    # 4. Tools, and pg_dump at least the server's major version.
    foreach ($tool in 'pg_dump', 'pg_restore', 'psql') {
        if (-not (Test-Path -LiteralPath (Join-Path $Bin "$tool.exe"))) { Stop-Workflow "$tool.exe not found in $Bin" }
    }
    $dumpVersion = [string](Invoke-Native (Join-Path $Bin 'pg_dump.exe') @('--version'))
    $restoreVersion = [string](Invoke-Native (Join-Path $Bin 'pg_restore.exe') @('--version'))
    if ($dumpVersion -notmatch '\(PostgreSQL\) (\d+)\.') { Stop-Workflow 'cannot read the pg_dump version' }
    $clientMajor = [int]$Matches[1]
    if ($clientMajor -lt $ExpectedServerMajor) { Stop-Workflow "pg_dump $clientMajor is older than the server ($ExpectedServerMajor)" }

    # 5. A new archive path in the backup folder, outside the repository.
    if (-not (Test-Path -LiteralPath $BackupDir -PathType Container)) { Stop-Workflow "$BackupDir does not exist" }
    $repoRoot = [string](Invoke-Native 'git' @('rev-parse', '--show-toplevel'))
    $Archive = [IO.Path]::GetFullPath((Join-Path $BackupDir "neon-prod-$(Get-Date -Format 'yyyy-MM-dd-HHmmss')-pre-0006.dump"))
    if ($Archive.StartsWith([IO.Path]::GetFullPath($repoRoot), [StringComparison]::OrdinalIgnoreCase)) { Stop-Workflow 'the archive would be inside the repository' }
    foreach ($path in $Archive, "$Archive.list.txt", "$Archive.audit.json", "$Archive.incomplete") {
        if (Test-Path -LiteralPath $path) { Stop-Workflow "$path already exists; backups are never overwritten" }
    }

    # 6. TLS: certificate and host-name verification against the reviewed root only.
    $env:PGSSLMODE = 'verify-full'
    $env:PGSSLROOTCERT = $RootCertPath

    # 7. Read-only identity check and row counts, one session. psql prompts for the password.
    $countColumns = ($CountedTables | ForEach-Object { "(SELECT count(*) FROM public.$_)" }) -join ', '
    $sql = "SELECT current_database(), current_setting('server_version_num'), pg_is_in_recovery(), " +
           "(SELECT string_agg(version_num, ',') FROM alembic_version), " +
           "to_regclass('public.risk_evaluations') IS NULL, to_regclass('public.event_attack_techniques') IS NULL, " +
           $countColumns
    $rows = @(Invoke-Native (Join-Path $Bin 'psql.exe') @('--host', $NeonHost, '--port', '5432', '--username', $NeonRole,
        '--dbname', $NeonDatabase, '--password', '--no-psqlrc', '--quiet', '--tuples-only', '--no-align',
        '--field-separator=|', '--set=ON_ERROR_STOP=1',
        '--command', 'SET default_transaction_read_only = on', '--command', $sql) | Where-Object { $_ -ne '' })
    if ($rows.Count -ne 1) { Stop-Workflow 'the identity check did not return exactly one row' }
    $id = $rows[0].Split('|')
    if ($id.Count -ne (6 + $CountedTables.Count)) { Stop-Workflow 'the identity check returned an unexpected shape' }
    $serverMajor = [int][math]::Floor([int]$id[1] / 10000)
    if ($id[0] -cne $NeonDatabase) { Stop-Workflow "connected to database $($id[0]), not $NeonDatabase" }
    if ($serverMajor -ne $ExpectedServerMajor -or $clientMajor -lt $serverMajor) { Stop-Workflow "server major version is $serverMajor" }
    if ($id[2] -ne 'f') { Stop-Workflow 'the endpoint is a read replica, not the branch primary' }
    if ($id[3] -cne $ExpectedRevision) { Stop-Workflow "Alembic revision is $($id[3]), expected $ExpectedRevision" }
    if ($id[4] -ne 't' -or $id[5] -ne 't') { Stop-Workflow 'risk_evaluations or event_attack_techniques already exists' }
    $productionCounts = [ordered]@{}
    for ($i = 0; $i -lt $CountedTables.Count; $i++) { $productionCounts[$CountedTables[$i]] = [long]$id[6 + $i] }
    Write-Host "Identity verified: database $($id[0]), server $($id[1]), revision $($id[3])"

    # 8. The backup. pg_dump prompts for the password again.
    $dumpStarted = $true
    Invoke-Native (Join-Path $Bin 'pg_dump.exe') @('--host', $NeonHost, '--port', '5432', '--username', $NeonRole,
        '--dbname', $NeonDatabase, '--password', '--format=custom', '--file', $Archive) | Out-Null
    $dumpFinished = $true

    # 9. Archive checks: present, non-empty, checksum, readable listing with the expected schema objects.
    $item = Get-Item -LiteralPath $Archive
    if ($item.Length -le 0) { Stop-Workflow 'the archive is empty' }
    $sha256 = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash
    $listing = @(Invoke-Native (Join-Path $Bin 'pg_restore.exe') @('--list', $Archive))
    $listing | Out-File -LiteralPath "$Archive.list.txt" -Encoding utf8 -NoClobber
    $tables = @($listing | ForEach-Object { if ($_ -match '^\d+; \d+ \d+ TABLE public (\S+) ') { $Matches[1] } })
    $tableData = @($listing | ForEach-Object { if ($_ -match '^\d+; \d+ \d+ TABLE DATA public (\S+) ') { $Matches[1] } })
    $foreignKeys = @($listing | Where-Object { $_ -match '^\d+; \d+ \d+ FK CONSTRAINT public ' }).Count
    $missing = @($RequiredTables | Where-Object { $_ -notin $tables })
    $unexpected = @($NotYetTables | Where-Object { $_ -in $tables })
    if ($missing.Count -gt 0) { Stop-Workflow "the archive lacks required tables: $($missing -join ', ')" }
    if ($unexpected.Count -gt 0) { Stop-Workflow "the archive already has: $($unexpected -join ', ')" }
    if (@($RequiredTables | Where-Object { $_ -notin $tableData }).Count -gt 0) { Stop-Workflow 'a required table has no TABLE DATA entry' }

    # 10. Audit record: identity and results only; no role, password or URL.
    [ordered]@{
        recorded_at_utc         = (Get-Date).ToUniversalTime().ToString('o')
        purpose                 = 'pre-0006/0007 production backup'
        source                  = "$NeonHost/$NeonDatabase"
        branch_confirmed        = $NeonBranch
        tls                     = 'verify-full'
        root_certificate_sha256 = $fingerprint
        server_version_num      = $id[1]
        alembic_revision        = $id[3]
        pg_dump_version         = $dumpVersion.Trim()
        pg_restore_version      = $restoreVersion.Trim()
        archive                 = $Archive
        archive_bytes           = $item.Length
        archive_sha256          = $sha256
        listing_file            = "$Archive.list.txt"
        tables                  = $tables.Count
        table_data_entries      = $tableData.Count
        fk_constraints          = $foreignKeys
        extra_tables            = @($tables | Where-Object { $_ -notin $RequiredTables })
        production_counts       = $productionCounts
        production_counts_note  = 'read in the identity session, before pg_dump took its own snapshot'
        restore_rehearsal       = 'not yet run (Part C)'
    } | ConvertTo-Json | Out-File -LiteralPath "$Archive.audit.json" -Encoding utf8 -NoClobber
    Write-Host "BACKUP VERIFIED: $Archive ($($item.Length) bytes) SHA256 $sha256"
    Write-Host 'Next: Part C with this path and checksum. Do not migrate.'
}
catch {
    if ($dumpStarted -and -not $dumpFinished -and $Archive -and (Test-Path -LiteralPath $Archive)) {
        Rename-Item -LiteralPath $Archive -NewName "$(Split-Path $Archive -Leaf).incomplete"
        Write-Warning "A partial file was renamed to $(Split-Path $Archive -Leaf).incomplete; it is not a backup."
    }
    throw
}
finally {
    Remove-Item Env:PGSSLMODE, Env:PGSSLROOTCERT -ErrorAction SilentlyContinue
}
```

## Part C: restore rehearsal into a local scratch database

Run it in a **new** PowerShell window. Every PostgreSQL command gets one fixed connection string
(`host=127.0.0.1 hostaddr=127.0.0.1 port=5432 user=postgres sslmode=disable`), and any inherited `PG*`
variable (including `PGHOST`, `PGHOSTADDR`, `PGPORT`, `PGSERVICE`, `PGSERVICEFILE`, `PGPASSFILE`,
`PGOPTIONS`) stops the block before any connection. No service name is ever given, so no service file is
read. Before the scratch database is created, PostgreSQL itself must report a loopback address and port
5432; the server's `system_identifier` is recorded then and re-checked before the restore, before every
verification query and before the drop. Any mismatch stops the block. The scratch database name must match
`^netra_restore_check_\d{14}$`, and only a database this run created is ever dropped.

```powershell
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# --- From Part B. -----------------------------------------------------------------------------------
$Archive        = '<archive path printed by Part B>'
$ExpectedSha256 = '<SHA256 printed by Part B>'
# ----------------------------------------------------------------------------------------------------
$LocalConnection  = 'host=127.0.0.1 hostaddr=127.0.0.1 port=5432 user=postgres sslmode=disable connect_timeout=10'
$ExpectedRevision = '0005_dataset_event_provenance'
$Bin       = 'C:\Program Files\PostgreSQL\18\bin'
$BackupDir = 'C:\NETRA-backups'
$RequiredTables = @('alembic_version', 'users', 'password_reset_tokens', 'assets', 'vulnerabilities',
    'security_events', 'incidents', 'incident_events', 'incident_history', 'decisions', 'authorizations',
    'containment_actions', 'cyber_memories', 'threat_indicators', 'security_assessments',
    'assessment_findings', 'import_batches')
$Scratch = 'netra_restore_check_' + (Get-Date -Format 'yyyyMMddHHmmss')
$script:ServerId = $null

function Stop-Workflow([string]$Reason) { throw "STOPPED: $Reason" }
function Invoke-Native([string]$Exe, [string[]]$Arguments) {
    $output = & $Exe @Arguments
    $code = $LASTEXITCODE
    if ($code -ne 0) { Stop-Workflow "$(Split-Path $Exe -Leaf) exited with code $code" }
    return $output
}
function Get-Connection([string]$Database) {
    # Only the maintenance database or this run's scratch database; never anything else.
    if ($Database -cne 'postgres' -and $Database -notmatch '^netra_restore_check_\d{14}$') { Stop-Workflow "database $Database refused" }
    if ($Database -ne 'postgres' -and $Database -cne $Scratch) { Stop-Workflow "database $Database is not this run's scratch database" }
    return "$LocalConnection dbname=$Database"
}
function Invoke-Psql([string]$Database, [string]$Sql) {
    return @(Invoke-Native (Join-Path $Bin 'psql.exe') @('--dbname', (Get-Connection $Database), '--no-password',
        '--no-psqlrc', '--quiet', '--tuples-only', '--no-align', '--field-separator=|', '--set=ON_ERROR_STOP=1',
        '--command', 'SET default_transaction_read_only = on', '--command', $Sql) | Where-Object { $_ -ne '' })
}
function Assert-LocalServer([string]$Database) {
    # PostgreSQL itself must report loopback, port 5432, the requested database and the same server as before.
    $row = @(Invoke-Psql $Database "SELECT host(inet_server_addr()), inet_server_port(), (SELECT system_identifier FROM pg_control_system()), current_database()")
    if ($row.Count -ne 1) { Stop-Workflow 'the server identity check did not return exactly one row' }
    $f = $row[0].Split('|')
    if ($f.Count -ne 4) { Stop-Workflow 'the server identity check returned an unexpected shape' }
    if ($f[0] -notin @('127.0.0.1', '::1')) { Stop-Workflow "the connected server address is $($f[0]), not loopback" }
    if ($f[1] -ne '5432') { Stop-Workflow "the connected server port is $($f[1]), not 5432" }
    if ($f[3] -cne $Database) { Stop-Workflow "connected to database $($f[3]), not $Database" }
    if ($null -eq $script:ServerId) { $script:ServerId = $f[2] }
    elseif ($f[2] -ne $script:ServerId) { Stop-Workflow 'the server identity changed during the rehearsal' }
}
function Invoke-LocalQuery([string]$Sql) {
    Assert-LocalServer $Scratch
    return Invoke-Psql $Scratch $Sql
}

$created = $false
$restored = $false
$verified = $false
$countReview = 'not compared'
$cleanup = 'not needed'
$RecordPath = $null   # set only once the archive path has been validated
try {
    # 1. Before anything else: no inherited libpq setting may redirect a connection.
    $inherited = @(Get-ChildItem Env: | Where-Object { $_.Name -like 'PG*' -or $_.Name -in @('DATABASE_URL', 'NETRA_MIGRATION_CONFIRM_TARGET') } | ForEach-Object Name)
    if ($inherited.Count -gt 0) { Stop-Workflow "remove these environment variables first (open a new window): $($inherited -join ', ')" }
    if ($Scratch -notmatch '^netra_restore_check_\d{14}$') { Stop-Workflow 'scratch database name refused' }

    # 2. The archive is the one Part B verified: in the backup folder, checksum matching both the value
    #    given here and the Part B audit record.
    $Archive = [IO.Path]::GetFullPath($Archive)
    if (-not $Archive.StartsWith([IO.Path]::GetFullPath($BackupDir) + '\', [StringComparison]::OrdinalIgnoreCase)) { Stop-Workflow 'the archive is not in the backup folder' }
    if (-not (Test-Path -LiteralPath "$Archive.audit.json")) { Stop-Workflow 'no audit record from Part B' }
    $audit = Get-Content -LiteralPath "$Archive.audit.json" -Raw | ConvertFrom-Json
    $actualSha256 = (Get-FileHash -LiteralPath $Archive -Algorithm SHA256).Hash
    if ($actualSha256 -ne $ExpectedSha256) { Stop-Workflow 'the archive checksum does not match the value given' }
    if ($audit.archive_sha256 -ne $ExpectedSha256) { Stop-Workflow 'the checksum does not match the Part B audit record' }
    if ($audit.archive -ne $Archive) { Stop-Workflow 'the audit record names a different archive' }
    $RecordPath = "$Archive.$Scratch.restore-check.json"
    if (Test-Path -LiteralPath $RecordPath) { Stop-Workflow "$RecordPath already exists" }
    $listing = Get-Content -LiteralPath "$Archive.list.txt"
    $archiveForeignKeys = @($listing | Where-Object { $_ -match '^\d+; \d+ \d+ FK CONSTRAINT public ' }).Count

    # 3. The port is served by the local postgres.exe only, on a loopback-reachable address.
    $listeners = @(Get-NetTCPConnection -State Listen -LocalPort 5432 -ErrorAction SilentlyContinue)
    if ($listeners.Count -eq 0) { Stop-Workflow 'nothing listens on port 5432' }
    foreach ($listener in $listeners) {
        if ((Get-Process -Id $listener.OwningProcess).ProcessName -ne 'postgres') { Stop-Workflow 'port 5432 is not served by postgres.exe only' }
    }
    if (-not ($listeners.LocalAddress | Where-Object { $_ -in @('127.0.0.1', '::1', '0.0.0.0', '::') })) { Stop-Workflow 'no loopback listener' }

    # 4. LOCAL superuser password for this block only (never the production password).
    $secure = Read-Host 'LOCAL postgres password (not production)' -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try { $env:PGPASSWORD = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr); Remove-Variable secure, bstr }

    # 5. Prove the server from PostgreSQL itself, then create the scratch database (fails if it exists).
    Assert-LocalServer 'postgres'
    Invoke-Native (Join-Path $Bin 'createdb.exe') @('--maintenance-db', (Get-Connection 'postgres'), '--no-password', $Scratch) | Out-Null
    $created = $true

    # 6. Restore all-or-nothing into the scratch database, after re-proving the server.
    Assert-LocalServer $Scratch
    Invoke-Native (Join-Path $Bin 'pg_restore.exe') @('--dbname', (Get-Connection $Scratch), '--no-password',
        '--no-owner', '--no-privileges', '--single-transaction', '--exit-on-error', $Archive) | Out-Null
    $restored = $true

    # 7. Verification of the restored copy (read-only sessions; the server is re-proved before each query).
    $revision = (Invoke-LocalQuery 'SELECT string_agg(version_num, '','') FROM alembic_version')[0]
    if ($revision -cne $ExpectedRevision) { Stop-Workflow "restored revision is $revision" }
    $restoredTables = Invoke-LocalQuery "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'"
    $missing = @($RequiredTables | Where-Object { $_ -notin $restoredTables })
    if ($missing.Count -gt 0) { Stop-Workflow "restored copy lacks: $($missing -join ', ')" }
    if (@('risk_evaluations', 'event_attack_techniques' | Where-Object { $_ -in $restoredTables }).Count -gt 0) { Stop-Workflow 'restored copy already has 0006/0007 tables' }
    $restoredForeignKeys = [int](Invoke-LocalQuery "SELECT count(*) FROM pg_constraint WHERE contype = 'f' AND connamespace = 'public'::regnamespace")[0]
    if ($restoredForeignKeys -ne $archiveForeignKeys) { Stop-Workflow "foreign keys: archive $archiveForeignKeys, restored $restoredForeignKeys" }

    # 8. Review checkpoint: restored row counts against the counts read before the dump (Part B).
    $countedTables = @($audit.production_counts.PSObject.Properties | ForEach-Object Name)
    if ($countedTables.Count -eq 0) { Stop-Workflow 'the audit record has no production counts' }
    $countSql = ($countedTables | ForEach-Object { "SELECT '$_', count(*) FROM public.$_" }) -join ' UNION ALL '
    $differences = @()
    foreach ($row in (Invoke-LocalQuery $countSql)) {
        $parts = $row.Split('|')
        $expected = [long]$audit.production_counts.($parts[0])
        Write-Host "  $($parts[0]): restored $($parts[1]), production before dump $expected"
        if ([long]$parts[1] -ne $expected) { $differences += $parts[0] }
    }
    if ($differences.Count -gt 0) {
        $countReview = "differs: $($differences -join ', ')"
        Stop-Workflow "REVIEW REQUIRED: row counts differ for $($differences -join ', '). This can be legitimate if production was written between the count and the dump; review before relying on this backup."
    }
    $countReview = 'match'
    $verified = $true
    Write-Host "RESTORE REHEARSAL PASSED for $Scratch"
}
finally {
    if ($created) {
        try {
            Assert-LocalServer 'postgres'   # re-proved before the drop; on failure nothing is dropped
            Invoke-Native (Join-Path $Bin 'dropdb.exe') @('--maintenance-db', (Get-Connection 'postgres'), '--no-password', $Scratch) | Out-Null
            $cleanup = 'dropped'
        }
        catch {
            $cleanup = 'FAILED'
            Write-Warning "Scratch database $Scratch was NOT confirmed dropped. Drop it manually on the LOCAL server only, after confirming the server, and record that you did."
        }
    }
    Remove-Item Env:PGPASSWORD -ErrorAction SilentlyContinue
    $result = [ordered]@{
        recorded_at_utc          = (Get-Date).ToUniversalTime().ToString('o')
        archive_sha256           = $ExpectedSha256
        scratch_database         = $Scratch
        target                   = '127.0.0.1:5432 (local)'
        server_system_identifier = $script:ServerId
        restore_completed        = $restored
        row_count_review         = $countReview
        verification_passed      = $verified
        scratch_cleanup          = $cleanup
    }
    if ($RecordPath) {
        $result | ConvertTo-Json | Out-File -LiteralPath $RecordPath -Encoding utf8 -NoClobber
        Write-Host "Restore check recorded in $RecordPath (cleanup: $cleanup)"
    }
}
```

**What each check proves.** `pg_restore --list` (Part B) proves only that the archive is a readable
custom-format file and which objects it contains; it does not prove that data loads or constraints
rebuild. The restore (`--single-transaction --exit-on-error`) proves the whole archive loads, or nothing
does. The checks after it confirm the expected revision, the required tables, the absence of the
0006/0007 tables and the same number of foreign keys as the archive. The row-count comparison is a review
checkpoint, not an exact consistency test: production counts are read just before `pg_dump` takes its own
snapshot, and matching counts are not proof of identical contents.

## Stop: review before anything else

After Part C passes, stop and review the two records (`*.audit.json`, `*.<scratch>.restore-check.json`) and
the listing. Do **not** run migrations or deploy as part of this procedure. The next steps are separate and
each needs its own approval:

1. Rehearse the migration on a **Neon branch** created from production (never on production first),
   with the migration guard's `NETRA_MIGRATION_CONFIRM_TARGET` (see `SECURITY_ASSESSMENT_MIGRATION.md`),
   or, as for 0006/0007, as one guarded SQL statement in the Neon SQL Editor.
2. Apply it to production, then deploy the backend, then the frontend.

## Limitations

- **Runtime unverified.** Both blocks are syntax-checked only. In particular these have not been observed on
  this machine: that `psql --quiet --tuples-only` prints no status line for `SET` (if it does, the
  one-row checks stop the block); that `createdb`/`dropdb` accept a connection string in `--maintenance-db`;
  that `pg_control_system()` is readable by the local `postgres` role; and TLS `verify-full` with the
  reviewed root certificate.
- **Separate connections.** Each step opens its own connection. The fixed connection string and the
  `system_identifier` re-check make a different server detectable, but a server swapped on the same
  loopback port between a check and the command that follows it cannot be excluded entirely.
- **Production password:** typed into the tools' own prompts, twice (identity check, dump). Not echoed, not
  in PowerShell history, not in any argument and not in a transcript.
- **Local password:** held in `PGPASSWORD` for Part C only. While set, it is inherited by every program
  started from that window and readable by other processes running as the same Windows user; it is removed
  in `finally`. Close the window when finished.
- **Records** hold the host, database, branch name, versions, sizes, checksums, root-certificate
  fingerprint, server identifier and counts: no role, password or URL. The `pg_restore` listing names
  database objects and the archive owner.

## Retention and cleanup

- Keep the archive, its listing and both records at least until 0006 and 0007 are verified in
  production and the release has been stable for an agreed period (suggested: 30 days). Never delete
  older backups without approval.
- Production dumps contain user email addresses and password hashes. Keep a second copy on
  access-controlled storage; `C:\NETRA-backups` is a single local copy.
- A `*.incomplete` file is a failed dump: keep it until reviewed, then remove it with approval.
- If a scratch database could not be confirmed dropped, confirm the server (loopback, port 5432, same
  `system_identifier`) before dropping it on the local server only, and record that in the review notes.
