"""Local dataset profiler: stream CSV files through a dataset profile and report aggregate facts.

Run from backend/:

    python -m app.services.dataset_profiler --profile cic-ids2017 PATH [PATH ...] [--json]

PATH is a .csv file or a folder of .csv files. The profiler is read-only and offline: it does not
upload, connect to a database, store rows or write anywhere. Each file is streamed twice (raw bytes,
then CSV records through the same validation code as uploads), lines are length-capped as for
uploads, and every tally keeps a bounded number of distinct keys, so memory stays bounded however
large the file is. Output holds counts, rule names, row numbers and the categorical values a
profile's ``describe_record`` yields (for CIC-IDS2017: label, protocol, digit-masked timestamp
shape, parsed hour and date), each escaped and truncated; it never prints whole rows or other cells.
"""

import argparse
import hashlib
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from app.core.config import Settings
from app.services.dataset_import import READ_ERRORS, check_record, open_csv, read_issue
from app.services.dataset_profiles import PROFILES, DatasetProfile

CHUNK_BYTES = 1024 * 1024
MAX_DISTINCT_PER_FACT = 300
MAX_VALUE_LENGTH = 80
PROGRESS_EVERY = 250_000
_ASCII = bytes(range(128))
_CP1252_UNDEFINED = frozenset({0x81, 0x8D, 0x8F, 0x90, 0x9D})
# Defaults, not this machine's configuration: the profiler needs no environment settings.
DEFAULT_MAX_UPLOAD_BYTES = Settings.model_fields["import_max_upload_bytes"].default
DEFAULT_MAX_ROWS = Settings.model_fields["import_max_rows"].default


class BoundedTally:
    """A counter that stops adding new keys at ``limit``; later new keys are counted as overflow."""

    def __init__(self, limit: int = MAX_DISTINCT_PER_FACT) -> None:
        self.counts: Counter[str] = Counter()
        self.limit = limit
        self.overflow = 0

    def add(self, key: str, count: int = 1) -> None:
        if key in self.counts or len(self.counts) < self.limit:
            self.counts[key] += count
        else:
            self.overflow += count

    def merge(self, other: "BoundedTally") -> None:
        for key, count in other.counts.items():
            self.add(key, count)
        self.overflow += other.overflow


@dataclass
class FileProfile:
    name: str
    size_bytes: int = 0
    sha256: str = ""
    crlf_lines: int = 0
    lf_lines: int = 0
    nul_bytes: int = 0
    non_ascii_bytes: Counter[int] = field(default_factory=Counter)
    header_issues: list[dict[str, Any]] = field(default_factory=list)
    records: int = 0
    blank_lines: int = 0
    accepted: int = 0
    rejected: int = 0
    issues: Counter[tuple[str, str]] = field(default_factory=Counter)
    first_row: dict[tuple[str, str], int] = field(default_factory=dict)
    stopped: dict[str, Any] | None = None
    facts: dict[str, BoundedTally] = field(default_factory=dict)

    @property
    def cp1252_undefined_bytes(self) -> int:
        return sum(count for byte, count in self.non_ascii_bytes.items() if byte in _CP1252_UNDEFINED)


def _printable(value: str) -> str:
    text = ascii(value)[1:-1]
    return text if len(text) <= MAX_VALUE_LENGTH else f"{text[:MAX_VALUE_LENGTH]}..."


def scan_bytes(path: Path, result: FileProfile) -> None:
    digest = hashlib.sha256()
    previous = b""
    with path.open("rb") as stream:
        while chunk := stream.read(CHUNK_BYTES):
            digest.update(chunk)
            result.size_bytes += len(chunk)
            result.lf_lines += chunk.count(b"\n")
            result.crlf_lines += chunk.count(b"\r\n") + (previous == b"\r" and chunk[:1] == b"\n")
            result.nul_bytes += chunk.count(0)
            high = chunk.translate(None, _ASCII)
            if high:
                result.non_ascii_bytes.update(high)
            previous = chunk[-1:]
    result.sha256 = digest.hexdigest()
    result.lf_lines -= result.crlf_lines  # LF-only line endings


def scan_records(path: Path, profile: DatasetProfile, result: FileProfile, progress: bool) -> None:
    with path.open("rb") as stream, open_csv(stream, profile) as reader:
        try:
            header = next(reader, None)
        except READ_ERRORS as error:
            result.stopped = read_issue(error, profile, row=1).as_dict()
            return
        if not header:
            result.header_issues.append({"rule": "header.missing", "row": 1})
            return
        header_issues = profile.check_header(header)
        if header_issues:
            result.header_issues = [issue.as_dict() for issue in header_issues]
            return

        positions = profile.column_positions(header)
        row = 1
        while True:
            try:
                record = next(reader, None)
            except READ_ERRORS as error:
                result.stopped = read_issue(error, profile, row=row + 1).as_dict()
                return
            if record is None:
                return
            row += 1
            if not record:
                result.blank_lines += 1
                continue
            result.records += 1
            if progress and result.records % PROGRESS_EVERY == 0:
                print(f"  {result.name}: {result.records:,} records", file=sys.stderr)

            issues = check_record(profile, header, positions, record, row)
            if issues:
                result.rejected += 1
                for issue in issues:
                    key = (issue.rule, issue.column or "")
                    result.issues[key] += 1
                    result.first_row.setdefault(key, row)
            else:
                result.accepted += 1
            if len(record) == len(header):
                values = {name: record[index] for name, index in positions.items()}
                for fact, value in profile.describe_record(values):
                    result.facts.setdefault(fact, BoundedTally()).add(_printable(value))


def profile_file(path: Path, profile: DatasetProfile, progress: bool = False) -> FileProfile:
    result = FileProfile(name=path.name)
    scan_bytes(path, result)
    if result.nul_bytes:
        result.stopped = {"rule": "file.not_text", "message": "file contains NUL bytes"}
        return result
    scan_records(path, profile, result, progress)
    return result


def collect_paths(arguments: list[str]) -> list[Path]:
    paths: list[Path] = []
    for argument in arguments:
        path = Path(argument)
        if path.is_dir():
            paths.extend(sorted(item for item in path.iterdir() if item.is_file() and item.suffix.lower() == ".csv"))
        elif path.is_file() and path.suffix.lower() == ".csv":
            paths.append(path)
        else:
            raise SystemExit(f"Not a .csv file or folder: {argument}")
    return paths


def _sorted_counts(tally: BoundedTally, fact: str) -> list[tuple[str, int]]:
    # Hours and dates read best in key order; everything else by frequency.
    if fact.startswith("timestamp hour") or fact.startswith("timestamp date"):
        return sorted(tally.counts.items())
    return tally.counts.most_common()


def summary(results: list[FileProfile]) -> dict[str, Any]:
    facts: dict[str, BoundedTally] = {}
    for result in results:
        for name, tally in result.facts.items():
            facts.setdefault(name, BoundedTally()).merge(tally)
    issues: Counter[tuple[str, str]] = Counter()
    non_ascii: Counter[int] = Counter()
    for result in results:
        issues.update(result.issues)
        non_ascii.update(result.non_ascii_bytes)
    return {
        "files": len(results),
        "bytes": sum(result.size_bytes for result in results),
        "records": sum(result.records for result in results),
        "accepted": sum(result.accepted for result in results),
        "rejected": sum(result.rejected for result in results),
        "headers_matching_profile": sum(not result.header_issues for result in results),
        "files_stopped_early": [result.name for result in results if result.stopped],
        "non_ascii_bytes": {f"0x{byte:02X}": count for byte, count in sorted(non_ascii.items())},
        "cp1252_undefined_bytes": sum(result.cp1252_undefined_bytes for result in results),
        "files_over_default_upload_bytes": sum(result.size_bytes > DEFAULT_MAX_UPLOAD_BYTES for result in results),
        "files_over_default_upload_rows": sum(result.records > DEFAULT_MAX_ROWS for result in results),
        "issues": {f"{rule} [{column}]" if column else rule: count for (rule, column), count in issues.most_common()},
        "facts": {name: dict(_sorted_counts(tally, name)) | ({"(other values)": tally.overflow} if tally.overflow else {})
                  for name, tally in sorted(facts.items())},
    }  # fmt: skip


def file_json(result: FileProfile) -> dict[str, Any]:
    return {
        "name": result.name,
        "size_bytes": result.size_bytes,
        "sha256": result.sha256,
        "line_endings": {"crlf": result.crlf_lines, "lf_only": result.lf_lines},
        "nul_bytes": result.nul_bytes,
        "non_ascii_bytes": {f"0x{byte:02X}": count for byte, count in sorted(result.non_ascii_bytes.items())},
        "header_issues": result.header_issues,
        "records": result.records,
        "blank_lines": result.blank_lines,
        "accepted": result.accepted,
        "rejected": result.rejected,
        "issues": [
            {"rule": rule, "column": column or None, "count": count, "first_row": result.first_row[(rule, column)]}
            for (rule, column), count in result.issues.most_common()
        ],
        "stopped": result.stopped,
        "facts": {name: dict(_sorted_counts(tally, name)) for name, tally in sorted(result.facts.items())},
    }


def print_report(profile: DatasetProfile, results: list[FileProfile]) -> None:
    print(f"NETRA dataset profiler · profile {profile.identifier} v{profile.version} · read-only, nothing uploaded or stored")
    for result in results:
        print(f"\n== {result.name}")
        print(f"size {result.size_bytes:,} bytes ({result.size_bytes / 1048576:.1f} MiB) · sha256 {result.sha256}")
        high = ", ".join(f"0x{byte:02X}×{count}" for byte, count in sorted(result.non_ascii_bytes.items())) or "none"
        print(f"line endings: CRLF {result.crlf_lines:,} · LF-only {result.lf_lines:,} · NUL bytes {result.nul_bytes} · non-ASCII bytes: {high}")
        if result.header_issues:
            print(f"header: does NOT match the profile ({len(result.header_issues)} issues; rows not checked)")
            for issue in result.header_issues[:10]:
                print(f"  {issue['rule']} column {issue.get('columnIndex') or '-'} {issue.get('column') or ''}")
        else:
            print("header: matches the profile")
        print(f"records {result.records:,} (blank lines {result.blank_lines:,}) · accepted {result.accepted:,} · rejected {result.rejected:,}")
        if result.stopped:
            print(f"STOPPED EARLY: {result.stopped['rule']} (row {result.stopped.get('row') or '-'}): {result.stopped['message']}")
        for (rule, column), count in result.issues.most_common():
            label = f"{rule} [{column}]" if column else rule
            print(f"  issue {label}: {count:,} (first at row {result.first_row[(rule, column)]:,})")
        for name, tally in sorted(result.facts.items()):
            values = " · ".join(f"{key}: {count:,}" for key, count in _sorted_counts(tally, name))
            print(f"  {name}: {values}" + (f" · (other values): {tally.overflow:,}" if tally.overflow else ""))

    totals = summary(results)
    print("\n== All files")
    print(f"files {totals['files']} · {totals['bytes']:,} bytes · records {totals['records']:,} · accepted {totals['accepted']:,} · rejected {totals['rejected']:,}")
    print(f"headers matching the profile: {totals['headers_matching_profile']} of {totals['files']}")
    print(f"files stopped early: {', '.join(totals['files_stopped_early']) or 'none'}")
    print(f"non-ASCII bytes: {totals['non_ascii_bytes'] or 'none'} · bytes undefined in cp1252: {totals['cp1252_undefined_bytes']}")
    print(f"over the default upload limits: {totals['files_over_default_upload_bytes']} files by size (> {DEFAULT_MAX_UPLOAD_BYTES:,} bytes), "
          f"{totals['files_over_default_upload_rows']} by rows (> {DEFAULT_MAX_ROWS:,})")  # fmt: skip
    for label, count in totals["issues"].items():
        print(f"  issue {label}: {count:,}")
    for name, counts in totals["facts"].items():
        print(f"  {name}: " + " · ".join(f"{key}: {count:,}" for key, count in counts.items()))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Profile dataset CSV files locally. Read-only; nothing is uploaded or stored.")
    parser.add_argument("paths", nargs="+", help=".csv files or folders of .csv files")
    parser.add_argument("--profile", required=True, choices=sorted(PROFILES))
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON instead of text")
    options = parser.parse_args(argv)

    profile = PROFILES[options.profile]
    paths = collect_paths(options.paths)
    results = [profile_file(path, profile, progress=not options.json) for path in paths]
    if options.json:
        print(json.dumps({"profile": profile.identifier, "version": profile.version,
                          "files": [file_json(result) for result in results], "summary": summary(results)}, indent=2))  # fmt: skip
    else:
        print_report(profile, results)
    return 0


if __name__ == "__main__":
    sys.exit(main())
