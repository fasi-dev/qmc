"""Human-readable completeness warnings for a scan (pure functions; used by the summary API and the report).

A scan that timed out or skipped files must never look complete: these notes are shown on the dashboard and in
the report whenever results may be missing.
"""
from __future__ import annotations

from datetime import datetime, timedelta

REASONS = {
    "parse_error": "could not be parsed (e.g. Python 2 or syntax errors) and were not scanned",
    "skipped_minified": "look minified (a line over 10,000 characters) and were not scanned",
    "too_large": "were too large to scan",
    "read_error": "could not be read",
    "cert_parse_error": "contain a certificate block that could not be parsed",
    "too_complex": "are YAML/JSON documents too large or nested to inspect",
}


def scan_warnings(analysis: dict | None) -> list[str]:
    if not analysis:
        return []
    out: list[str] = []
    if analysis.get("scan_status") == "partial":
        out.append("The scan hit its time limit: results are PARTIAL and later files were not scanned.")
    counts: dict[str, int] = {}
    for item in analysis.get("files_skipped") or []:
        counts[item.get("reason", "other")] = counts.get(item.get("reason", "other"), 0) + 1
    for reason, n in sorted(counts.items()):
        what = REASONS.get(reason, f"were skipped ({reason})")
        out.append(f"{n} file(s) {what}. Findings in them are missing from this report.")
    return out


def is_expired(created_at_iso: str, now: datetime, retention_hours: int) -> bool:
    """True if a scan created at `created_at_iso` (ISO 8601 with offset) is older than the retention window.
    Unparsable timestamps are treated as expired so they cannot accumulate forever."""
    if retention_hours <= 0:
        return False
    try:
        created = datetime.fromisoformat(created_at_iso)
    except (TypeError, ValueError):
        return True
    if created.tzinfo is None:
        created = created.replace(tzinfo=now.tzinfo)
    return now - created > timedelta(hours=retention_hours)
