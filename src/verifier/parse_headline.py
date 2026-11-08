"""Headline parser: Anthropic's payload.json -> one published snapshot row.

The row uses the program-neutral published column names (see columns.py).
If a field we rely on is missing, this fails with a clear message instead of
guessing, because that means Anthropic changed its format.
"""

from __future__ import annotations

import json
import re

from . import config
from .columns import SNAPSHOT_COLUMNS, check_published


class FormatChanged(Exception):
    pass


def _get(obj: dict, dotted: str):
    cur = obj
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            raise FormatChanged(f"payload.json has no field '{dotted}'. "
                                "Anthropic's format may have changed.")
        cur = cur[part]
    return cur


def _utc_seconds(ts: str | None) -> str | None:
    """'2026-10-02T19:47:20.314425Z' -> '2026-10-02T19:47:20Z' (contract format)."""
    if ts is None:
        return None
    m = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?(Z|\+00:00)$", ts)
    if not m:
        raise FormatChanged(f"Unexpected time format in payload.json: {ts!r}")
    return m.group(1) + "Z"


def parse_headline(payload: bytes | dict, *, capture_utc: str | None,
                   source_sha256: str | None, note: str | None = None) -> dict:
    p = json.loads(payload) if isinstance(payload, (bytes, str)) else payload
    ledger = _get(p, "ledger")
    if not isinstance(ledger, list):
        raise FormatChanged("payload.json 'ledger' is not a list.")
    row = {
        "program": config.PROGRAM,
        "capture_utc": capture_utc,
        "source_sha256": source_sha256,
        "as_of_utc": _utc_seconds(_get(p, "as_of")),
        "revision": _get(p, "revision"),
        "candidates": _get(p, "headline.analyzed"),
        "reviewed_by_firms": _get(p, "headline.triaged"),
        "confirmed_valid": _get(p, "headline.verified"),
        "true_positive_pct": _get(p, "headline.tpr_pct"),
        "reported_after_triage": _get(p, "headline.confirmed_reported"),
        "reported_without_review": _get(p, "headline.reported_without_review"),
        "reported_total": _get(p, "headline.disclosed"),
        "acknowledged": _get(p, "headline.acknowledged"),
        "patched_lab_count": _get(p, "headline.fixed_in_response"),
        "advisories": _get(p, "headline.advisories"),
        "cves": _get(p, "headline.cves"),
        "ghsas": _get(p, "headline.ghsas"),
        "projects_reported": _get(p, "project_count"),
        "ledger_entries": len(ledger),
        "revealed_entries": sum(1 for e in ledger if e.get("reveal_tier") == "revealed"),
        "severity_agreement_n": _get(p, "severity_matrix.n_vendor"),
        "severity_exact_agreement_pct": _get(p, "severity_matrix.exact_pct_vendor"),
        "severity_within_one_band_pct": _get(p, "severity_matrix.within_one_pct_vendor"),
        "program_fix_rate_pct": _get(p, "fix_rate_pct"),
        "program_revealed_count": _get(p, "revealed.count"),
        "label": "Lab-reported",
        "note": note,
    }
    assert list(row) == SNAPSHOT_COLUMNS
    check_published(list(row))
    return row


def tier_counts(payload: bytes | dict) -> dict[str, int]:
    """Ledger entries per reveal tier, counted from the ledger itself."""
    p = json.loads(payload) if isinstance(payload, (bytes, str)) else payload
    counts: dict[str, int] = {}
    for e in _get(p, "ledger"):
        t = e.get("reveal_tier")
        counts[t] = counts.get(t, 0) + 1
    return counts
