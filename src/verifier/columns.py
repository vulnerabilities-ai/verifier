"""Published column names (program-neutral, approved by Jon on November 5, 2026).

Anthropic's own field names stay exactly as they are in raw captures, cards and
preimages, because the committed bytes must never change. Anything published
under data/ uses the names below, and every published file except programs
starts with a `program` column.

Sources: docs/design-handoff/claude-design-R-B-02-data-contract.md and
docs/design-handoff/claude-design-R-E-02-data-contract-additions.md (R-E wins).
"""

from __future__ import annotations

# Anthropic-specific name in the R-B contract -> program-neutral published name.
RENAMES: dict[str, str] = {
    "ant_id": "finding_id",
    "hash_or_ant_id": "hash_or_finding_id",
    "claude_severity": "model_severity",
    "severity_claude": "severity_model",
    "anthropic_fix_rate_pct": "program_fix_rate_pct",
    "anthropic_revealed_count": "program_revealed_count",
}

# Names that must never appear as a published column.
FORBIDDEN_PUBLISHED = frozenset(RENAMES)

SNAPSHOT_COLUMNS: list[str] = [
    "program",
    "capture_utc",
    "source_sha256",
    "as_of_utc",
    "revision",
    "candidates",
    "reviewed_by_firms",
    "confirmed_valid",
    "true_positive_pct",
    "reported_after_triage",
    "reported_without_review",
    "reported_total",
    "acknowledged",
    "patched_lab_count",
    "advisories",
    "cves",
    "ghsas",
    "projects_reported",
    "ledger_entries",
    "revealed_entries",
    "severity_agreement_n",
    "severity_exact_agreement_pct",
    "severity_within_one_band_pct",
    "program_fix_rate_pct",
    "program_revealed_count",
    "label",
    "note",
]

# Where each snapshot column comes from in Anthropic's payload.json.
SNAPSHOT_SOURCES: dict[str, str] = {
    "as_of_utc": "as_of",
    "revision": "revision",
    "candidates": "headline.analyzed",
    "reviewed_by_firms": "headline.triaged",
    "confirmed_valid": "headline.verified",
    "true_positive_pct": "headline.tpr_pct",
    "reported_after_triage": "headline.confirmed_reported",
    "reported_without_review": "headline.reported_without_review",
    "reported_total": "headline.disclosed",
    "acknowledged": "headline.acknowledged",
    "patched_lab_count": "headline.fixed_in_response",
    "advisories": "headline.advisories",
    "cves": "headline.cves",
    "ghsas": "headline.ghsas",
    "projects_reported": "project_count",
    "ledger_entries": "len(ledger)",
    "revealed_entries": "count of ledger entries with reveal_tier == 'revealed'",
    "severity_agreement_n": "severity_matrix.n_vendor",
    "severity_exact_agreement_pct": "severity_matrix.exact_pct_vendor",
    "severity_within_one_band_pct": "severity_matrix.within_one_pct_vendor",
    "program_fix_rate_pct": "fix_rate_pct (anthropic_fix_rate_pct in R-B)",
    "program_revealed_count": "revealed.count (anthropic_revealed_count in R-B)",
}


def check_published(columns: list[str]) -> None:
    bad = [c for c in columns if c in FORBIDDEN_PUBLISHED]
    if bad:
        raise ValueError(f"Anthropic-specific names in published columns: {bad}")
    if not columns or columns[0] != "program":
        raise ValueError("The first published column must be 'program'.")
