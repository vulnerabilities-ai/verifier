"""Column definitions for every published file (written to data/schema/).

Column NAMES are program-neutral. The "source_field" values keep the
program's own field names on purpose: they are attribution (where a value
comes from), not published column names.
"""

from __future__ import annotations

from ..columns import SNAPSHOT_COLUMNS, SNAPSHOT_SOURCES

LR = "Lab-reported"
IV = "Independently verified"
GAPS_LABEL = "Independently verified (our count from the program's published files)"

# (name, type, meaning, source_field, label)
_PROGRAM = ("program", "string", "The program's ID. anthropic-cvd for every row today.", None, None)

SNAPSHOT_META = {
    "program": _PROGRAM[1:],
    "capture_utc": ("time", "When we captured the dashboard page for this snapshot (first capture containing it). "
                    "For backfill rows, when we copied the program's archived snapshot. "
                    "For Jon's manual capture of 2026-10-30, the end-of-day bound 2026-10-30T23:59:59Z.", None, IV),
    "source_sha256": ("string", "SHA-256 of the captured dashboard page (index.html for backfill rows).", None, IV),
    "as_of_utc": ("time", "The 'last updated' time the program shows, to the second.", "as_of", LR),
    "revision": ("integer", "The program's revision number.", "revision", LR),
    "candidates": ("integer", "Findings the program's models flagged before triage.", "headline.analyzed", LR),
    "reviewed_by_firms": ("integer", "Findings reviewed by external firms.", "headline.triaged", LR),
    "confirmed_valid": ("integer", "Findings the firms confirmed valid.", "headline.verified", LR),
    "true_positive_pct": ("number", "The program's true-positive percentage.", "headline.tpr_pct", LR),
    "reported_after_triage": ("integer", "Reported to maintainers after firm review.", "headline.confirmed_reported", LR),
    "reported_without_review": ("integer", "Reported to maintainers without firm review.", "headline.reported_without_review", LR),
    "reported_total": ("integer", "Total reported to maintainers ('disclosed').", "headline.disclosed", LR),
    "acknowledged": ("integer", "Acknowledged by a maintainer.", "headline.acknowledged", LR),
    "patched_lab_count": ("integer", "Patched, by the program's own 'to our knowledge' count.", "headline.fixed_in_response", LR),
    "advisories": ("integer", "Identifiers assigned, as the program counts them.", "headline.advisories", LR),
    "cves": ("integer", "CVE records, as the program counts them.", "headline.cves", LR),
    "ghsas": ("integer", "GitHub Security Advisories, as the program counts them.", "headline.ghsas", LR),
    "projects_reported": ("integer", "Projects with reported findings.", "project_count", LR),
    "ledger_entries": ("integer", "Commitments in the ledger (our count of payload.json ledger entries).", "len(ledger)", IV),
    "revealed_entries": ("integer", "Ledger entries in the revealed tier (our count).", "ledger[].reveal_tier", IV),
    "severity_agreement_n": ("integer", "Number of findings in the program's model-versus-firm severity comparison.", "severity_matrix.n_vendor", LR),
    "severity_exact_agreement_pct": ("number", "Exact severity agreement, model versus firm, as the program reports it.", "severity_matrix.exact_pct_vendor", LR),
    "severity_within_one_band_pct": ("number", "Agreement within one severity band, as the program reports it.", "severity_matrix.within_one_pct_vendor", LR),
    "program_fix_rate_pct": ("number", "The 'fix rate' in the program's data file: fixed findings as a share of REVEALED findings "
                             "(program_revealed_count), not of all reported findings. Never show it without that denominator.",
                             "fix_rate_pct (anthropic_fix_rate_pct in R-B)", LR),
    "program_revealed_count": ("integer", "The revealed count the fix rate is based on.", "revealed.count (anthropic_revealed_count in R-B)", LR),
    "source_kind": ("string", "our_capture (our own daily capture) or program_archive_backfill (a copy of the program's own "
                    "archived snapshot; never first-seen evidence).", None, None),
    "program_snapshot_label": ("string", "For backfill rows, the program's own snapshot label, for example 2026-08-26-1155. Empty otherwise.", "snapshots/<label>", LR),
    "first_seen_by_us": ("time", "For our_capture rows, when our first capture containing this snapshot fetched its data file. "
                         "Empty for backfill rows.", None, IV),
    "label": ("string", "Always Lab-reported (the counts are the program's).", None, None),
    "note": ("string", "Free text, for example the manual-capture note or the Aug 26, 2026 change in date conventions.", None, None),
}

COMMITMENT_META = [
    _PROGRAM,
    ("hash", "string", "The SHA-3-512 commitment hash.", "hash", IV),
    ("hash_short", "string", "First 12 characters of the hash.", "hash", None),
    ("committed_at", "date", "The commitment date, from the program's ledger.", "committed_at", LR),
    ("first_seen_by_us", "time", "Our earliest daily capture containing the hash (its ledger.json fetch time). For Jon's "
     "manual capture, the end-of-day bound 2026-10-30T23:59:59Z. Backfill copies never count.", None, IV),
    ("first_seen_basis", "string", "How to read first_seen_by_us, including the earliest independent evidence available when the "
     "data was built: the GitHub commit time of that capture, and the Internet Archive receipt for ledger.json when one exists.", None, None),
    ("tier", "string", "discovered, sent, acknowledged_by_maintainer or revealed.", "reveal_tier", LR),
    ("status", "string", "disclosed, fixed, withdrawn, merged or empty.", "status", LR),
    ("withdrawn", "boolean", "The program's withdrawn flag (it can differ from status; both are published as found).", "withdrawn", LR),
    ("withdrawn_reason", "string", "The program's withdrawal reason, as found (also set on merged entries).", "withdrawn_reason", LR),
    ("merged_into", "string", "The revealed finding a merged commitment was folded into, when the program names one. "
     "Withheld unless it names a revealed finding.", "merged_into", LR),
    ("model_severity", "string", "The program's model's own severity rating.", "claude_severity", LR),
    ("revealed", "boolean", "True once the program has revealed the finding.", "revealed", LR),
    ("finding_id", "string", "The finding ID (revealed rows only).", "ant_id", LR),
    ("project", "string", "Project (revealed rows only).", "project", LR),
    ("bug_class", "string", "Bug class (revealed rows only).", "bug_class", LR),
    ("cve_ids", "list", "CVE IDs (revealed rows only).", "cve_ids", LR),
    ("ghsa_ids", "list", "GHSA IDs (revealed rows only).", "ghsa_ids", LR),
    ("fixed_in_response", "boolean", "The program's 'fixed in response' flag (revealed rows only).", "is_fixed_in_response", LR),
    ("patched_at", "date", "Patch date from the ledger (revealed rows only).", "patched_at", LR),
    ("revealed_at", "date", "Reveal date from the ledger (revealed rows only).", "revealed_at", LR),
    ("card_url", "string", "The finding card's address (revealed rows only).", None, None),
    ("hash_check", "string", "R2 result: match, mismatch, unavailable (no card or preimage could be read), not_checked "
     "(revealed, no card yet) or not_applicable (not revealed).", None, IV),
    ("fix_merged", "string", "not_checked (revealed) or not_applicable. Filled in phase 3.", None, IV),
]

EVENT_META = [
    _PROGRAM,
    ("capture_utc", "time", "When we first captured the newer snapshot (its ledger.json fetch time).", None, IV),
    ("event_type", "string", "new_commitment, removed_commitment, revealed, withdrawn, merged, status_change, "
     "headline_change or field_change.", None, IV),
    ("hash_or_finding_id", "string", "The finding ID when revealed, otherwise the hash. Empty for headline_change.", "ant_id / hash", None),
    ("field", "string", "The published name of the field that changed (for example status, tier, model_severity, "
     "or a snapshots column for headline_change). Empty for new_commitment and removed_commitment.", None, None),
    ("old_value", "string", "Value in the earlier snapshot (empty for none).", None, LR),
    ("new_value", "string", "Value in the newer snapshot (empty for none).", None, LR),
]

GAP_META = [
    _PROGRAM,
    ("capture_utc", "time", "As in snapshots.", None, None),
    ("revision", "integer", "The program's revision number.", "revision", LR),
    ("source_kind", "string", "As in snapshots.", None, None),
    ("program_snapshot_label", "string", "As in snapshots.", "snapshots/<label>", LR),
    ("patched_claimed", "integer", "The program's patched figure.", "headline.fixed_in_response", GAPS_LABEL),
    ("patched_itemized", "integer", "Ledger entries flagged fixed in response.", "ledger[].is_fixed_in_response", GAPS_LABEL),
    ("cves_claimed", "integer", "CVE records claimed.", "headline.cves", GAPS_LABEL),
    ("cves_itemized", "integer", "Unique CVE IDs on ledger entries (cve_ids and corrected_cve_ids).", "ledger[].cve_ids", GAPS_LABEL),
    ("ghsas_claimed", "integer", "GHSAs claimed.", "headline.ghsas", GAPS_LABEL),
    ("ghsas_itemized", "integer", "Unique GHSA IDs on ledger entries (ghsa_ids and corrected_ghsa_ids).", "ledger[].ghsa_ids", GAPS_LABEL),
    ("reported_claimed", "integer", "Reported to maintainers ('disclosed').", "headline.disclosed", GAPS_LABEL),
    ("reported_flagged_in_ledger", "integer", "Ledger entries flagged disclosed.", "ledger[].was_disclosed", GAPS_LABEL),
    ("revealed_itemized", "integer", "Ledger entries in the revealed tier.", "ledger[].reveal_tier", GAPS_LABEL),
    ("revealed_payload_count", "integer", "The revealed count in the program's data file.", "revealed.count", GAPS_LABEL),
    ("withdrawn_flag", "integer", "Ledger entries with the withdrawn flag (empty if the snapshot has no such field).", "ledger[].withdrawn", GAPS_LABEL),
    ("withdrawn_status", "integer", "Ledger entries with status withdrawn.", "ledger[].status", GAPS_LABEL),
    ("merged_status", "integer", "Ledger entries with status merged.", "ledger[].status", GAPS_LABEL),
    ("merged_with_target", "integer", "Merged entries that name the finding they were merged into.", "ledger[].merged_into", GAPS_LABEL),
    ("label", "string", f"Always '{GAPS_LABEL}'.", None, None),
]

WITHDRAWAL_META = [
    _PROGRAM,
    ("capture_utc", "time", "As in snapshots.", None, None),
    ("revision", "integer", "The program's revision number.", "revision", LR),
    ("source_kind", "string", "As in snapshots.", None, None),
    ("program_snapshot_label", "string", "As in snapshots.", "snapshots/<label>", LR),
    ("view", "string", "by_flag (entries with the withdrawn flag), by_status (entries with status withdrawn) or "
     "by_reason_all_entries (every entry with a withdrawal reason, including merged entries). Three views of the same "
     "ledger; none is an error.", None, None),
    ("reason", "string", "The program's withdrawal reason. Empty when the entry has none.", "withdrawn_reason", LR),
    ("count", "integer", "Number of ledger entries.", None, GAPS_LABEL),
]


def _cols(meta: list[tuple]) -> list[dict]:
    return [{"name": n, "type": t, "meaning": m, "source_field": s, "label": l} for n, t, m, s, l in meta]


def snapshot_meta() -> list[tuple]:
    out = []
    for c in SNAPSHOT_COLUMNS:
        t, m, s, l = SNAPSHOT_META[c]
        out.append((c, t, m, s if s is not None else SNAPSHOT_SOURCES.get(c), l))
    return out


FILES = {
    "snapshots": ("One row per snapshot: each distinct data file in our own daily captures, plus each "
                  "backfilled copy of the program's own archive.", snapshot_meta),
    "commitments": ("One row per commitment hash, newest commitment first.", lambda: COMMITMENT_META),
    "events": ("One row per change between consecutive snapshots in our own daily captures.", lambda: EVENT_META),
    "gaps": ("One row per snapshot: claimed against itemized counts, with no commentary.", lambda: GAP_META),
    "withdrawals": ("One row per snapshot, view and reason: three views of withdrawals, none treated as an error.",
                    lambda: WITHDRAWAL_META),
}


def columns(file: str) -> list[str]:
    return [m[0] for m in FILES[file][1]()]


def schema_doc(file: str) -> dict:
    desc, meta = FILES[file]
    return {"schema_version": 1, "file": file, "formats": ["csv", "json"], "rows": desc,
            "columns": _cols(meta())}
