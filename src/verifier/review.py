"""Plain tally for the weekly review pull request (phase 2 version).

Counts only, in neutral words. The full report with the wording guard is
phase 3. Nothing here judges, explains or infers anything.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path


def _rows(root: Path, name: str) -> list[dict]:
    return json.loads((root / "data" / f"{name}.json").read_text(encoding="utf-8"))["rows"]


def review_summary(root: Path, cards_fetch: dict | None = None) -> str:
    root = Path(root)
    snaps = _rows(root, "snapshots")
    gaps = _rows(root, "gaps")
    events = _rows(root, "events")
    commits = _rows(root, "commitments")
    checks = Counter(r["hash_check"] for r in commits if r["tier"] == "revealed")
    ours = [s for s in snaps if s["source_kind"] == "our_capture"]
    latest = ours[-1] if ours else None
    lines = ["## Weekly review (phase 2 tally)", "",
             "This pull request updates `data/` and `cards/` from the archive. Counts only; "
             "nothing in it is a judgement. Merge it if the numbers look right; write \"hold\" "
             "in a comment otherwise.", ""]
    if latest:
        lines += [f"- Latest snapshot in our captures: revision {latest['revision']}, as of "
                  f"{latest['as_of_utc']}, first captured {latest['first_seen_by_us']}.",
                  f"- Snapshots in the table: {len(snaps)} ({len(ours)} from our captures, "
                  f"{len(snaps) - len(ours)} copied from the program's own archive)."]
    lines += ["", "### Finding cards (rule R2)", "",
              f"- Revealed findings: {sum(checks.values())}",
              f"- Hash check match: {checks.get('match', 0)}",
              f"- Hash check mismatch: {checks.get('mismatch', 0)}",
              f"- Card or preimage unavailable: {checks.get('unavailable', 0)}",
              f"- Not checked yet: {checks.get('not_checked', 0)}"]
    if cards_fetch:
        lines += [f"- This run fetched {cards_fetch.get('fetched', 0)} card(s) "
                  f"({cards_fetch.get('new_copies', 0)} new copies, {cards_fetch.get('unchanged', 0)} unchanged); "
                  f"could not fetch: {', '.join(cards_fetch.get('unavailable', [])) or 'none'}."]
    if events:
        last = max(e["capture_utc"] for e in events)
        by_type = Counter(e["event_type"] for e in events if e["capture_utc"] == last)
        lines += ["", f"### Changes first captured at {last}", ""]
        lines += [f"- {t}: {n}" for t, n in sorted(by_type.items())]
    if gaps:
        g = [x for x in gaps if x["source_kind"] == "our_capture"][-1]
        lines += ["", f"### Claimed and itemized counts (revision {g['revision']})", "",
                  "| Measure | Claimed | Itemized |", "| --- | --- | --- |",
                  f"| Patched | {g['patched_claimed']} | {g['patched_itemized']} |",
                  f"| CVEs | {g['cves_claimed']} | {g['cves_itemized']} |",
                  f"| GHSAs | {g['ghsas_claimed']} | {g['ghsas_itemized']} |",
                  f"| Reported | {g['reported_claimed']} | {g['reported_flagged_in_ledger']} (flagged in ledger) |",
                  f"| Revealed | {g['revealed_payload_count']} (data file) | {g['revealed_itemized']} |",
                  f"| Withdrawn | {g['withdrawn_flag']} (flag) | {g['withdrawn_status']} (status) |",
                  f"| Merged | {g['merged_status']} (status) | {g['merged_with_target']} (name a target) |"]
    return "\n".join(lines) + "\n"
