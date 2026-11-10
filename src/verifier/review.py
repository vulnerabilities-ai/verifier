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


def unavailable_cards(root: Path) -> list[tuple[str, str]]:
    """(finding ID, plain reason) for every card whose R2 result is unavailable."""
    out = []
    for v in sorted((Path(root) / "cards").glob("*/verification.json")):
        rec = json.loads(v.read_text(encoding="utf-8"))
        r2 = rec.get("r2") or {}
        if r2.get("outcome") == "unavailable":
            reason = (r2.get("unavailable_reason") or {}).get("text") or "no reason was recorded"
            out.append((rec.get("finding_id", v.parent.name), reason))
    return out


CHECK_NAMES = {"cards": "Card fetch", "lookups": "Public-record lookups", "build": "Rebuild of data/",
               "report": "Report and wording guard", "tests": "Tests", "audit": "Archive audit"}


def review_pr(root: Path, outcomes: dict[str, str], date: str,
              cards_fetch: dict | None = None, report_file: str | None = None,
              sample: bool = False) -> tuple[str, str]:
    """Title and description for the weekly review pull request.

    outcomes: check name -> "success" or anything else (failure, skipped, cancelled).
    When any check did not succeed, the title says "checks failed" and the
    description starts with what failed. If the rebuild failed, only the raw
    card fetch is in the pull request (data/ is left as it is on main)."""
    failed = [k for k in CHECK_NAMES if outcomes.get(k, "success") != "success"]
    title = (f"Sample lookups (5 findings) {date}" if sample else f"Weekly review {date}") + (
        " (checks failed)" if failed else "")
    head = []
    if failed:
        head = ["## Checks failed", "",
                "These checks did not pass in this run: "
                + ", ".join(f"{CHECK_NAMES[k]} ({outcomes.get(k)})" for k in failed) + ".", "",
                "The raw finding cards fetched in this run are committed here so they are not lost.",
                ("The rebuild failed, so `data/` and the cards' `verification.json` files are left as they are on "
                 "main; only the raw card files and their manifests are included."
                 if outcomes.get("build", "success") != "success" else
                 "The rebuild ran, so `data/` is included, but the checks above failed."),
                "", "**Do not merge until the failure is understood.** Write \"hold\" in a comment and ask Claude Code.",
                "", "---", ""]
    rpath = Path(root) / report_file if report_file else None
    if rpath and rpath.exists() and outcomes.get("report", "success") == "success":
        from .report import top_section
        body = top_section(rpath.read_text(encoding="utf-8"), report_file)
        unav = unavailable_cards(root)
        if unav:
            body += "\nCards whose hash could not be checked, and why:\n\n" + "".join(f"- {f}: {w}\n" for f, w in unav)
    elif outcomes.get("build", "success") == "success" and (Path(root) / "data" / "snapshots.json").exists():
        body = review_summary(root, cards_fetch)
    else:
        body = "## Weekly review (phase 2 tally)\n\nNo rebuilt tables in this run.\n"
        if cards_fetch:
            body += (f"\n- Cards fetched: {cards_fetch.get('fetched', 0)} "
                     f"({cards_fetch.get('new_copies', 0)} new copies, {cards_fetch.get('unchanged', 0)} unchanged).\n")
            for fid in cards_fetch.get("unavailable", []):
                why = (cards_fetch.get("unavailable_reasons") or {}).get(fid, "no reason was recorded")
                body += f"- {fid}: {why}\n"
    return title, "\n".join(head) + body


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
              f"- Preimage withheld by the program: {checks.get('preimage_withheld', 0)}",
              f"- Card or preimage unavailable: {checks.get('unavailable', 0)}",
              f"- Not checked yet: {checks.get('not_checked', 0)}"]
    unavailable = unavailable_cards(root)
    if unavailable:
        lines += ["", "Cards whose hash could not be checked, and why:", ""]
        lines += [f"- {fid}: {why}" for fid, why in unavailable]
    if cards_fetch:
        lines += ["", f"- This run fetched {cards_fetch.get('fetched', 0)} card(s) "
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
