"""Phase 3 tables: verification (R2-R5, R7 per finding), severity (R7 monthly
matrix), summary (one row) and programs. Deterministic; no network."""

from __future__ import annotations

import csv
import io
import json
import re
from collections import Counter
from datetime import date
from pathlib import Path

from .. import config
from ..records_read import RecordReader
from .sources import MANUAL_DAY

PROGRAM = config.PROGRAM
FINAL_HASH = {"match", "mismatch", "preimage_withheld"}
LABELS = {
    "label_hash_check": "Independently verified",
    "label_ids_exist": "Independently verified",
    "label_fix_merged": "Independently verified",
    "label_dates": "Lab-reported",
    "label_intervals": "Lab-reported dates, merge date independently verified",
    "label_severity": "Each source's own",
}
POLICY = {"days_report_to_patch": 90, "days_patch_to_reveal": 45, "days_report_to_reveal": 135}
# severity file source -> verification column (each source and CVSS version kept apart)
SEVERITY_COLUMNS = {"model": "severity_model", "firm": "severity_firm", "maintainer": "severity_maintainer",
                    "github": "severity_github", "nvd_v31": "severity_nvd_v31", "nvd_v40": "severity_nvd_v40"}
SEVERITY_SOURCES = tuple(SEVERITY_COLUMNS)
CVSS_COLUMNS = ("cvss_github_v31_score", "cvss_github_v40_score", "cvss_nvd_v31_score", "cvss_nvd_v40_score")
_CVE = re.compile(r"CVE-\d{4}-\d{4,}")
_GHSA = re.compile(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}")


def _d(s: str | None) -> date | None:
    if not s or not isinstance(s, str):
        return None
    try:
        return date.fromisoformat(s[:10])
    except ValueError:
        return None


def days(a: str | None, b: str | None) -> int | None:
    x, y = _d(a), _d(b)
    return (y - x).days if x and y else None


def _worst(statuses: list[str]) -> str:
    for s in ("rate_limited", "lookup_unreadable", "network_error", "not_checked"):
        if s in statuses:
            return s
    return "ok"


def finding_inputs(root: Path, revealed_entries: dict[str, dict]) -> dict[str, dict]:
    """finding ID -> what the lookups need (IDs from ledger and card, the card's fix links)."""
    out = {}
    for fid, e in revealed_entries.items():
        v = _verification(root, fid)
        facts = (v or {}).get("card_facts") or {}
        links = facts.get("links") or {}
        text = " ".join(links.get("nvd", []) + links.get("ghsa", []))
        out[fid] = {
            "cve_ids": sorted(set((e.get("cve_ids") or []) + (e.get("corrected_cve_ids") or []) + _CVE.findall(text))),
            "ghsa_ids": sorted(set((e.get("ghsa_ids") or []) + (e.get("corrected_ghsa_ids") or []) + _GHSA.findall(text))),
            "fix_links": links.get("fix", []), "advisory_links": links.get("advisory", []),
        }
    return out


def _verification(root: Path, fid: str) -> dict | None:
    p = Path(root) / "cards" / fid / "verification.json"
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else None


def verification_rows(root: Path, revealed_entries: dict[str, dict], checks: dict[str, dict],
                      reader: RecordReader) -> list[dict]:
    inputs = finding_inputs(root, revealed_entries)
    rows = []
    for fid in sorted(revealed_entries):
        e = revealed_entries[fid]
        v = _verification(root, fid) or {}
        facts = v.get("card_facts") or {}
        dates = facts.get("dates") or {}
        sev = facts.get("severities") or {}
        r2 = v.get("r2") or {}
        hash_check = (checks.get(fid) or {}).get("outcome", "not_checked")
        inp = inputs[fid]
        lookup_statuses, notes = [], list(v.get("notes") or [])

        # R3: identifiers
        detail, gh_adv, nvd_rec = {}, [], []
        for g in inp["ghsa_ids"]:
            a = reader.github_advisory(g)
            detail[g] = {"github": a.get("status") if a.get("status") != "ok" else "exists"}
            lookup_statuses.append(a["status"] if a["status"] in ("rate_limited", "lookup_unreadable",
                                                                  "network_error", "not_checked") else "ok")
            if a.get("status") == "ok":
                gh_adv.append(a)
            elif a.get("reason") and a["status"] != "not_found":
                notes.append(f"Lookup of {g} in the GitHub Advisory Database: {a['reason']}.")
        for c in inp["cve_ids"]:
            a = reader.github_advisories_for_cve(c)
            n = reader.nvd_cve(c)
            detail[c] = {"github": "exists" if a.get("status") == "ok" else a.get("status"),
                         "nvd": "exists" if n.get("status") == "ok" else n.get("status")}
            for x, src in ((a, "GitHub Advisory Database"), (n, "NVD")):
                if x["status"] in ("rate_limited", "lookup_unreadable", "network_error", "not_checked"):
                    lookup_statuses.append(x["status"])
                    if x.get("reason") and x["status"] != "not_checked":
                        notes.append(f"Lookup of {c} in {src}: {x['reason']}.")
                else:
                    lookup_statuses.append("ok")
            if a.get("status") == "ok":
                gh_adv.extend(a.get("advisories", []))
            if n.get("status") == "ok":
                nvd_rec.append(n)
        ids_exist = _ids_exist(detail)

        # R4: fix merged
        fix = reader.fix_merged(inp["fix_links"], inp["advisory_links"])
        if fix["fix_merged"] in ("rate_limited", "lookup_unreadable", "network_error"):
            lookup_statuses.append(fix["fix_merged"])
            notes.append(f"Fix lookup: {fix.get('reason')}.")
        elif fix.get("reason") == "never looked up" or (fix["fix_merged"] == "not_checked"
                                                         and "never looked up" in str(fix.get("reason"))):
            lookup_statuses.append("not_checked")
        if fix.get("note"):
            notes.append(f"Fix: {fix['note'].strip()}.")
        if fix.get("address"):
            notes.append(f"Fix address (not on GitHub, not checked): {fix['address']}.")

        # Differences recorded without judgement
        gh_first = sorted(gh_adv, key=lambda a: a.get("published") or "")[0] if gh_adv else None
        if gh_first and gh_first.get("source_code_location") and e.get("project"):
            loc = gh_first["source_code_location"].lower().rstrip("/")
            if not loc.endswith("/" + e["project"].lower()):
                notes.append(f"The ledger names project '{e['project']}'. The GitHub advisory names source "
                             f"'{gh_first['source_code_location']}'.")
        report, patch, reveal = dates.get("report_date"), dates.get("patch_released_date"), dates.get("reveal_date")
        merged_at = fix.get("fix_merged_at")
        status = _worst(lookup_statuses)
        if status == "ok" and not inp["cve_ids"] and not inp["ghsa_ids"]:
            status = "no_identifiers"  # nothing to look up: not the same as a successful lookup
        nvd_first = sorted(nvd_rec, key=lambda n: n.get("published") or "")[0] if nvd_rec else None
        row = {
            "program": PROGRAM, "finding_id": fid, "hash": e.get("hash"), "project": e.get("project"),
            "bug_class": e.get("bug_class"), "hash_check": hash_check,
            "hash_checked_at": v.get("hash_checked_at"),
            "withheld_statement": r2.get("withheld_statement"),
            "cve_ids": inp["cve_ids"], "ghsa_ids": inp["ghsa_ids"], "ids_exist": ids_exist,
            "ids_exist_detail": detail,
            "advisory_published": (gh_first or {}).get("published", "")[:10] or None,
            "nvd_published": (nvd_first or {}).get("published", "")[:10] or None,
            "fix_merged": fix["fix_merged"], "fix_merged_at": merged_at, "fix_url": fix.get("fix_url"),
            "fix_merge_base": fix.get("merge_base"),
            "report_date": report, "patch_released_date": patch, "reveal_date": reveal,
            "discovered_or_logged_date": dates.get("discovered_or_logged_date"),
            "days_report_to_patch": days(report, patch), "days_patch_to_reveal": days(patch, reveal),
            "days_report_to_reveal": days(report, reveal), "days_report_to_merge": days(report, merged_at),
            "severity_model": sev.get("model"), "severity_firm": sev.get("firm"),
            "severity_maintainer": sev.get("maintainer"),
            "severity_github": (gh_first or {}).get("severity"),
            # CVSS by version and source: never merged, never chosen between; absent means empty.
            "cvss_github_v31_score": (gh_first or {}).get("cvss_v31_score"),
            "cvss_github_v40_score": (gh_first or {}).get("cvss_v40_score"),
            "cvss_github_entries": (gh_first or {}).get("cvss_entries") or [],
            "cvss_nvd_v31_score": (nvd_first or {}).get("cvss_v31_score"),
            "severity_nvd_v31": (nvd_first or {}).get("severity_v31"),
            "cvss_nvd_v31_source": (nvd_first or {}).get("cvss_v31_source"),
            "cvss_nvd_v40_score": (nvd_first or {}).get("cvss_v40_score"),
            "severity_nvd_v40": (nvd_first or {}).get("severity_v40"),
            "cvss_nvd_v40_source": (nvd_first or {}).get("cvss_v40_source"),
            "cvss_nvd_entries": (nvd_first or {}).get("cvss_entries") or [],
            "cwe_github": sorted({c for a in gh_adv for c in a.get("cwes", [])}),
            "cwe_nvd": sorted({c for n in nvd_rec for c in n.get("cwes", [])}),
            "advisory_review_status": (gh_first or {}).get("review_status"),
            "advisory_packages": sorted({p for a in gh_adv for p in a.get("packages", [])}),
            "lookup_status": status,
            "checked": "yes" if fully_checked(hash_check, ids_exist, fix["fix_merged"]) else "no",
            "method": "automated: R2 finding card; R3 GitHub Advisory Database and NVD; R4 GitHub",
            **LABELS,
            "notes": " ".join(notes) or None,
        }
        rows.append(row)
    return rows


# "Fully checked" (Jon, 2026-11-10): the hash check is conclusive, the identifiers are
# confirmed or there are none, AND the fix's merge status was actually determined.
IDS_CONCLUSIVE = frozenset({"verified", "not_applicable"})
FIX_CONCLUSIVE = frozenset({"yes", "no"})


def fully_checked(hash_check: str, ids_exist: str, fix_merged: str) -> bool:
    return hash_check in FINAL_HASH and ids_exist in IDS_CONCLUSIVE and fix_merged in FIX_CONCLUSIVE


def _ids_exist(detail: dict) -> str:
    if not detail:
        return "not_applicable"
    states = []
    for d in detail.values():
        vals = list(d.values())
        if "exists" in vals:
            states.append("exists")
        elif vals and all(x == "not_found" for x in vals):
            states.append("not_found")
        else:
            states.append(_worst([x for x in vals if x not in ("exists", "not_found")]))
    if "not_found" in states:
        return "not_found"
    pending = [s for s in states if s != "exists"]
    return _worst(pending) if pending else "verified"


def severity_rows(ver: list[dict]) -> list[dict]:
    c = Counter()
    for r in ver:
        month = (r.get("reveal_date") or "")[:7] or None
        for src in SEVERITY_SOURCES:
            val = r.get(SEVERITY_COLUMNS[src])
            c[(month, src, (val.lower() if isinstance(val, str) and val else "not_available"))] += 1
    rows = [{"program": PROGRAM, "month": m, "source": s, "severity": sev, "count": n}
            for (m, s, sev), n in c.items()]
    rows.sort(key=lambda r: (r["month"] or "", SEVERITY_SOURCES.index(r["source"]), r["severity"]))
    return rows


def _pct(n, d):
    return round(100.0 * n / d, 2) if d else None


def summary_row(snapshots: list[dict], commitments: list[dict], gaps: list[dict], withdrawals: list[dict],
                ver: list[dict], policy_source: str | None) -> dict:
    ours = [s for s in snapshots if s["source_kind"] == "our_capture"]
    s = ours[-1]
    g = next(x for x in gaps if x["capture_utc"] == s["capture_utc"] and x["source_kind"] == "our_capture")

    def wview(view):
        return {(r["reason"] or "none"): r["count"] for r in withdrawals
                if r["capture_utc"] == s["capture_utc"] and r["source_kind"] == "our_capture" and r["view"] == view}
    hc = Counter(r["hash_check"] for r in commitments if r["tier"] == "revealed")
    tiers = Counter(r["tier"] for r in commitments)
    committed = sorted(r["committed_at"] for r in commitments if r["committed_at"])
    revealed = s["revealed_entries"]
    intervals = {}
    for k, limit in POLICY.items():
        vals = [r[k] for r in ver if r[k] is not None]
        intervals[k] = {"reference_days": limit, "with_dates": len(vals),
                        "within": sum(1 for x in vals if x <= limit), "above": sum(1 for x in vals if x > limit)}
    merge_vals = [r["days_report_to_merge"] for r in ver if r["days_report_to_merge"] is not None]
    intervals["days_report_to_merge"] = {"reference_days": None, "with_dates": len(merge_vals)}
    by_flag, by_status = wview("by_flag"), wview("by_status")
    row = {
        "program": PROGRAM, "capture_utc": s["capture_utc"], "as_of_utc": s["as_of_utc"],
        "revision": s["revision"],
        "commitments_total": len(commitments), "by_tier": dict(sorted(tiers.items())),
        "revealed": revealed, "program_revealed_count": s["program_revealed_count"],
        "projects_with_revealed_findings": len({r["project"] for r in commitments if r["tier"] == "revealed" and r["project"]}),
        "withdrawn": sum(by_status.values()), "withdrawal_reasons": by_status,
        "withdrawn_by_flag": sum(by_flag.values()), "withdrawal_reasons_by_flag": by_flag,
        "withdrawn_by_status": sum(by_status.values()), "withdrawal_reasons_by_status": by_status,
        "merged": g["merged_status"], "merged_with_target": g["merged_with_target"],
        "earliest_commitment": committed[0] if committed else None,
        "latest_commitment": committed[-1] if committed else None,
        "checked_n": sum(1 for r in ver if r["checked"] == "yes"), "checked_of": len(ver),
        "hash_matches": hc.get("match", 0), "hash_mismatches": hc.get("mismatch", 0),
        "hash_preimage_withheld": hc.get("preimage_withheld", 0), "hash_unavailable": hc.get("unavailable", 0),
        "hash_not_checked": hc.get("not_checked", 0),
        "reported_total": s["reported_total"], "patched_lab_count": s["patched_lab_count"],
        "fixed_itemized": g["patched_itemized"],
        "revealed_share_of_reported_pct": _pct(revealed, s["reported_total"]),
        "itemized_share_of_reported_pct": _pct(revealed, s["reported_total"]),
        "fixed_itemized_share_of_patched_claimed_pct": _pct(g["patched_itemized"], s["patched_lab_count"]),
        "fixed_itemized_share_of_reported_pct": _pct(g["patched_itemized"], s["reported_total"]),
        "fix_merged": dict(sorted(Counter(r["fix_merged"] for r in ver).items())),
        "ids_exist": dict(sorted(Counter(r["ids_exist"] for r in ver).items())),
        "lookups": dict(sorted(Counter(r["lookup_status"] for r in ver).items())),
        "cvss_scores_present": {c: sum(1 for r in ver if r.get(c) is not None) for c in CVSS_COLUMNS},
        "interval_comparisons": intervals, "policy_source": policy_source,
        "archive_began": MANUAL_DAY,
    }
    return row


def policy_source(root: Path) -> str | None:
    pol = sorted((Path(root) / "captures" / "policy").glob("*/MANIFEST.json"))
    if not pol:
        return None
    m = json.loads(pol[-1].read_text(encoding="utf-8"))
    f = (m.get("files") or [{}])[0]
    return f"{f.get('url')} (our copy {f.get('stored_at')}, fetched {f.get('fetched_utc')})"


PROGRAM_COLUMNS = ["program", "name", "operator", "status", "per_finding_record", "publishes_summary", "as_of"]


def programs_rows(root: Path, snapshots: list[dict]) -> list[dict]:
    """Jon's hand-kept rows, with anthropic-cvd's status and as_of from the latest snapshot."""
    text = (Path(root) / "data" / "programs-manual.csv").read_text(encoding="utf-8")
    rows = [dict(r) for r in csv.DictReader(io.StringIO(text))]
    if [list(r) for r in rows][:1] and list(rows[0]) != PROGRAM_COLUMNS:
        raise ValueError(f"data/programs-manual.csv columns must be {PROGRAM_COLUMNS}")
    ours = [s for s in snapshots if s["source_kind"] == "our_capture"]
    if ours:
        s = ours[-1]
        for r in rows:
            if r["program"] == PROGRAM:
                r["status"] = f"Dashboard last updated {s['as_of_utc'][:10]} (revision {s['revision']})"
                r["as_of"] = s["as_of_utc"][:10]
    return [{c: (r.get(c) or None) for c in PROGRAM_COLUMNS} for r in rows]
