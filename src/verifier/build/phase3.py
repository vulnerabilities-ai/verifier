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
from ..records import GH_COMMIT, GH_PULL, GH_RELEASE_TAG, GH_REPO_ADVISORY, card_repository, fix_targets
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
                    "github": "severity_github",
                    "nvd_primary_v31": "severity_nvd_primary_v31", "nvd_primary_v40": "severity_nvd_primary_v40",
                    "nvd_cna_v31": "severity_nvd_cna_v31", "nvd_cna_v40": "severity_nvd_cna_v40"}
SEVERITY_SOURCES = tuple(SEVERITY_COLUMNS)
CVSS_COLUMNS = ("repo_advisory_cvss_v31_score", "repo_advisory_cvss_v40_score",
                "cvss_github_v31_score", "cvss_github_v40_score",
                "cvss_nvd_primary_v31_score", "cvss_nvd_primary_v40_score",
                "cvss_nvd_cna_v31_score", "cvss_nvd_cna_v40_score")
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


PENDING = ("rate_limited", "github_refused_token", "lookup_unreadable", "network_error", "no_repository_known",
           "not_checked")
ABSENT = ("not_found", "not_in_global_database")  # a source that was read and has no entry


def _worst(statuses: list[str]) -> str:
    for s in PENDING:
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
        detail, gh_adv, nvd_rec, repo_adv = {}, [], [], []
        repository = card_repository(inp["fix_links"], inp["advisory_links"])
        for g in inp["ghsa_ids"]:
            a = reader.github_advisory(g)
            detail[g] = {"github": a.get("status") if a.get("status") != "ok" else "exists"}
            lookup_statuses.append(a["status"] if a["status"] in PENDING else "ok")
            if a.get("status") == "ok":
                gh_adv.append(a)
            elif a.get("status") == "not_in_global_database":
                notes.append(f"{g}: {config.NOT_IN_GLOBAL_DATABASE} ({a.get('evidence')}).")
            elif a.get("status") == "github_refused_token":
                notes.append(f"Lookup of {g} in the GitHub Advisory Database: GitHub refused the built-in token "
                             f"(HTTP 403, message \"{a['reason']}\").")
            elif a.get("reason") and a["status"] != "not_found":
                notes.append(f"Lookup of {g} in the GitHub Advisory Database: {a['reason']}.")
            if a.get("status") in ("not_in_global_database", "github_refused_token"):
                # The repository's own advisory: a separate source, never merged with the global fields.
                ra = reader.repo_advisory(repository, g)
                detail[g]["repository_advisory"] = "exists" if ra["status"] == "ok" else ra["status"]
                lookup_statuses.append(ra["status"] if ra["status"] in PENDING else "ok")
                if ra["status"] == "ok":
                    repo_adv.append(ra)
                elif ra.get("reason"):
                    notes.append(f"{g} repository advisory"
                                 + (f" ({ra['repository']})" if ra.get("repository") else "") + f": {ra['reason']}.")
        for c in inp["cve_ids"]:
            a = reader.github_advisories_for_cve(c)
            n = reader.nvd_cve(c)
            detail[c] = {"github": "exists" if a.get("status") == "ok" else a.get("status"),
                         "nvd": "exists" if n.get("status") == "ok" else n.get("status")}
            for x, src in ((a, "GitHub Advisory Database"), (n, "NVD")):
                if x["status"] in PENDING:
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
        if fix["fix_merged"] in ("rate_limited", "github_refused_token", "lookup_unreadable", "network_error"):
            lookup_statuses.append(fix["fix_merged"])
            notes.append(f"Fix lookup: {fix.get('reason')}.")
        elif fix.get("reason") == "never looked up" or (fix["fix_merged"] == "not_checked"
                                                         and "never looked up" in str(fix.get("reason"))):
            lookup_statuses.append("not_checked")
        if fix.get("note"):
            notes.append(f"Fix: {fix['note'].strip()}.")
        if fix.get("address"):
            notes.append(unchecked_link_note(fix["address"], inp["fix_links"]))
        reason = fix_check_reason(v, inp, fix["fix_merged"])

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
            "fix_check_reason": reason[1] if reason else None,
            "fix_link_type_not_checked": link_type(fix["address"]) if fix.get("address") else None,
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
            # NIST's own entry (Primary, nvd@nist.gov) and the reporting authority's (Secondary), apart.
            "cvss_nvd_primary_v31_score": (nvd_first or {}).get("cvss_primary_v31_score"),
            "severity_nvd_primary_v31": (nvd_first or {}).get("severity_primary_v31"),
            "cvss_nvd_primary_v40_score": (nvd_first or {}).get("cvss_primary_v40_score"),
            "severity_nvd_primary_v40": (nvd_first or {}).get("severity_primary_v40"),
            "cvss_nvd_cna_v31_score": (nvd_first or {}).get("cvss_cna_v31_score"),
            "severity_nvd_cna_v31": (nvd_first or {}).get("severity_cna_v31"),
            "cvss_nvd_cna_v31_source": (nvd_first or {}).get("cvss_cna_v31_source"),
            "cvss_nvd_cna_v40_score": (nvd_first or {}).get("cvss_cna_v40_score"),
            "severity_nvd_cna_v40": (nvd_first or {}).get("severity_cna_v40"),
            "cvss_nvd_cna_v40_source": (nvd_first or {}).get("cvss_cna_v40_source"),
            "cvss_nvd_entries": (nvd_first or {}).get("cvss_entries") or [],
            "cwe_github": sorted({c for a in gh_adv for c in a.get("cwes", [])}),
            "cwe_nvd": sorted({c for n in nvd_rec for c in n.get("cwes", [])}),
            "advisory_review_status": (gh_first or {}).get("review_status"),
            # Repository advisories (GitHub's per-repository advisories), their own source.
            **_repo_columns(repo_adv),
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


# Why a fix could not be checked (fix_merged = not_checked): read from the card only.
# Fix commits are never inferred from advisories or NVD references here.
FIX_CHECK_REASONS = {
    "no_card": "no copy of the finding card is available",
    "no_outside_links": "the card links no fix commit or pull request (the card has no outside links)",
    "only_nvd_links": "the card links no fix commit or pull request (its only outside links are NVD records)",
    "github_not_commit_or_pull": "the card's links are not GitHub commits or pull requests (it links GitHub, "
                                 "but not to a commit or pull request)",
    "fix_not_on_github": "the card's fix link is not on GitHub",  # its fix section links another host
    "other_links": "the card's links are not GitHub commits or pull requests",
    "not_looked_up_yet": "the card links a GitHub fix, which has not been looked up yet",
    "advisory_commit_no_fix_link": "the card has no separate fix link; its advisory link is a GitHub commit, "
                                   "which is not used as the fix link",
    "advisory_commit_other_fix_link": "the card's fix link is not a GitHub commit or pull request; its advisory "
                                      "link is a GitHub commit, which is not used as the fix link",
    "commit_in_text_only": "the card has no fix or advisory link that is a GitHub commit or pull request; it links "
                           "a GitHub commit or pull request only in its text, which is not used as the fix link",
    "links_not_recorded": "the card's links were not recorded when it was read",
}


def fix_check_reason(v: dict | None, inp: dict, fix_merged: str) -> tuple[str, str] | None:
    """(code, plain reason) when fix_merged is not_checked; None otherwise."""
    if fix_merged != "not_checked":
        return None
    facts = (v or {}).get("card_facts")
    if not facts:
        return "no_card", FIX_CHECK_REASONS["no_card"]
    t = fix_targets(inp.get("fix_links", []), inp.get("advisory_links", []))
    if t["commit"] or t["pull"]:
        return "not_looked_up_yet", FIX_CHECK_REASONS["not_looked_up_yet"]
    links = facts.get("outside_links")
    if links is None:  # the build re-reads every stored card, so this only happens with hand-made files
        return "links_not_recorded", FIX_CHECK_REASONS["links_not_recorded"]
    if not links:
        return "no_outside_links", FIX_CHECK_REASONS["no_outside_links"]
    fix_links, adv_links = inp.get("fix_links", []), inp.get("advisory_links", [])
    if any(GH_COMMIT.match(u) for u in adv_links):  # never looked up as the fix
        return (("advisory_commit_other_fix_link", FIX_CHECK_REASONS["advisory_commit_other_fix_link"]) if fix_links
                else ("advisory_commit_no_fix_link", FIX_CHECK_REASONS["advisory_commit_no_fix_link"]))
    if any(GH_COMMIT.match(u) or GH_PULL.match(u) for u in links):
        return "commit_in_text_only", FIX_CHECK_REASONS["commit_in_text_only"]
    hosts = {_host(u) for u in links}
    if hosts == {"nvd.nist.gov"}:
        return "only_nvd_links", FIX_CHECK_REASONS["only_nvd_links"]
    if "github.com" in hosts:  # e.g. a release tag, an advisory, a file or the repository itself
        return "github_not_commit_or_pull", FIX_CHECK_REASONS["github_not_commit_or_pull"]
    if any(_host(u) not in ("github.com", "nvd.nist.gov") for u in t["not_on_github"]):
        return "fix_not_on_github", FIX_CHECK_REASONS["fix_not_on_github"]
    return "other_links", FIX_CHECK_REASONS["other_links"]


# The kind of link a card gives in place of a fix commit or pull request (none is ever checked as the fix).
LINK_TYPES = ("GitHub release tag", "GitHub repository advisory", "GitHub advisory", "NVD page", "other")


def link_type(url: str) -> str:
    if GH_RELEASE_TAG.match(url):
        return "GitHub release tag"
    if GH_REPO_ADVISORY.match(url):
        return "GitHub repository advisory"
    if _host(url) == "github.com" and "/advisories/" in url:
        return "GitHub advisory"
    if _host(url) == "nvd.nist.gov":
        return "NVD page"
    return "other"


def unchecked_link_note(url: str, fix_links: list[str]) -> str:
    section = "fix" if url in fix_links else "advisory"
    kind = link_type(url)
    what = {"other": "a link of another kind", "NVD page": "an NVD page"}.get(kind, f"a {kind}")
    return (f"The card's {section} link is {what}, not a commit or pull request; it was not checked as the fix: "
            f"{url}.")


def _host(url: str) -> str:
    from urllib.parse import urlsplit
    h = (urlsplit(url).hostname or "").lower()
    return h[4:] if h.startswith("www.") else h


def _repo_columns(repo_adv: list[dict]) -> dict:
    first = sorted(repo_adv, key=lambda a: a.get("published") or "")[0] if repo_adv else {}
    return {
        "repo_advisory_repository": first.get("repository"),
        "repo_advisory_published": (first.get("published") or "")[:10] or None,
        "repo_advisory_severity": first.get("severity"),
        "repo_advisory_cve_id": first.get("cve_id"),
        "repo_advisory_cwes": first.get("cwes") or [],
        "repo_advisory_cvss_v31_score": first.get("cvss_v31_score"),
        "repo_advisory_cvss_v40_score": first.get("cvss_v40_score"),
        "repo_advisory_state": first.get("state"),
        "repo_advisory_read_with": first.get("read_with"),
    }


def _ids_exist(detail: dict) -> str:
    """verified: every ID has an entry in at least one source (global database, NVD, or the
    repository's own advisory). not_found: some ID was read in every source and none has it."""
    if not detail:
        return "not_applicable"
    states = []
    for d in detail.values():
        vals = list(d.values())
        if "exists" in vals:
            states.append("exists")
        elif vals and all(x in ABSENT for x in vals):
            states.append("not_found")
        else:
            states.append(_worst([x for x in vals if x not in ("exists",) + ABSENT]))
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
        "ghsa_ids": _ghsa_counts(ver),
        "fix_check_reasons": dict(sorted(Counter(r["fix_check_reason"] for r in ver
                                                 if r.get("fix_check_reason")).items())),
        "fix_links_not_checked_by_type": dict(sorted(Counter(r["fix_link_type_not_checked"] for r in ver
                                                             if r.get("fix_link_type_not_checked")).items())),
        "interval_comparisons": intervals, "policy_source": policy_source,
        "archive_began": MANUAL_DAY,
    }
    return row


def _ghsa_counts(ver: list[dict]) -> dict:
    """Per GHSA ID on revealed findings: global database status and repository-advisory status."""
    glob, repo = Counter(), Counter()
    seen = set()
    for r in ver:
        for g, d in (r.get("ids_exist_detail") or {}).items():
            if not g.startswith("GHSA-") or g in seen:
                continue
            seen.add(g)
            glob[d.get("github")] += 1
            if "repository_advisory" in d:
                repo[d["repository_advisory"]] += 1
    return {"total": len(seen), "global_database": dict(sorted(glob.items())),
            "repository_advisory": dict(sorted(repo.items()))}


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
