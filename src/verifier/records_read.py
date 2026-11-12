"""Read stored public-record responses (records/) into R3 and R4 results.

No network. Tolerant by design: an unexpected shape, a missing field, a body
that is not JSON or an unexpected status never raises. It gives the result
"lookup_unreadable" with a plain reason, and the raw response stays in records/.

Statuses for one lookup:
  ok                 the response was read
  not_found          the source answered that the record does not exist
  lookup_unreadable  a response came back but could not be read (reason given)
  rate_limited       the last attempt was stopped by a rate limit (none stored yet)
  not_checked        never attempted
  network_error      the source could not be reached (reason given)
  github_refused_token  GitHub answered HTTP 403 "Resource not accessible by integration":
                     it refused the workflow's built-in token for this resource (not a
                     rate limit; the exact message is kept as the reason)
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from . import config
from .records import Key, fix_keys, fix_targets, keys_for_ids, repo_keys
from .store import Archive


class Unreadable(Exception):
    pass


def _get(d, *path, required=True, types=None):
    cur = d
    for p in path:
        if isinstance(p, int):
            if not isinstance(cur, list) or len(cur) <= p:
                if required:
                    raise Unreadable(f"response has no item {p} under '{'.'.join(map(str, path[:-1])) or 'top'}'")
                return None
        elif not isinstance(cur, dict) or p not in cur:
            if required:
                raise Unreadable(f"response has no '{'.'.join(map(str, path))}' field")
            return None
        cur = cur[p]
    if types is not None and cur is not None and not isinstance(cur, types):
        if required:
            raise Unreadable(f"'{'.'.join(map(str, path))}' has an unexpected type ({type(cur).__name__})")
        return None
    return cur


class RecordReader:
    def __init__(self, root: Path, github_api: str = config.GITHUB_API, nvd_api: str = config.NVD_API):
        self.store = Archive(root, area="records")
        self.github_api, self.nvd_api = github_api, nvd_api

    # -- raw access -----------------------------------------------------------------
    def raw(self, key: Key) -> dict:
        """{"status", "reason", "body", "http_status", "as_of", "stored_at"} for the latest
        usable response of a key."""
        m = self.store.load_json(f"records/{key.path}/MANIFEST.json")
        if not m or not m.get("attempts"):
            return {"status": "not_checked", "reason": "never looked up"}
        attempts = m["attempts"]
        fetched = [a for a in attempts if a.get("outcome") == "fetched"]
        if not fetched:
            last = attempts[-1]
            st = "rate_limited" if last.get("outcome") == "rate_limited" else "network_error"
            return {"status": st, "reason": last.get("reason") or st}
        a = fetched[-1]
        body = None
        if a.get("stored_at"):
            try:
                body = self.store.read_bytes(a["stored_at"])
            except OSError:
                return {"status": "lookup_unreadable", "reason": "stored response file is missing"}
        return {"status": "fetched", "http_status": a.get("status"), "body": body, "as_of": a.get("fetched_utc"),
                "stored_at": a.get("stored_at"), "url": key.url}

    def json_of(self, key: Key, ok_statuses=(200,), not_found=(404,)) -> dict:
        r = self.raw(key)
        if r["status"] != "fetched":
            return r
        hs = r.get("http_status")
        base = {"as_of": r.get("as_of"), "stored_at": r.get("stored_at"), "url": r.get("url")}
        if hs in not_found:
            return {**base, "status": "not_found", "reason": f"HTTP {hs}"}
        if hs == 403 and key.source == "github":
            msg = _message(r.get("body"))
            if msg and config.GITHUB_REFUSED_MESSAGE.lower() in msg.lower():
                # Not a rate limit: GitHub refused the built-in token for this resource.
                return {**base, "status": "github_refused_token", "reason": msg, "http_status": 403}
        if hs not in ok_statuses:
            return {**base, "status": "lookup_unreadable", "reason": f"unexpected HTTP {hs}"}
        if not r.get("body"):
            return {**base, "status": "lookup_unreadable", "reason": "empty response"}
        try:
            return {**base, "status": "ok", "data": json.loads(r["body"].decode("utf-8"))}
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            return {**base, "status": "lookup_unreadable", "reason": f"response is not JSON ({e.__class__.__name__})"}

    # -- R3 parsers -------------------------------------------------------------------
    def github_advisory(self, ghsa: str) -> dict:
        k = keys_for_ids([], [ghsa], self.github_api, self.nvd_api)[0]
        r = self.json_of(k)
        if r["status"] != "ok":
            return r
        try:
            return {**_strip(r), **parse_github_advisory(r["data"])}
        except Unreadable as e:
            return {**_strip(r), "status": "lookup_unreadable", "reason": str(e)}

    def github_advisories_for_cve(self, cve: str) -> dict:
        k = keys_for_ids([cve], [], self.github_api, self.nvd_api)[0]
        r = self.json_of(k)
        if r["status"] != "ok":
            return r
        data = r["data"]
        if not isinstance(data, list):
            return {**_strip(r), "status": "lookup_unreadable",
                    "reason": f"expected a list of advisories, got {type(data).__name__}"}
        out = []
        for i, item in enumerate(data):
            try:
                out.append(parse_github_advisory(item))
            except Unreadable as e:
                return {**_strip(r), "status": "lookup_unreadable", "reason": f"advisory {i}: {e}"}
        return {**_strip(r), "status": "ok" if out else "not_found",
                "reason": None if out else "GitHub lists no advisory for this CVE", "advisories": out}

    def nvd_cve(self, cve: str) -> dict:
        k = keys_for_ids([cve], [], self.github_api, self.nvd_api)[1]
        r = self.json_of(k)
        if r["status"] != "ok":
            return r
        try:
            return {**_strip(r), **parse_nvd(r["data"], cve)}
        except Unreadable as e:
            return {**_strip(r), "status": "lookup_unreadable", "reason": str(e)}

    # -- R4 ---------------------------------------------------------------------------------
    def fix_merged(self, fix_links: list[str], advisory_links: list[str]) -> dict:
        t = fix_targets(fix_links, advisory_links)
        if not t["commit"] and not t["pull"]:
            if t["not_on_github"]:
                return {"status": "not_checked", "fix_merged": "not_checked",
                        "reason": "the fix is not on GitHub", "address": t["not_on_github"][0]}
            return {"status": "not_checked", "fix_merged": "not_checked", "reason": "the card names no fix"}
        o, r = (t["pull"] or t["commit"])[:2]
        repo = self.json_of(repo_keys(o, r, self.github_api))
        if repo["status"] != "ok":
            return {**_strip(repo), "fix_merged": _pending(repo["status"]), "reason": f"repository: {repo.get('reason')}"}
        branch = repo["data"].get("default_branch") if isinstance(repo["data"], dict) else None
        if not isinstance(branch, str) or not branch:
            return {"status": "lookup_unreadable", "fix_merged": "lookup_unreadable",
                    "reason": "repository response has no 'default_branch'"}
        keys = {k.kind: k for k in fix_keys(t, branch, self.github_api)}
        res = {"default_branch": branch, "fix_url": None, "fix_merged_at": None, "merge_base": None}
        unreadable = []
        if "pull" in keys:
            p = self.json_of(keys["pull"])
            res["fix_url"] = f"https://github.com/{o}/{r}/pull/{t['pull'][2]}"
            if p["status"] == "ok":
                try:
                    merged = _get(p["data"], "merged", required=False)
                    merged_at = _get(p["data"], "merged_at", required=False, types=str)
                    base = _get(p["data"], "base", "ref", types=str)
                    res["merge_base"] = base
                    if (merged or merged_at) and base == branch:
                        return {**res, "status": "ok", "fix_merged": "yes", "fix_merged_at": merged_at,
                                "evidence": "pull request merged into the default branch", "as_of": p.get("as_of")}
                    if merged or merged_at:
                        res.update(fix_merged_at=merged_at, note=f"pull request merged into '{base}', "
                                   f"not the default branch '{branch}'")
                    else:
                        res["note"] = "pull request not merged"
                except Unreadable as e:
                    unreadable.append(f"pull request: {e}")
            elif p["status"] not in ("not_found",):
                unreadable.append(f"pull request: {p.get('reason')}")
        if "commit" in keys:
            res["fix_url"] = res["fix_url"] or f"https://github.com/{o}/{r}/commit/{t['commit'][2]}"
            c = self.json_of(keys["commit"], not_found=(404, 422))
            if c["status"] == "not_found":
                res["note"] = "the fix commit was not found"
            elif c["status"] != "ok":
                unreadable.append(f"commit: {c.get('reason')}")
            cmp_ = self.json_of(keys["compare"], not_found=(404,)) if "compare" in keys else None
            if cmp_ and cmp_["status"] == "ok":
                st = cmp_["data"].get("status") if isinstance(cmp_["data"], dict) else None
                if st in ("behind", "identical"):
                    date, ev = None, "commit is on the default branch"
                    if "commit_pulls" in keys:
                        cp = self.json_of(keys["commit_pulls"])
                        if cp["status"] == "ok" and isinstance(cp["data"], list):
                            for pr in cp["data"]:
                                if isinstance(pr, dict) and pr.get("merged_at") and \
                                        isinstance(pr.get("base"), dict) and pr["base"].get("ref") == branch:
                                    date, ev = pr["merged_at"], "commit is on the default branch via a merged pull request"
                                    break
                    return {**res, "status": "ok", "fix_merged": "yes", "fix_merged_at": date, "evidence": ev,
                            "note": None if date else "merge time not available (no merged pull request found)"}
                if st in ("ahead", "diverged"):
                    res["note"] = (res.get("note") or "") + f" commit is not on the default branch (compare: {st})"
                elif st is None:
                    unreadable.append("compare: response has no 'status' field")
            elif cmp_ and cmp_["status"] not in ("not_found",):
                unreadable.append(f"compare: {cmp_.get('reason')}")
        if unreadable:
            statuses = " ".join(unreadable)
            kind = "rate_limited" if "rate limit" in statuses.lower() else (
                "github_refused_token" if config.GITHUB_REFUSED_MESSAGE.lower() in statuses.lower() else (
                    "not_checked" if "never looked up" in statuses else "lookup_unreadable"))
            return {**res, "status": kind, "fix_merged": kind, "reason": "; ".join(unreadable)}
        return {**res, "status": "ok", "fix_merged": "no", "evidence": res.get("note")}


def _pending(status: str) -> str:
    return {"rate_limited": "rate_limited", "not_checked": "not_checked",
            "github_refused_token": "github_refused_token"}.get(status, "lookup_unreadable")


def _message(body: bytes | None) -> str | None:
    """The 'message' field of a GitHub error response, exactly as sent, if there is one."""
    try:
        d = json.loads((body or b"").decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    m = d.get("message") if isinstance(d, dict) else None
    return m if isinstance(m, str) else None


def _strip(r: dict) -> dict:
    return {k: v for k, v in r.items() if k not in ("data", "body")}


def _cvss_version(vector: str | None) -> str | None:
    m = re.match(r"CVSS:(\d+(?:\.\d+)?)/", vector or "")
    return m.group(1) if m else None


# CVSS versions that have their own published columns. Any other version (for
# example 3.0 or 2.0) is kept in the *_entries list, so nothing is hidden.
COLUMN_VERSIONS = {"3.1": "v31", "4.0": "v40"}


def _score(v):
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def github_cvss_entries(d: dict) -> list[dict]:
    """Every real CVSS entry in a GitHub advisory. An object without a vector
    string is a placeholder (GitHub sends {"vector_string": null, "score": 0.0}
    for a version it has no score for): it is absent, never a score of 0.0."""
    out, seen = [], set()
    sev_all = d.get("cvss_severities") if isinstance(d.get("cvss_severities"), dict) else {}
    candidates = [(k, v) for k, v in sorted(sev_all.items())]
    if isinstance(d.get("cvss"), dict):
        candidates.append(("cvss", d["cvss"]))
    for field, v in candidates:
        if not isinstance(v, dict):
            continue
        vector = v.get("vector_string")
        if not isinstance(vector, str) or not vector.strip():
            continue  # placeholder: absent
        version = _cvss_version(vector)
        score = _score(v.get("score"))
        if version is None or score is None or vector in seen:
            continue
        seen.add(vector)
        out.append({"field": field, "version": version, "score": score, "vector": vector})
    return out


def by_version(entries: list[dict]) -> dict:
    """{'v31': entry, 'v40': entry} for the column versions, one entry each."""
    out = {}
    for e in entries:
        col = COLUMN_VERSIONS.get(e["version"])
        if col and col not in out:
            out[col] = e
    return out


def parse_github_advisory(d) -> dict:
    if not isinstance(d, dict):
        raise Unreadable(f"expected an advisory object, got {type(d).__name__}")
    ghsa = _get(d, "ghsa_id", types=str)
    entries = github_cvss_entries(d)
    cols = by_version(entries)
    cwes = [c.get("cwe_id") for c in (_get(d, "cwes", required=False, types=list) or [])
            if isinstance(c, dict) and c.get("cwe_id")]
    packages = []
    for v in _get(d, "vulnerabilities", required=False, types=list) or []:
        pkg = v.get("package") if isinstance(v, dict) else None
        if isinstance(pkg, dict) and pkg.get("name"):
            packages.append(f"{pkg.get('ecosystem', '?')}:{pkg['name']}")
    credits = []
    for c in _get(d, "credits", required=False, types=list) or []:
        if isinstance(c, dict):
            u = c.get("user") if isinstance(c.get("user"), dict) else {}
            credits.append({"login": u.get("login"), "type": c.get("type")})
    refs = [r if isinstance(r, str) else (r.get("url") if isinstance(r, dict) else None)
            for r in (_get(d, "references", required=False, types=list) or [])]
    return {
        "status": "ok", "exists": True, "ghsa_id": ghsa, "cve_id": _get(d, "cve_id", required=False),
        "review_status": _get(d, "type", required=False),
        "published": _get(d, "published_at", required=False), "updated": _get(d, "updated_at", required=False),
        "severity": _get(d, "severity", required=False),  # GitHub's own stated severity
        "cvss_v31_score": (cols.get("v31") or {}).get("score"),
        "cvss_v40_score": (cols.get("v40") or {}).get("score"),
        "cvss_entries": entries, "cwes": cwes, "packages": packages,
        "source_code_location": _get(d, "source_code_location", required=False),
        "references": [r for r in refs if r], "credits": credits,
    }


def nvd_cvss_entries(metrics: dict) -> list[dict]:
    """Every CVSS entry in an NVD record, each with its own source and type
    (NIST's own analysis is "Primary" from nvd@nist.gov; a reporting authority's
    (CNA's) score shown by NVD is "Secondary").
    An entry without a vector string or score is absent, never 0.0."""
    out = []
    for key in sorted(metrics):
        lst = metrics.get(key)
        if not isinstance(lst, list):
            continue
        for m in lst:
            if not isinstance(m, dict) or not isinstance(m.get("cvssData"), dict):
                continue
            data = m["cvssData"]
            vector = data.get("vectorString")
            score = _score(data.get("baseScore"))
            if not isinstance(vector, str) or not vector.strip() or score is None:
                continue
            out.append({"version": str(data.get("version") or _cvss_version(vector) or ""), "score": score,
                        "severity": data.get("baseSeverity") or m.get("baseSeverity"),
                        "source": m.get("source"), "type": m.get("type"), "vector": vector})
    return out


NVD_PRIMARY_SOURCE = "nvd@nist.gov"


def nvd_split(entries: list[dict]) -> dict:
    """Per column version, NIST's own entry and the reporting authority's entry, kept apart:
    {"primary": {"v31": e, ...}, "cna": {"v31": e, ...}}.
    - primary: the entry with type Primary and source nvd@nist.gov (only if exactly one);
    - cna: the Secondary entry, only if exactly one exists for that version. If there are
      several, none is chosen: the column stays empty and all are in the entries list."""
    out = {"primary": {}, "cna": {}}
    for ver, col in COLUMN_VERSIONS.items():
        same = [e for e in entries if e["version"] == ver]
        primary = [e for e in same if e.get("type") == "Primary" and e.get("source") == NVD_PRIMARY_SOURCE]
        secondary = [e for e in same if e.get("type") == "Secondary"]
        if len(primary) == 1:
            out["primary"][col] = primary[0]
        if len(secondary) == 1:
            out["cna"][col] = secondary[0]
    return out


def parse_nvd(d, cve: str) -> dict:
    if not isinstance(d, dict):
        raise Unreadable(f"expected an object, got {type(d).__name__}")
    total = _get(d, "totalResults", types=int)
    vulns = _get(d, "vulnerabilities", types=list)
    if total == 0 or not vulns:
        return {"status": "not_found", "exists": False, "reason": "NVD returned no record for this CVE"}
    c = _get(vulns[0], "cve", types=dict)
    if c.get("id") != cve:
        raise Unreadable(f"NVD returned {c.get('id')!r} instead of {cve}")
    metrics = c.get("metrics") if isinstance(c.get("metrics"), dict) else {}
    entries = nvd_cvss_entries(metrics)
    split = nvd_split(entries)
    cwes = []
    for w in c.get("weaknesses") or []:
        for desc in (w.get("description") or []) if isinstance(w, dict) else []:
            if isinstance(desc, dict) and str(desc.get("value", "")).startswith("CWE-"):
                cwes.append(desc["value"])
    out = {"status": "ok", "exists": True, "published": c.get("published"),
           "updated": c.get("lastModified"), "vuln_status": c.get("vulnStatus"),
           "cvss_entries": entries, "cwes": sorted(set(cwes)),
           "references": [r.get("url") for r in c.get("references") or [] if isinstance(r, dict)]}
    for col in COLUMN_VERSIONS.values():
        p_ = split["primary"].get(col) or {}
        c_ = split["cna"].get(col) or {}
        out[f"cvss_primary_{col}_score"] = p_.get("score")
        out[f"severity_primary_{col}"] = p_.get("severity")
        out[f"cvss_cna_{col}_score"] = c_.get("score")
        out[f"severity_cna_{col}"] = c_.get("severity")
        out[f"cvss_cna_{col}_source"] = c_.get("source")
    return out
