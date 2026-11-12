"""diagnose_403: why does GitHub refuse the built-in token for some global advisories?

For up to 5 GHSA IDs whose global-advisory lookup returned HTTP 403 "Resource not
accessible by integration", it tries, for each ID in order:

1. the same global-advisory request WITHOUT the Authorization header, paced at one
   request per 70 seconds, stopping at the first 403 rate-limit response (later
   unauthenticated requests are recorded as rate_limited, not made);
2. the repository advisory endpoint, GET /repos/{owner}/{repo}/security-advisories/{ghsa_id},
   with the built-in token. The repository comes from the finding's card (fix links)
   or its ledger project.

Raw responses go under records/diagnostic/ (never edited), and the outcomes into a
report. Only api.github.com is used. No new host, no new secret.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from urllib.parse import quote

from . import config
from .net import Fetcher
from .records import GH_COMMIT, GH_PULL, Key, RecordFetcher
from .records_read import RecordReader, _message
from .wording import check_text


def refused_ids(root: Path) -> list[str]:
    """GHSA IDs whose stored global-advisory lookup is github_refused_token, sorted."""
    reader = RecordReader(root)
    base = Path(root) / "records" / "github" / "advisories"
    out = []
    for d in sorted(base.glob("GHSA-*")) if base.exists() else []:
        if reader.github_advisory(d.name).get("status") == "github_refused_token":
            out.append(d.name)
    return out


def choose_ids(root: Path, spec: str) -> list[str]:
    """'auto' -> the first 5 refused IDs in sorted order; otherwise a comma-separated list (max 5)."""
    spec = (spec or "").strip()
    if spec.lower() == "auto":
        return refused_ids(root)[:config.DIAG_MAX_IDS]
    ids = [x.strip() for x in spec.split(",") if x.strip()]
    return ids[:config.DIAG_MAX_IDS]


def repository_for(findings: dict[str, dict], ghsa: str) -> tuple[str, str] | None:
    """owner/repo for a GHSA ID, from the card's GitHub fix links, else the ledger project."""
    for f in findings.values():
        if ghsa not in f.get("ghsa_ids", []):
            continue
        for u in f.get("fix_links", []) + f.get("advisory_links", []):
            m = GH_COMMIT.match(u) or GH_PULL.match(u)
            if m:
                return m.group(1), m.group(2).removesuffix(".git")
        proj = f.get("project") or ""
        if proj.count("/") == 1:
            o, r = proj.split("/")
            return o, r
    return None


def _outcome(rf: RecordFetcher, key: Key, attempt: dict) -> dict:
    out = {"url": key.url, "outcome": attempt.get("outcome"), "status": attempt.get("status"),
           "stored_at": attempt.get("stored_at"), "reason": attempt.get("reason")}
    if attempt.get("stored_at"):
        body = rf.store.read_bytes(attempt["stored_at"])
        msg = _message(body)
        out["message"] = msg
        try:
            d = json.loads(body.decode("utf-8"))
            if isinstance(d, dict) and d.get("ghsa_id"):
                out["ghsa_id_in_response"] = d.get("ghsa_id")
        except (UnicodeDecodeError, json.JSONDecodeError):
            pass
    return out


def diagnose(root: Path, ghsa_ids: list[str], findings: dict[str, dict], *, token: str | None,
             github_api: str = config.GITHUB_API, unauth_fetcher: Fetcher | None = None,
             auth_fetcher: Fetcher | None = None, sleep=time.sleep, clock=time.monotonic,
             wall=time.time) -> list[dict]:
    # Unauthenticated: a fetcher that may send credentials to no host at all.
    unauth = RecordFetcher(root, token=None, github_api=github_api, sleep=sleep, clock=clock, wall=wall,
                           stop_below=0, fetcher=unauth_fetcher or Fetcher(
                               credential_destinations=frozenset(),  # never sends a token anywhere
                               robots_exempt_hosts=config.API_ROBOTS_EXEMPT))
    auth = RecordFetcher(root, token=token, github_api=github_api, sleep=sleep, clock=clock, wall=wall,
                         fetcher=auth_fetcher)
    results, last_unauth = [], None
    for ghsa in ghsa_ids[:config.DIAG_MAX_IDS]:
        row = {"ghsa_id": ghsa}
        k1 = Key("github", "advisory_unauthenticated", f"diagnostic/github/advisories-unauthenticated/{ghsa}",
                 f"{github_api}/advisories/{quote(ghsa)}")
        if last_unauth is not None and not unauth.github_stopped:
            wait = config.DIAG_UNAUTH_GAP_SECONDS - (clock() - last_unauth)
            if wait > 0:
                sleep(wait)
        if not unauth.github_stopped:
            last_unauth = clock()
        row["global_without_token"] = _outcome(unauth, k1, unauth.fetch(k1))
        repo = repository_for(findings, ghsa)
        if repo:
            o, r = repo
            k2 = Key("github", "repository_advisory", f"diagnostic/github/repos/{o}/{r}/security-advisories/{ghsa}",
                     f"{github_api}/repos/{o}/{r}/security-advisories/{quote(ghsa)}")
            row["repository"] = f"{o}/{r}"
            row["repository_advisory_with_token"] = _outcome(auth, k2, auth.fetch(k2))
        else:
            row["repository"] = None
            row["repository_advisory_with_token"] = {"outcome": "not_attempted",
                                                     "reason": "no GitHub repository known for this advisory"}
        results.append(row)
    return results


def _describe(o: dict) -> str:
    if o.get("outcome") == "rate_limited" and o.get("status") is None:
        return f"not made: {o.get('reason')}"
    if o.get("outcome") == "not_attempted":
        return f"not attempted: {o.get('reason')}"
    if o.get("outcome") == "network_error":
        return f"no response: {o.get('reason')}"
    text = f"HTTP {o.get('status')}" + (" (rate limit; later requests without the token were not made)"
                                         if o.get("outcome") == "rate_limited" else "")
    if o.get("ghsa_id_in_response"):
        text += f", advisory {o['ghsa_id_in_response']} returned"
    if o.get("message"):
        text += f', message "{o["message"]}"'
    if o.get("stored_at"):
        text += f" (raw response: `{o['stored_at']}`)"
    return text


def report(results: list[dict], run_date: str) -> str:
    L = [f"# GitHub 403 diagnostic, {run_date}", "",
         "Generated by deterministic code. For each advisory whose global-advisory lookup returned HTTP 403 "
         f"\"{config.GITHUB_REFUSED_MESSAGE}\" with the workflow's built-in token, this run tried: (1) the same "
         "request without the Authorization header, paced at one request per 70 seconds and stopping at the first "
         "403 rate-limit response; (2) the repository advisory endpoint with the token. Only api.github.com was "
         "used. Raw responses are under `records/diagnostic/`.", "",
         "| Advisory | Global advisory, no token | Repository | Repository advisory, with token |",
         "| --- | --- | --- | --- |"]
    for r in results:
        L.append(f"| {r['ghsa_id']} | {_describe(r['global_without_token'])} | {r['repository'] or '-'} | "
                 f"{_describe(r['repository_advisory_with_token'])} |")
    ok_unauth = sum(1 for r in results if r["global_without_token"].get("status") == 200)
    ok_repo = sum(1 for r in results if r["repository_advisory_with_token"].get("status") == 200)
    L += ["", f"Global advisory readable without the token: {ok_unauth} of {len(results)}. "
              f"Repository advisory readable with the token: {ok_repo} of {len(results)}.", ""]
    text = "\n".join(L) + "\n"
    check_text(text, "403 diagnostic report")
    return text
