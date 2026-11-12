"""Public-record lookups for rules R3 (identifiers) and R4 (fix merged).

This module only FETCHES and STORES raw responses under records/, exactly as
served, never edited (store-only-when-changed). Reading them is done by
records_read.py during the build, which never touches the network.

Sources:
- GitHub REST API (api.github.com): global security advisories, repositories,
  commits, pull requests. Uses the workflow's built-in token only.
- NVD CVE API 2.0 (services.nvd.nist.gov): no key; one request every 8 seconds, and on
  HTTP 429 a 35-second wait and up to 3 retries before recording rate_limited.

Both are documented APIs exempt from the robots.txt check (Jon, 2026-11-10);
every other host keeps it. Nothing here ever aborts a run: a failure is
recorded as an attempt with its reason, and GitHub's rate limit stops further
GitHub calls cleanly, recording "rate_limited" so the next run resumes.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlsplit

from . import config
from .capture import time_suffix
from .net import CaptureError, Fetcher, Response, sha256_hex, utc_now
from .store import Archive

GH_COMMIT = re.compile(r"^https?://github\.com/([^/\s]+)/([^/\s]+)/commit/([0-9a-fA-F]{7,40})")
GH_PULL = re.compile(r"^https?://github\.com/([^/\s]+)/([^/\s]+)/pull/(\d+)")
GH_REPO_ADVISORY = re.compile(r"^https?://github\.com/([^/\s]+)/([^/\s]+)/security/advisories/(GHSA-[\w-]+)")


class RateLimited(Exception):
    pass


# ---------------------------------------------------------------------------
# What to look up for one finding
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Key:
    """One lookup. path is relative to records/ and names its folder."""
    source: str  # "github" or "nvd"
    kind: str    # advisory, advisory_by_cve, cve, repo, commit, pull, compare, commit_pulls
    path: str
    url: str


def gh(path: str) -> str:
    return config.GITHUB_API + path


def keys_for_ids(cves: list[str], ghsas: list[str], github_api: str = config.GITHUB_API,
                 nvd_api: str = config.NVD_API) -> list[Key]:
    out = []
    for g in sorted(set(ghsas)):
        out.append(Key("github", "advisory", f"github/advisories/{g}", f"{github_api}/advisories/{quote(g)}"))
    for c in sorted(set(cves)):
        out.append(Key("github", "advisory_by_cve", f"github/advisories-by-cve/{c}",
                       f"{github_api}/advisories?cve_id={quote(c)}"))
        out.append(Key("nvd", "cve", f"nvd/cves/{c}", f"{nvd_api}?cveId={quote(c)}"))
    return out


def fix_targets(fix_links: list[str], advisory_links: list[str]) -> dict:
    """GitHub commit and pull request named on the card, and anything not on GitHub."""
    commit = next((GH_COMMIT.match(u) for u in fix_links if GH_COMMIT.match(u)), None)
    pull = next((GH_PULL.match(u) for u in advisory_links + fix_links if GH_PULL.match(u)), None)
    other = [u for u in fix_links + advisory_links
             if not GH_COMMIT.match(u) and not GH_PULL.match(u) and "github.com/advisories/" not in u]
    return {
        "commit": (commit.group(1), commit.group(2).removesuffix(".git"), commit.group(3)) if commit else None,
        "pull": (pull.group(1), pull.group(2), int(pull.group(3))) if pull else None,
        "not_on_github": other if not commit and not pull else [],
    }


def card_repository(fix_links: list[str], advisory_links: list[str]) -> tuple[str, str] | None:
    """owner/repo named by the finding card's GitHub links (fix commit, pull request or
    repository advisory). None when the card gives no GitHub repository."""
    for u in advisory_links + fix_links:
        m = GH_REPO_ADVISORY.match(u) or GH_COMMIT.match(u) or GH_PULL.match(u)
        if m:
            return m.group(1), m.group(2).removesuffix(".git")
    return None


def global_unauth_key(ghsa: str, github_api: str = config.GITHUB_API) -> Key:
    """The global-advisory request made WITHOUT the token, to confirm a 403."""
    return Key("github", "advisory_unauthenticated", f"github/advisories-unauthenticated/{ghsa}",
               f"{github_api}/advisories/{quote(ghsa)}")


def repo_advisory_key(owner: str, repo: str, ghsa: str, github_api: str = config.GITHUB_API,
                      unauthenticated: bool = False) -> Key:
    path = f"github/repos/{owner}/{repo}/security-advisories/{ghsa}"
    return Key("github", "repo_advisory_unauthenticated" if unauthenticated else "repo_advisory",
               path + ("/unauthenticated" if unauthenticated else ""),
               f"{github_api}/repos/{owner}/{repo}/security-advisories/{quote(ghsa)}")


def repo_keys(owner: str, repo: str, github_api: str = config.GITHUB_API) -> Key:
    return Key("github", "repo", f"github/repos/{owner}/{repo}/repo", f"{github_api}/repos/{owner}/{repo}")


def fix_keys(t: dict, default_branch: str | None, github_api: str = config.GITHUB_API) -> list[Key]:
    keys = []
    if t["commit"]:
        o, r, sha = t["commit"]
        keys.append(repo_keys(o, r, github_api))
        keys.append(Key("github", "commit", f"github/repos/{o}/{r}/commits/{sha}",
                        f"{github_api}/repos/{o}/{r}/commits/{sha}"))
        if default_branch:
            keys.append(Key("github", "compare", f"github/repos/{o}/{r}/compare/{default_branch}...{sha}",
                            f"{github_api}/repos/{o}/{r}/compare/{quote(default_branch, safe='')}...{sha}"))
        if not t["pull"]:
            keys.append(Key("github", "commit_pulls", f"github/repos/{o}/{r}/commits/{sha}/pulls",
                            f"{github_api}/repos/{o}/{r}/commits/{sha}/pulls"))
    if t["pull"]:
        o, r, n = t["pull"]
        keys.append(repo_keys(o, r, github_api))
        keys.append(Key("github", "pull", f"github/repos/{o}/{r}/pulls/{n}",
                        f"{github_api}/repos/{o}/{r}/pulls/{n}"))
    seen, out = set(), []
    for k in keys:
        if k.path not in seen:
            seen.add(k.path)
            out.append(k)
    return out


# ---------------------------------------------------------------------------
# Fetching with both sources' rules
# ---------------------------------------------------------------------------
class RecordFetcher:
    def __init__(self, root: Path, *, token: str | None = None, fetcher: Fetcher | None = None,
                 github_api: str = config.GITHUB_API, nvd_api: str = config.NVD_API,
                 sleep=time.sleep, clock=time.monotonic, wall=time.time,
                 stop_below: int = config.GITHUB_STOP_BELOW,
                 nvd_gap: float = config.NVD_MIN_GAP_SECONDS,
                 nvd_retry_wait: float = config.NVD_RETRY_WAIT_SECONDS, nvd_retries: int = config.NVD_RETRIES,
                 spread: bool = True):
        self.store = Archive(root, area="records")
        gh_host = urlsplit(github_api).netloc
        nvd_host = urlsplit(nvd_api).netloc
        self.github_api, self.nvd_api = github_api, nvd_api
        self.fetcher = fetcher or Fetcher(
            credential_destinations=frozenset({f"{urlsplit(github_api).scheme}://{gh_host}"}),
            robots_exempt_hosts=config.API_ROBOTS_EXEMPT)
        self._token = token or None
        self.sleep, self.clock, self.wall = sleep, clock, wall
        self.stop_below = stop_below
        self.nvd_gap, self.nvd_retry_wait, self.nvd_retries = nvd_gap, nvd_retry_wait, nvd_retries
        self.spread = spread  # spread GitHub calls over the rate-limit window (off when the caller paces)
        self._nvd_last: float | None = None
        self.github_stopped: str | None = None
        self.nvd_stopped: str | None = None
        self.gh_remaining: int | None = None
        self.gh_reset: float | None = None
        self.tally = {"fetched": 0, "unchanged": 0, "rate_limited": 0, "errors": 0}

    def __repr__(self) -> str:  # never show the token
        return "<RecordFetcher>"

    # -- pacing ----------------------------------------------------------------
    def _pace_github(self) -> None:
        if self.github_stopped:
            raise RateLimited(self.github_stopped)
        if self.gh_remaining is not None and self.gh_reset is not None:
            spare = self.gh_remaining - self.stop_below
            if spare <= 0:
                self.github_stopped = (f"GitHub rate limit: {self.gh_remaining} requests left; "
                                       f"stopped to stay above {self.stop_below}")
                raise RateLimited(self.github_stopped)
            window = max(0.0, self.gh_reset - self.wall())
            gap = window / spare
            if self.spread and gap > 1.0:  # spread the remaining calls over the time to reset
                self.sleep(min(gap, 30.0))

    def _pace_nvd(self) -> None:
        """At most one NVD request every nvd_gap seconds (8 s)."""
        if self.nvd_stopped:
            raise RateLimited(self.nvd_stopped)
        if self._nvd_last is not None:
            gap = self.clock() - self._nvd_last
            if gap < self.nvd_gap:
                self.sleep(self.nvd_gap - gap)
        self._nvd_last = self.clock()

    def _read_github_limits(self, resp: Response) -> None:
        try:
            if resp.header("X-RateLimit-Remaining") is not None:
                self.gh_remaining = int(resp.header("X-RateLimit-Remaining"))
            if resp.header("X-RateLimit-Reset") is not None:
                self.gh_reset = float(resp.header("X-RateLimit-Reset"))
        except ValueError:
            pass
        body = resp.body[:2000].decode("utf-8", errors="replace").lower()
        limited = resp.status == 429 or (resp.status == 403 and (
            "rate limit" in body or resp.header("Retry-After") is not None or self.gh_remaining == 0))
        if limited:
            self.github_stopped = (f"GitHub rate limit reached (HTTP {resp.status}"
                                   + (f", Retry-After {resp.header('Retry-After')}s" if resp.header("Retry-After") else "")
                                   + ")")
            raise RateLimited(self.github_stopped)

    # -- one lookup --------------------------------------------------------------
    def fetch(self, key: Key) -> dict:
        """Fetch one key and store it. Returns the attempt record. Never raises."""
        attempt = {"attempted_utc": utc_now(), "url": key.url}
        try:
            if key.source == "github":
                self._pace_github()
                headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
                if self._token:
                    headers["Authorization"] = f"Bearer {self._token}"
                resp = self.fetcher.get(key.url, headers=headers)
                try:
                    self._read_github_limits(resp)
                except RateLimited as e:
                    # A real rate-limit response came back: keep it as received, and record
                    # the lookup as rate_limited so the next run resumes it first.
                    attempt.update(outcome="rate_limited", reason=str(e), status=resp.status,
                                   fetched_utc=resp.fetched_utc, headers=_safe_headers(resp.headers))
                    if resp.body:
                        stored_at, new = self.store.store(f"records/{key.path}", "response.json", resp.body,
                                                          self.store.known_blobs(), time_suffix(resp.fetched_utc))
                        attempt.update(stored_at=stored_at, newly_stored=new, sha256=sha256_hex(resp.body),
                                       size_bytes=len(resp.body))
                    self.tally["rate_limited"] += 1
                    self._record(key, attempt)
                    return attempt
            else:
                retries = 0
                while True:
                    self._pace_nvd()
                    resp = self.fetcher.get(key.url)
                    if resp.status == 429 and retries < self.nvd_retries:
                        retries += 1  # NVD busy: wait 35 s and try again (up to 3 times)
                        self.sleep(self.nvd_retry_wait)
                        continue
                    break
                if retries:
                    attempt["retries_after_429"] = retries
                if resp.status in (403, 429):
                    self.nvd_stopped = (f"NVD rate limit reached (HTTP {resp.status}"
                                        + (f" after {retries} retries" if retries else "") + ")")
                    raise RateLimited(self.nvd_stopped)
        except RateLimited as e:
            attempt.update(outcome="rate_limited", reason=str(e))
            self.tally["rate_limited"] += 1
            self._record(key, attempt)
            return attempt
        except CaptureError as e:
            attempt.update(outcome="network_error", reason=str(e))
            self.tally["errors"] += 1
            self._record(key, attempt)
            return attempt
        attempt.update(outcome="fetched", status=resp.status, fetched_utc=resp.fetched_utc,
                       final_url=resp.final_url, headers=_safe_headers(resp.headers))
        blobs = self.store.known_blobs()
        name = "response.json"
        stored_at, new = self.store.store(f"records/{key.path}", name, resp.body or b"",
                                          blobs, time_suffix(resp.fetched_utc)) if resp.body else (None, False)
        attempt.update(size_bytes=len(resp.body), stored_at=stored_at, newly_stored=new)
        if resp.body:
            attempt["sha256"] = sha256_hex(resp.body)
        self.tally["fetched" if new else "unchanged"] += 1
        self._record(key, attempt)
        return attempt

    def _record(self, key: Key, attempt: dict) -> None:
        rel = f"records/{key.path}/MANIFEST.json"
        m = self.store.load_json(rel) or {"schema_version": 1, "source": key.source, "kind": key.kind,
                                          "url": key.url, "attempts": []}
        m["attempts"].append(attempt)
        self.store.save_json(rel, m)

    def last_ok(self, key: Key) -> dict | None:
        m = self.store.load_json(f"records/{key.path}/MANIFEST.json")
        if not m:
            return None
        ok = [a for a in m["attempts"] if a.get("outcome") == "fetched"]
        return ok[-1] if ok else None

    def last_attempt(self, key: Key) -> dict | None:
        m = self.store.load_json(f"records/{key.path}/MANIFEST.json")
        return m["attempts"][-1] if m and m.get("attempts") else None


def _safe_headers(h: dict) -> dict:
    keep = ("content-type", "etag", "last-modified", "date", "x-ratelimit-limit", "x-ratelimit-remaining",
            "x-ratelimit-reset", "x-ratelimit-used", "retry-after", "x-github-request-id")
    return {k: v for k, v in h.items() if k.lower() in keep}


# ---------------------------------------------------------------------------
# Planning a run
# ---------------------------------------------------------------------------
def default_branch_from(rf: RecordFetcher, key: Key) -> str | None:
    a = rf.last_ok(key)
    if not a or not a.get("stored_at"):
        return None
    try:
        v = json.loads(rf.store.read_bytes(a["stored_at"]))
        b = v.get("default_branch") if isinstance(v, dict) else None
        return b if isinstance(b, str) and b else None
    except (ValueError, UnicodeDecodeError):
        return None


def choose_sample(finding_ids: list[str], must_include: str = "ANT-2026-87DJGDRB",
                  n: int = config.SAMPLE_FINDINGS) -> list[str]:
    """wolfSSL plus the first n-1 other finding IDs in sorted order (the same every time)."""
    others = sorted(i for i in finding_ids if i != must_include)
    chosen = ([must_include] if must_include in finding_ids else []) + others
    return chosen[:n]


def run_lookups(root: Path, findings: dict[str, dict], rf: RecordFetcher,
                sample_only: bool = False, unauth_rf: RecordFetcher | None = None) -> dict:
    """findings: finding ID -> {"cve_ids", "ghsa_ids", "fix_links", "advisory_links"}.
    Looks up never-fetched and rate-limited keys first, then refreshes the rest.
    Returns a tally; never raises."""
    ids = choose_sample(list(findings)) if sample_only else sorted(findings)
    planned: list[Key] = []
    seen = set()

    def add(k):
        if k.path not in seen:
            seen.add(k.path)
            planned.append(k)
    for fid in ids:
        f = findings[fid]
        for k in keys_for_ids(f.get("cve_ids", []), f.get("ghsa_ids", []), rf.github_api, rf.nvd_api):
            add(k)
        t = fix_targets(f.get("fix_links", []), f.get("advisory_links", []))
        for k in fix_keys(t, None, rf.github_api):
            add(k)

    def priority(k):
        last = rf.last_attempt(k)
        ok = rf.last_ok(k)
        if last and last.get("outcome") == "rate_limited":
            return (0, k.path)          # stopped by a rate limit last time: resume these first
        if ok is None:
            return (1, k.path)          # never fetched (or only failed)
        if last and last.get("outcome") != "fetched":
            return (2, k.path)          # failed last time
        return (3, ok.get("fetched_utc") or "", k.path)  # refresh, oldest first
    planned.sort(key=priority)
    # repositories first within each priority group, so compares can follow
    planned.sort(key=lambda k: (priority(k)[0], k.kind != "repo"))
    for k in planned:
        rf.fetch(k)
    # second pass: compare each fix commit with its repository's default branch
    for fid in ids:
        f = findings[fid]
        t = fix_targets(f.get("fix_links", []), f.get("advisory_links", []))
        if t["commit"]:
            o, r, _ = t["commit"]
            branch = default_branch_from(rf, repo_keys(o, r, rf.github_api))
            for k in fix_keys(t, branch, rf.github_api):
                if k.kind == "compare" and k.path not in seen:
                    seen.add(k.path)
                    rf.fetch(k)
    unauth_tally = refused_followups(root, {i: findings[i] for i in ids}, rf, unauth_rf)
    return {**rf.tally, "findings": len(ids), "sample_only": sample_only,
            "sample_ids": ids if sample_only else None,
            "github_stopped": rf.github_stopped, "nvd_stopped": rf.nvd_stopped, "without_token": unauth_tally}


def unauthenticated_fetcher(root: Path, rf: RecordFetcher) -> RecordFetcher:
    """A RecordFetcher that never sends a token: its fetcher may send credentials nowhere."""
    return RecordFetcher(root, token=None, github_api=rf.github_api, nvd_api=rf.nvd_api, sleep=rf.sleep,
                         clock=rf.clock, wall=rf.wall, stop_below=0, spread=False,
                         fetcher=Fetcher(credential_destinations=frozenset(),  # never sends a token
                                         robots_exempt_hosts=rf.fetcher.robots_exempt_hosts,
                                         min_interval=rf.fetcher.min_interval))


def _fresh(rf: RecordFetcher, key: Key, days: int) -> bool:
    ok = rf.last_ok(key)
    if not ok or not ok.get("fetched_utc"):
        return False
    from datetime import datetime, timedelta
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    try:
        then = datetime.strptime(ok["fetched_utc"], fmt)
        now = datetime.strptime(utc_now(), fmt)
    except ValueError:
        return False
    return now - then < timedelta(days=days)


def refused_followups(root: Path, findings: dict[str, dict], rf: RecordFetcher,
                      unauth_rf: RecordFetcher | None = None) -> dict:
    """For GHSA IDs whose global-advisory lookup GitHub refused for the token (HTTP 403):
    1. the repository advisory, with the token, for the repository the card links to;
    2. WITHOUT the token, one request per 70 s, stopping at the first rate-limit answer and
       resumed on the next run: the global request (to confirm there is no global entry), and
       the repository advisory again where the token was refused there too."""
    from .records_read import RecordReader
    reader = RecordReader(root, rf.github_api, rf.nvd_api)
    unauth_rf = unauth_rf or unauthenticated_fetcher(root, rf)
    refused, repo_of = [], {}
    for f in findings.values():
        repo = card_repository(f.get("fix_links", []), f.get("advisory_links", []))
        for g in f.get("ghsa_ids", []):
            if reader.global_token_status(g) == "github_refused_token" and g not in repo_of:
                refused.append(g)
                repo_of[g] = repo
    refused.sort()
    # 1. repository advisories with the token (normal pacing)
    for g in refused:
        if repo_of[g]:
            rf.fetch(repo_advisory_key(*repo_of[g], g, rf.github_api))
    # 2. requests without the token, rate-limited first, then never made, then due again
    todo = []
    for g in refused:
        k = global_unauth_key(g, rf.github_api)
        if not _fresh(unauth_rf, k, config.UNAUTH_RECHECK_DAYS):
            todo.append(k)
        if repo_of[g] and reader.repo_token_status(*repo_of[g], g) == "github_refused_token":
            k2 = repo_advisory_key(*repo_of[g], g, rf.github_api, unauthenticated=True)
            if not _fresh(unauth_rf, k2, config.UNAUTH_RECHECK_DAYS):
                todo.append(k2)

    def prio(k):
        last = unauth_rf.last_attempt(k)
        return (0 if last and last.get("outcome") == "rate_limited" else 1 if not unauth_rf.last_ok(k) else 2, k.path)
    todo.sort(key=prio)
    start, last, made = rf.clock(), None, 0
    for k in todo:
        if unauth_rf.github_stopped:
            unauth_rf.fetch(k)  # recorded as rate_limited, resumed first next run
            continue
        if rf.clock() - start > config.UNAUTH_BUDGET_SECONDS:
            break  # the rest wait for the next run
        if last is not None:
            wait = config.UNAUTH_GAP_SECONDS - (rf.clock() - last)
            if wait > 0:
                rf.sleep(wait)
        last = rf.clock()
        unauth_rf.fetch(k)
        made += 1
    return {"refused_global": len(refused), "requests_made": made, "planned": len(todo),
            "stopped": unauth_rf.github_stopped}
