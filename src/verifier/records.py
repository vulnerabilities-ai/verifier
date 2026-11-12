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
                 nvd_retry_wait: float = config.NVD_RETRY_WAIT_SECONDS, nvd_retries: int = config.NVD_RETRIES):
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
            if gap > 1.0:  # spread the remaining calls over the time to reset
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
                sample_only: bool = False) -> dict:
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
    return {**rf.tally, "findings": len(ids), "sample_only": sample_only,
            "sample_ids": ids if sample_only else None,
            "github_stopped": rf.github_stopped, "nvd_stopped": rf.nvd_stopped}
