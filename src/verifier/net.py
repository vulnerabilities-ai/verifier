"""Polite HTTP fetching with robots.txt checks.

Rules (spec R1 and "Conduct toward the source"):
- identify ourselves with a clear User-Agent;
- at most one request per second to any host;
- read robots.txt for every host before touching it, and stop if a path we
  need is disallowed;
- fail loudly on errors.
"""

from __future__ import annotations

import hashlib
import time
import urllib.error
import urllib.request
import urllib.robotparser
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit

from . import config


class CaptureError(Exception):
    """A fetch or validation failed. The run must end red."""


class RobotsDisallowed(CaptureError):
    """robots.txt disallows a path we need. Stop and ask Jon."""


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class Response:
    url: str
    final_url: str
    status: int
    headers: dict[str, str]
    body: bytes
    fetched_utc: str

    def header(self, name: str) -> str | None:
        for k, v in self.headers.items():
            if k.lower() == name.lower():
                return v
        return None


@dataclass
class RobotsResult:
    host: str
    url: str
    status: int | None
    fetched_utc: str
    sha256: str | None
    checked_urls: dict[str, bool] = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "robots_url": self.url,
            "status": self.status,
            "fetched_utc": self.fetched_utc,
            "sha256": self.sha256,
            "checked": self.checked_urls,
        }


# Hosts allowed to receive the Internet Archive keys (exact host names).
CREDENTIAL_HOSTS = frozenset({"web.archive.org", "archive.org"})
SENSITIVE_HEADERS = ("Authorization", "Cookie", "Proxy-Authorization")


def credential_destination(url: str) -> str:
    """scheme://host[:port] of a URL, lower-cased: what must match to carry keys."""
    parts = urlsplit(url)
    return f"{parts.scheme.lower()}://{parts.netloc.lower()}"


class CredentialSafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follows redirects, but drops credentials unless the new address is an
    allowed host reached with the same scheme.

    Python's default redirect handler copies request headers, including
    Authorization, to whatever address a server redirects to. This handler
    removes them when the redirect points anywhere else: a different host,
    a different port, or from https to http.
    """

    def __init__(self, allowed: frozenset[str]):
        super().__init__()
        self.allowed = allowed  # set of "scheme://host[:port]"
        self.dropped: list[str] = []  # destinations credentials were withheld from

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        new = super().redirect_request(req, fp, code, msg, headers, newurl)
        if new is None:
            return None
        had = [h for h in SENSITIVE_HEADERS if req.has_header(h) or new.has_header(h)]
        dest = credential_destination(new.full_url)
        same_scheme = urlsplit(req.full_url).scheme.lower() == urlsplit(new.full_url).scheme.lower()
        if had and not (dest in self.allowed and same_scheme):
            for h in SENSITIVE_HEADERS:
                new.remove_header(h)
            self.dropped.append(dest)
        return new


class Fetcher:
    def __init__(self, user_agent: str = config.USER_AGENT,
                 min_interval: float = config.MIN_INTERVAL_SECONDS,
                 timeout: float = config.TIMEOUT_SECONDS,
                 credential_destinations: frozenset[str] | None = None):
        self.user_agent = user_agent
        self.min_interval = min_interval
        self.timeout = timeout
        self._last_request: dict[str, float] = {}
        self._robots: dict[str, tuple[urllib.robotparser.RobotFileParser, RobotsResult]] = {}
        if credential_destinations is None:
            credential_destinations = frozenset(f"https://{h}" for h in CREDENTIAL_HOSTS)
        self.credential_destinations = frozenset(credential_destinations)
        self.redirects = CredentialSafeRedirectHandler(self.credential_destinations)
        self.opener = urllib.request.build_opener(self.redirects)

    # -- politeness -------------------------------------------------------
    def _wait_turn(self, url: str) -> None:
        host = urlsplit(url).netloc
        last = self._last_request.get(host)
        if last is not None:
            gap = time.monotonic() - last
            if gap < self.min_interval:
                time.sleep(self.min_interval - gap)
        self._last_request[host] = time.monotonic()

    def _raw_get(self, url: str, timeout: float | None = None, *, method: str = "GET",
                 data: bytes | None = None, headers: dict[str, str] | None = None) -> Response:
        """One HTTP request. Request headers (which may carry credentials) are
        never stored in the Response or put into error messages."""
        self._wait_turn(url)
        h = {"User-Agent": self.user_agent}
        h.update(headers or {})
        if any(k.lower() in {x.lower() for x in SENSITIVE_HEADERS} for k in h) \
                and credential_destination(url) not in self.credential_destinations:
            raise CaptureError(f"Refusing to send credentials to {credential_destination(url)}: "
                               "not an allowed Internet Archive host.")
        req = urllib.request.Request(url, data=data, headers=h, method=method)
        fetched = utc_now()
        try:
            with self.opener.open(req, timeout=timeout or self.timeout) as r:
                body = r.read()
                return Response(url, r.geturl(), r.status, dict(r.headers.items()), body, fetched)
        except urllib.error.HTTPError as e:
            body = e.read() if e.fp else b""
            return Response(url, e.geturl() or url, e.code, dict(e.headers.items()) if e.headers else {}, body, fetched)
        except (urllib.error.URLError, OSError) as e:
            reason = getattr(e, "reason", e)
            raise CaptureError(f"Could not reach {url}: {type(reason).__name__}: {reason}") from None

    # -- robots.txt -------------------------------------------------------
    def _robots_for(self, url: str):
        parts = urlsplit(url)
        host = parts.netloc
        if host in self._robots:
            return self._robots[host]
        robots_url = f"{parts.scheme}://{host}/robots.txt"
        resp = self._raw_get(robots_url)
        rp = urllib.robotparser.RobotFileParser(robots_url)
        if resp.status == 200:
            rp.parse(resp.body.decode("utf-8", errors="replace").splitlines())
        elif resp.status in (401, 403):
            rp.disallow_all = True
        elif 400 <= resp.status < 500:
            rp.allow_all = True  # no robots.txt: everything allowed
        else:
            raise CaptureError(
                f"Could not read {robots_url} (HTTP {resp.status}); "
                "not fetching anything from that host until it can be read.")
        result = RobotsResult(host, robots_url, resp.status, resp.fetched_utc,
                              sha256_hex(resp.body) if resp.status == 200 else None)
        self._robots[host] = (rp, result)
        return self._robots[host]

    def check_robots(self, urls: list[str]) -> dict[str, dict]:
        """Check every URL against its host's robots.txt before fetching anything.

        Raises RobotsDisallowed listing every disallowed URL.
        """
        disallowed = []
        for u in urls:
            rp, result = self._robots_for(u)
            ok = rp.can_fetch(config.UA_TOKEN, u)
            result.checked_urls[u] = ok
            if not ok:
                disallowed.append(u)
        if disallowed:
            raise RobotsDisallowed(
                "robots.txt disallows: " + ", ".join(disallowed)
                + ". The pipeline stopped. Jon must decide how to proceed.")
        return {h: r.as_dict() for h, (_, r) in self._robots.items()}

    def robots_summary(self) -> dict[str, dict]:
        return {h: r.as_dict() for h, (_, r) in self._robots.items()}

    # -- fetching ---------------------------------------------------------
    def get(self, url: str, timeout: float | None = None, *, method: str = "GET",
            data: bytes | None = None, headers: dict[str, str] | None = None) -> Response:
        rp, result = self._robots_for(url)
        if not rp.can_fetch(config.UA_TOKEN, url):
            raise RobotsDisallowed(f"robots.txt disallows {url}. Jon must decide how to proceed.")
        result.checked_urls.setdefault(url, True)
        return self._raw_get(url, timeout, method=method, data=data, headers=headers)
