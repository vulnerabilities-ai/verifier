"""Tiny local web servers that stand in for Anthropic's site, the Internet
Archive and anthropic.com during tests, so tests never touch the real sites."""

from __future__ import annotations

import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"

HTML = b"<!doctype html><html><body>dashboard</body></html>"


@dataclass
class Req:
    path: str
    method: str
    headers: dict
    body: bytes


class FakeSite:
    """routes: path -> (status, body, headers) or a callable(Req) returning that.
    A path ending in '*' matches by prefix."""

    def __init__(self, routes: dict | None = None):
        self.routes = dict(routes or {})
        self.requests: list[Req] = []
        site = self

        class Handler(BaseHTTPRequestHandler):
            def _handle(self):
                n = int(self.headers.get("Content-Length") or 0)
                req = Req(self.path, self.command, dict(self.headers.items()),
                          self.rfile.read(n) if n else b"")
                site.requests.append(req)
                route = site.routes.get(self.path)
                if route is None:
                    for prefix, r in site.routes.items():
                        if prefix.endswith("*") and self.path.startswith(prefix[:-1]):
                            route = r
                            break
                if callable(route):
                    route = route(req)
                if route == "drop":  # simulate "connection refused"-like failure
                    self.close_connection = True
                    self.wfile.flush()
                    self.connection.close()
                    return
                status, body, headers = route if route else (404, b"not found", {})
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = _handle

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def paths(self) -> list[str]:
        return [r.path for r in self.requests]

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def dashboard_routes(payload: bytes = b'{"ok": 1}', ledger: bytes = b"[]",
                     robots: bytes = b"User-agent: *\nAllow: /\n") -> dict:
    h = {"Content-Type": "text/html", "ETag": '"abc"', "Last-Modified": "Fri, 02 Oct 2026 19:47:20 GMT"}
    j = {"Content-Type": "application/json"}
    return {
        "/robots.txt": (200, robots, {}),
        "/2026/cvd/": (200, HTML, h),
        "/2026/cvd/data/payload.json": (200, payload, j),
        "/2026/cvd/data/ledger.json": (200, ledger, j),
        "/2026/cvd/about/index.html": (200, b"<html>about</html>", h),
        "/2026/cvd/archive/index.html": (200, b"<html>archive</html>", h),
    }


def snapshot_routes(labels: list[str]) -> dict:
    r = {}
    for lbl in labels:
        page = (f'<html><a href="data/payload.json">p</a>'
                f'<script>fetch("data/extra.json")</script></html>').encode()
        r[f"/2026/cvd/snapshots/{lbl}/index.html"] = (200, page, {})
        r[f"/2026/cvd/snapshots/{lbl}/data/payload.json"] = (200, f'{{"label": "{lbl}"}}'.encode(), {})
        r[f"/2026/cvd/snapshots/{lbl}/data/extra.json"] = (200, b'{"extra": true}', {})
        # data/ledger.json deliberately absent (404) to test "not present"
    return r


def policy_routes(robots: bytes = b"User-agent: *\nAllow: /\n") -> dict:
    return {
        "/robots.txt": (200, robots, {}),
        "/coordinated-vulnerability-disclosure": (200, b"<html>policy</html>", {}),
    }


def now_ts() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")


class FakeArchive(FakeSite):
    """A pretend Internet Archive (Save Page Now, status, availability, id_ copies).

    behaviour: "ok" new snapshot; "reuse" returns self.reuse_ts; "busy" 429;
    "drop" connection dropped; "error-but-saved" HTTP 520 yet a snapshot is made.
    `content` maps original URL -> bytes the Archive holds (for id_ copies).
    """

    def __init__(self, content: dict[str, bytes], robots: bytes = b"User-agent: *\nAllow: /\n"):
        self.behaviour = "ok"
        self.behaviour_for: dict[str, str] = {}  # per original URL override
        self.reuse_ts = "20261030191525"
        self.content = content
        self.raw_override: dict[str, bytes] = {}
        self.snapshots: dict[str, list[str]] = {}
        self.jobs: dict[str, str] = {}
        self.auth_seen: list[str] = []
        super().__init__({
            "/robots.txt": (200, robots, {}),
            "/save/status/*": self._status,
            "/save/*": self._save_get,
            "/save": self._save_post,
            "/web/*": self._web,
            "/wayback/available*": self._available,
        })

    def _snap(self, url: str, ts: str | None = None) -> str:
        ts = ts or now_ts()
        self.snapshots.setdefault(url, []).append(ts)
        return ts

    def _outcome(self, url):
        b = self.behaviour_for.get(url, self.behaviour)
        if b == "busy":
            return (429, b"Too Many Requests", {})
        if b == "drop":
            return "drop"
        if b == "error-but-saved":
            self._snap(url)
            return (520, b"error", {})
        return None

    def _save_get(self, req: Req):
        url = req.path[len("/save/"):]
        bad = self._outcome(url)
        if bad:
            return bad
        b = self.behaviour_for.get(url, self.behaviour)
        ts = self.reuse_ts if b == "reuse" else self._snap(url)
        return (302, b"", {"Location": f"/web/{ts}/{url}"})

    def _save_post(self, req: Req):
        self.auth_seen.append(req.headers.get("Authorization", ""))
        url = parse_qs(req.body.decode())["url"][0]
        bad = self._outcome(url)
        if bad:
            return bad
        job = f"spn2-{len(self.jobs) + 1}"
        b = self.behaviour_for.get(url, self.behaviour)
        self.jobs[job] = self.reuse_ts if b == "reuse" else self._snap(url)
        return (200, json.dumps({"url": url, "job_id": job}).encode(), {})

    def _status(self, req: Req):
        self.auth_seen.append(req.headers.get("Authorization", ""))
        job = req.path.rsplit("/", 1)[1]
        return (200, json.dumps({"status": "success", "timestamp": self.jobs[job]}).encode(), {})

    def _web(self, req: Req):
        rest = req.path[len("/web/"):]
        stamp, url = rest.split("/", 1)
        if stamp.endswith("id_"):
            data = self.raw_override.get(url, self.content.get(url))
            return (200, data, {}) if data is not None else (404, b"", {})
        return (200, b"<html>archived</html>", {})

    def _available(self, req: Req):
        q = parse_qs(urlsplit(req.path).query)
        url, ts = q["url"][0], q.get("timestamp", [""])[0]
        snaps = sorted(self.snapshots.get(url, []))
        if not snaps:
            return (200, b'{"archived_snapshots": {}}', {})
        closest = min(snaps, key=lambda s: abs(int(s) - int(ts or s)))
        body = {"archived_snapshots": {"closest": {
            "available": True, "status": "200", "timestamp": closest,
            "url": f"http://web.archive.org/web/{closest}/{url}"}}}
        return (200, json.dumps(body).encode(), {})
