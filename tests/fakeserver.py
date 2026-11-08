"""A tiny local web server that stands in for Anthropic's site, the Internet
Archive and anthropic.com during tests, so tests never touch the real sites."""

from __future__ import annotations

import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1,localhost"

HTML = b"<!doctype html><html><body>dashboard</body></html>"


class FakeSite:
    """routes: path -> (status, body bytes, extra headers dict)."""

    def __init__(self, routes: dict | None = None):
        self.routes = dict(routes or {})
        self.requests: list[tuple[str, str]] = []  # (path, user-agent)
        site = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                site.requests.append((self.path, self.headers.get("User-Agent", "")))
                route = site.routes.get(self.path)
                if route is None:
                    for prefix, handler in site.routes.items():
                        if prefix.endswith("*") and self.path.startswith(prefix[:-1]):
                            route = handler(self.path) if callable(handler) else handler
                            break
                status, body, headers = route if route else (404, b"not found", {})
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

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


def archive_routes(robots: bytes = b"User-agent: *\nAllow: /\n", ts: str = "20261030191525") -> dict:
    def save(path):
        target = path[len("/save/"):]
        return (302, b"", {"Location": f"/web/{ts}/{target}"})
    return {
        "/robots.txt": (200, robots, {}),
        "/save/*": save,
        "/web/*": (200, b"<html>archived</html>", {}),
    }


def policy_routes(robots: bytes = b"User-agent: *\nAllow: /\n") -> dict:
    return {
        "/robots.txt": (200, robots, {}),
        "/coordinated-vulnerability-disclosure": (200, b"<html>policy</html>", {}),
    }
