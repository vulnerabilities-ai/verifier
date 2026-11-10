"""Internet Archive receipts.

For each capture we ask the Archive's Save Page Now to save the dashboard,
ledger.json and payload.json. The Archive is often busy, so:

- requests are spaced at least 20 seconds apart, and failed ones are retried
  in rounds after 1, 3 and 10 minutes, within a total time budget;
- HTTP 429 is recorded as "Archive busy";
- after every failed or ambiguous request we ask the Archive's availability
  API whether a snapshot dated after our fetch exists anyway (on Nov 8 a
  snapshot was created two seconds after a request that returned an error);
- for every receipt we fetch the Archive's raw copy (the "id_" address) and
  compare its SHA-256 with ours.

Authenticated Save Page Now is used when IA_ACCESS_KEY and IA_SECRET_KEY are
set; otherwise anonymous mode. The keys are only ever placed in a request
header. They are never written to a file, a manifest, a log or an error message.
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from urllib.parse import quote, urlencode

from . import config
from .net import CaptureError, Fetcher, RobotsDisallowed, sha256_hex, utc_now

_WAYBACK_TS = re.compile(r"/web/(\d{14})")


def ts_to_iso(ts: str) -> str:
    return f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}T{ts[8:10]}:{ts[10:12]}:{ts[12:14]}Z"


def iso_to_ts(iso: str) -> str:
    return iso[0:4] + iso[5:7] + iso[8:10] + iso[11:13] + iso[14:16] + iso[17:19]


def seconds_between(earlier_iso: str, later_iso: str) -> int:
    f = "%Y-%m-%dT%H:%M:%SZ"
    a = datetime.strptime(earlier_iso, f).replace(tzinfo=timezone.utc)
    b = datetime.strptime(later_iso, f).replace(tzinfo=timezone.utc)
    return int((b - a).total_seconds())


class ArchiveClient:
    def __init__(self, fetcher: Fetcher, *,
                 wayback_base: str = config.WAYBACK_BASE,
                 availability_url: str = config.AVAILABILITY_URL,
                 access_key: str | None = None, secret_key: str | None = None,
                 spacing: float = config.ARCHIVE_SPACING_SECONDS,
                 backoff: tuple[float, ...] = config.ARCHIVE_BACKOFF_SECONDS,
                 budget: float = config.ARCHIVE_BUDGET_SECONDS,
                 poll_interval: float = config.ARCHIVE_POLL_INTERVAL_SECONDS,
                 poll_timeout: float = config.ARCHIVE_POLL_TIMEOUT_SECONDS,
                 window: int = config.ARCHIVE_RECEIPT_WINDOW_SECONDS,
                 sleep=time.sleep, clock=time.monotonic):
        self.fetcher = fetcher
        self.wayback_base = wayback_base
        self.availability_url = availability_url
        self._auth = (f"LOW {access_key}:{secret_key}"
                      if access_key and secret_key else None)
        self.spacing, self.backoff, self.budget = spacing, tuple(backoff), budget
        self.poll_interval, self.poll_timeout = poll_interval, poll_timeout
        self.window = window
        self.sleep, self.clock = sleep, clock
        self._last_save: float | None = None
        # Optional callable(name, snapshot_ts, our_sha256, archive_bytes) -> dict,
        # set by the runner to save and describe raw-copy mismatches.
        self.on_mismatch = None

    def __repr__(self) -> str:  # never show credentials
        return f"<ArchiveClient mode={self.mode}>"

    @property
    def mode(self) -> str:
        return "authenticated" if self._auth else "anonymous"

    # -- addresses (also used for the robots.txt preflight) ------------------
    def save_url(self, url: str) -> str:
        return self.wayback_base + "save" if self._auth else self.wayback_base + "save/" + url

    def raw_url(self, ts: str, url: str) -> str:
        return f"{self.wayback_base}web/{ts}id_/{url}"

    def availability_query(self, url: str, after_iso: str) -> str:
        return self.availability_url + "?" + urlencode({"url": url, "timestamp": iso_to_ts(after_iso)})

    def planned_urls(self, urls: list[str]) -> list[str]:
        out = []
        for u in urls:
            out.append(self.save_url(u))
            if self._auth:
                out.append(self.wayback_base + "save/status/job")
            out.append(self.raw_url("20260101000000", u))
            out.append(self.availability_query(u, "2026-01-01T00:00:00Z"))
        return out

    # -- one save request ------------------------------------------------------
    def _space(self) -> None:
        if self._last_save is not None:
            gap = self.clock() - self._last_save
            if gap < self.spacing:
                self.sleep(self.spacing - gap)
        self._last_save = self.clock()

    def save(self, url: str) -> dict:
        self._space()
        info = {"requested_utc": utc_now(), "mode": self.mode}
        try:
            return {**info, **(self._save_auth(url) if self._auth else self._save_anon(url))}
        except RobotsDisallowed:
            raise
        except CaptureError as e:
            return {**info, "outcome": "error", "error": str(e)}

    @staticmethod
    def _busy(status: int) -> dict:
        return {"outcome": "busy", "status": status, "error": "Archive busy (HTTP 429)"}

    def _save_anon(self, url: str) -> dict:
        resp = self.fetcher.get(self.save_url(url), timeout=config.SPN_TIMEOUT_SECONDS)
        if resp.status == 429:
            return self._busy(429)
        candidates = [resp.final_url, resp.header("Content-Location") or "", resp.header("Location") or ""]
        snap = next((c for c in candidates if _WAYBACK_TS.search(c)), None)
        if resp.status < 400 and snap:
            return {"outcome": "snapshot", "status": resp.status,
                    "snapshot_timestamp": _WAYBACK_TS.search(snap).group(1)}
        return {"outcome": "error", "status": resp.status,
                "error": f"HTTP {resp.status}, no snapshot address in the response"}

    def _save_auth(self, url: str) -> dict:
        headers = {"Accept": "application/json", "Authorization": self._auth}
        resp = self.fetcher.get(self.save_url(url), timeout=config.SPN_TIMEOUT_SECONDS,
                                method="POST", data=urlencode({"url": url}).encode(),
                                headers=headers)
        if resp.status == 429:
            return self._busy(429)
        try:
            body = json.loads(resp.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {"outcome": "error", "status": resp.status,
                    "error": f"HTTP {resp.status}, response was not JSON"}
        job = body.get("job_id")
        if not job:
            return {"outcome": "error", "status": resp.status,
                    "error": str(body.get("message") or body.get("status_ext") or "no job id")[:300]}
        start = self.clock()
        while True:
            self.sleep(self.poll_interval)
            st = self.fetcher.get(f"{self.wayback_base}save/status/{quote(job, safe='')}",
                                  headers=headers)
            if st.status == 429:
                return {**self._busy(429), "job_id": job}
            try:
                s = json.loads(st.body.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                s = {"status": "unreadable"}
            if s.get("status") == "success" and s.get("timestamp"):
                return {"outcome": "snapshot", "job_id": job, "snapshot_timestamp": s["timestamp"]}
            if s.get("status") == "error":
                return {"outcome": "error", "job_id": job,
                        "error": str(s.get("message") or s.get("status_ext") or "error")[:300]}
            if self.clock() - start > self.poll_timeout:
                return {"outcome": "ambiguous", "job_id": job,
                        "error": "The Archive had not finished the capture when we stopped waiting"}

    # -- availability API and raw-copy check -------------------------------------
    def availability(self, url: str, after_iso: str) -> dict:
        """Ask whether a snapshot dated at or after our fetch exists."""
        q = self.availability_query(url, after_iso)
        rec = {"checked_utc": utc_now(), "query": q, "our_fetched_utc": after_iso}
        try:
            resp = self.fetcher.get(q)
        except RobotsDisallowed:
            raise
        except CaptureError as e:
            return {**rec, "result": "error", "error": str(e)}
        rec["status"] = resp.status
        if resp.status == 429:
            return {**rec, "result": "busy", "error": "Archive busy (HTTP 429)"}
        try:
            closest = json.loads(resp.body.decode("utf-8")).get("archived_snapshots", {}).get("closest")
        except (UnicodeDecodeError, json.JSONDecodeError, AttributeError):
            return {**rec, "result": "error", "error": f"HTTP {resp.status}, unreadable response"}
        if not closest or not closest.get("timestamp"):
            return {**rec, "result": "none"}
        ts = str(closest["timestamp"])
        rec.update(closest_timestamp=ts, closest_url=closest.get("url"),
                   closest_status=closest.get("status"))
        delay = seconds_between(after_iso, ts_to_iso(ts))
        if 0 <= delay <= self.window:
            return {**rec, "result": "found_after_our_fetch", "seconds_after_our_fetch": delay}
        return {**rec, "result": "none_after_our_fetch", "seconds_after_our_fetch": delay}

    def raw_check(self, url: str, ts: str, our_sha256: str, name: str | None = None) -> dict:
        raw = self.raw_url(ts, url)
        rec = {"raw_url": raw, "checked_utc": utc_now()}
        try:
            resp = self.fetcher.get(raw)
        except RobotsDisallowed:
            raise
        except CaptureError as e:
            return {**rec, "result": "unavailable", "error": str(e)}
        rec.update(status=resp.status, final_url=resp.final_url)
        if resp.status != 200 or not resp.body:
            return {**rec, "result": "unavailable", "error": f"HTTP {resp.status}"}
        sha = sha256_hex(resp.body)
        rec.update(raw_sha256=sha, result="match" if sha == our_sha256 else "mismatch")
        if sha != our_sha256 and self.on_mismatch is not None:
            # Detail only: the result above stays "mismatch" whatever this finds.
            try:
                rec["diagnostic"] = self.on_mismatch(name or url.rstrip("/").rsplit("/", 1)[-1],
                                                     ts, our_sha256, resp.body)
            except Exception as e:  # noqa: BLE001 - a diagnostic must never break a run
                rec["diagnostic"] = {"error": f"{type(e).__name__}: {e}"}
        m = _WAYBACK_TS.search(resp.final_url or "")
        if m and m.group(1) != ts:
            rec["note"] = f"The Archive served its copy dated {m.group(1)} instead."
        return rec

    def receipt(self, item: dict, ts: str, source: str) -> dict:
        iso = ts_to_iso(ts)
        rec = {
            "source": source,
            "snapshot_timestamp": ts,
            "snapshot_timestamp_utc": iso,
            "snapshot_url": f"{self.wayback_base}web/{ts}/{item['url']}",
            "seconds_after_our_fetch": seconds_between(item["our_fetched_utc"], iso),
        }
        if rec["seconds_after_our_fetch"] < 0:
            rec["reused_existing_snapshot"] = True
            rec["note"] = ("The Archive returned a snapshot dated before our fetch (it reuses "
                           "recent snapshots). It shows what the Archive held then; the raw "
                           "check shows whether it has the same bytes as our copy.")
        rec["raw_check"] = self.raw_check(item["url"], ts, item["our_sha256"], item.get("name"))
        return rec

    # -- the whole archive step for one capture ----------------------------------
    def archive_items(self, items: list[dict]) -> dict:
        """items: dicts with name, url, our_fetched_utc, our_sha256."""
        deadline = self.clock() + self.budget
        states = [{**it, "status": "pending", "attempts": [], "availability_checks": []}
                  for it in items]
        waits = (0,) + self.backoff
        for wait in waits:
            pending = [s for s in states if s["status"] == "pending"]
            if not pending:
                break
            if wait:
                if self.clock() + wait > deadline:
                    break
                self.sleep(wait)
            for s in pending:
                if self.clock() > deadline:
                    break
                res = self.save(s["url"])
                s["attempts"].append(res)
                if res.get("outcome") == "snapshot":
                    s["status"] = "receipt"
                    s["receipt"] = self.receipt(s, res["snapshot_timestamp"], "save-page-now")
                    continue
                av = self.availability(s["url"], s["our_fetched_utc"])
                s["availability_checks"].append(av)
                if av.get("result") == "found_after_our_fetch":
                    s["status"] = "receipt"
                    s["receipt"] = self.receipt(s, av["closest_timestamp"], "availability-api")
        return {
            "mode": self.mode,
            "ok": all(s["status"] == "receipt" for s in states),
            "receipts": sum(1 for s in states if s["status"] == "receipt"),
            "pending": [s["name"] for s in states if s["status"] == "pending"],
            "items": states,
        }
