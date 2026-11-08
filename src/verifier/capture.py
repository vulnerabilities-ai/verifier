"""Daily capture of the dashboard (spec rule R1), the one-time backfill of
Anthropic's own archived snapshots (quirk 10), and the monthly copy of the
disclosure policy page (rule R5)."""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from urllib.parse import urljoin

from . import config
from .net import CaptureError, Fetcher, Response, sha256_hex, utc_now
from .store import Archive

BACKFILL_NOTE = (
    "Copy of Anthropic's own archived snapshot. Our fetch time is when we copied "
    "it, not evidence of when we first saw anything; these files are excluded "
    "from first-seen."
)


# --------------------------------------------------------------------------
# validation
# --------------------------------------------------------------------------
def validate(resp: Response, kind: str) -> None:
    """Fail loudly on errors, empty files or an unexpected format. Never guess."""
    if resp.status != 200:
        raise CaptureError(f"{resp.url} returned HTTP {resp.status} (expected 200).")
    if not resp.body or not resp.body.strip():
        raise CaptureError(f"{resp.url} returned an empty file.")
    if kind == "json":
        try:
            json.loads(resp.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise CaptureError(
                f"{resp.url} is not valid JSON ({e}). The format may have changed.") from e
    elif kind == "html":
        head = resp.body[:4096].lower()
        if b"<html" not in head and b"<!doctype html" not in head:
            raise CaptureError(
                f"{resp.url} does not look like an HTML page. The format may have changed.")


def file_entry(name: str, resp: Response) -> dict:
    return {
        "name": name,
        "url": resp.url,
        "final_url": resp.final_url,
        "status": resp.status,
        "fetched_utc": resp.fetched_utc,
        "etag": resp.header("ETag"),
        "last_modified": resp.header("Last-Modified"),
        "content_type": resp.header("Content-Type"),
        "size_bytes": len(resp.body),
        "sha256": sha256_hex(resp.body),
        "headers": resp.headers,
    }


def time_suffix(ts: str) -> str:
    # "2026-11-09T14:23:01Z" -> "T142301Z"
    return "T" + ts[11:19].replace(":", "") + "Z"


# --------------------------------------------------------------------------
# Internet Archive
# --------------------------------------------------------------------------
_WAYBACK_TS = re.compile(r"/web/(\d{14})")


def save_page_now(fetcher: Fetcher, url: str, spn_prefix: str = config.SPN_PREFIX,
                  retry_wait: float = 15.0) -> dict:
    """Ask the Internet Archive to save `url`. Record what it returns, as is.

    The Archive may hand back a recent existing snapshot instead of a new one;
    we record the timestamp it returns and do not treat that as an error.
    """
    request_url = spn_prefix + url
    attempts = []
    for attempt in (1, 2):
        requested = utc_now()
        try:
            resp = fetcher.get(request_url, timeout=config.SPN_TIMEOUT_SECONDS)
            candidates = [resp.final_url, resp.header("Content-Location") or "",
                          resp.header("Location") or ""]
            snap = next((c for c in candidates if _WAYBACK_TS.search(c)), None)
            info = {"attempt": attempt, "requested_utc": requested, "status": resp.status,
                    "final_url": resp.final_url,
                    "content_location": resp.header("Content-Location")}
            if resp.status < 400 and snap:
                ts = _WAYBACK_TS.search(snap).group(1)
                snapshot_url = snap if snap.startswith("http") else urljoin("https://web.archive.org/", snap)
                ts_iso = f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}T{ts[8:10]}:{ts[10:12]}:{ts[12:14]}Z"
                result = {
                    "ok": True,
                    "request_url": request_url,
                    "requested_utc": requested,
                    "snapshot_url": snapshot_url,
                    "snapshot_timestamp": ts,
                    "snapshot_timestamp_utc": ts_iso,
                    "attempts": attempts + [info],
                }
                if ts_iso < requested[:-4]:  # older than the minute we asked
                    result["note"] = ("The Archive returned a snapshot dated before this "
                                      "request (it may have reused a recent snapshot). "
                                      "Recorded as returned.")
                return result
            info["error"] = "no snapshot address in the response"
        except CaptureError as e:
            info = {"attempt": attempt, "requested_utc": requested, "error": str(e)}
        attempts.append(info)
        if attempt == 1:
            time.sleep(retry_wait)
    return {"ok": False, "request_url": request_url, "attempts": attempts,
            "error": attempts[-1].get("error", "failed")}


# --------------------------------------------------------------------------
# main daily capture
# --------------------------------------------------------------------------
@dataclass
class RunInfo:
    run_id: str = "local"
    trigger: str = "manual"
    mode: str = "normal"  # "normal" or "test"
    started_utc: str = field(default_factory=utc_now)


def target_urls(base_url: str) -> list[tuple[str, str, str]]:
    return [(name, urljoin(base_url, path), kind) for name, path, kind in config.TARGETS]


def fetch_targets(fetcher: Fetcher, base_url: str) -> list[tuple[str, Response]]:
    out = []
    for name, url, kind in target_urls(base_url):
        resp = fetcher.get(url)
        validate(resp, kind)
        out.append((name, resp))
    return out


def store_daily(archive: Archive, fetched: list[tuple[str, Response]], run: RunInfo,
                base_url: str, robots: dict, ia: dict | None) -> dict:
    """Write today's files (only changed ones), the manifest, and latest.json."""
    first_fetch = fetched[0][1].fetched_utc
    y, m, d = first_fetch[0:4], first_fetch[5:7], first_fetch[8:10]
    folder = f"captures/{y}/{m}/{d}"
    blobs = archive.known_blobs()
    suffix = time_suffix(first_fetch)
    files = []
    for name, resp in fetched:
        stored_at, new = archive.store(folder, name, resp.body, blobs, suffix)
        entry = file_entry(name, resp)
        entry["stored_at"] = stored_at
        entry["newly_stored"] = new
        files.append(entry)

    manifest_rel = f"{folder}/MANIFEST.json"
    manifest = archive.load_json(manifest_rel) or {
        "schema_version": 1,
        "program": config.PROGRAM,
        "date_utc": f"{y}-{m}-{d}",
        "about": ("Raw files exactly as served. Each run lists what was fetched. "
                  "When bytes were identical to a copy already in the archive, "
                  "stored_at points to that copy instead of saving a duplicate."),
        "runs": [],
    }
    run_entry = {
        "run_id": run.run_id,
        "trigger": run.trigger,
        "started_utc": run.started_utc,
        "finished_utc": utc_now(),
        "base_url": base_url,
        "user_agent": config.USER_AGENT,
        "robots": robots,
        "files": files,
        "internet_archive": ia,
    }
    manifest["runs"].append(run_entry)
    archive.save_json(manifest_rel, manifest)

    archive.save_json("captures/latest.json", {
        "last_capture_utc": first_fetch,
        "last_capture_date": f"{y}-{m}-{d}",
        "manifest": manifest_rel,
        "files": {f["name"]: {"sha256": f["sha256"], "stored_at": f["stored_at"]} for f in files},
    })
    return {"manifest": manifest_rel, "files": files}


# --------------------------------------------------------------------------
# backfill of Anthropic's own archived snapshots (one-time)
# --------------------------------------------------------------------------
def snapshot_folder_url(base_url: str, label: str) -> str:
    return urljoin(base_url, f"snapshots/{label}/")


def backfill_rel(label: str) -> str:
    return f"captures/anthropic-archive/{label}"


def backfill_due(archive: Archive) -> list[str]:
    return [lbl for lbl in config.ANTHROPIC_SNAPSHOT_LABELS
            if not archive.exists(f"{backfill_rel(lbl)}/MANIFEST.json")]


_JSON_LINK = re.compile(r"""["']([^"'\s<>]+?\.json)(?:[?#][^"']*)?["']""")


def backfill_one(archive: Archive, fetcher: Fetcher, base_url: str, label: str) -> dict:
    folder_url = snapshot_folder_url(base_url, label)
    index = fetcher.get(folder_url + "index.html")
    validate(index, "html")

    text = index.body.decode("utf-8", errors="replace")
    linked = set()
    for link in _JSON_LINK.findall(text):
        full = urljoin(index.url, link)
        if full.startswith(folder_url):
            linked.add(full[len(folder_url):])
    wanted = sorted(linked | set(config.SNAPSHOT_DEFAULT_DATA))

    fetched: list[tuple[str, Response]] = [("index.html", index)]
    absent = []
    for rel in wanted:
        if ".." in rel.split("/"):
            continue
        resp = fetcher.get(folder_url + rel)
        if resp.status == 404 and rel not in linked:
            absent.append({"path": rel, "url": resp.url, "status": 404,
                           "fetched_utc": resp.fetched_utc})
            continue
        validate(resp, "json")
        fetched.append((rel, resp))

    folder = backfill_rel(label)
    blobs = archive.known_blobs()
    files = []
    for rel, resp in fetched:
        stored_at, new = archive.store(folder, rel, resp.body, blobs, time_suffix(resp.fetched_utc))
        entry = file_entry(rel, resp)
        entry.update(stored_at=stored_at, newly_stored=new)
        files.append(entry)
    manifest = {
        "schema_version": 1,
        "program": config.PROGRAM,
        "kind": "anthropic-archive-backfill",
        "anthropic_snapshot_label": label,
        "our_fetch_utc": index.fetched_utc,
        "note": BACKFILL_NOTE,
        "source_url": folder_url + "index.html",
        "user_agent": config.USER_AGENT,
        "files": files,
        "not_present": absent,
    }
    archive.save_json(f"{folder}/MANIFEST.json", manifest)
    return manifest


# --------------------------------------------------------------------------
# monthly copy of the disclosure policy page
# --------------------------------------------------------------------------
def policy_rel(month: str) -> str:
    return f"captures/policy/{month}"


def policy_due(archive: Archive, now_utc: str) -> bool:
    return not archive.exists(f"{policy_rel(now_utc[:7])}/MANIFEST.json")


def capture_policy(archive: Archive, fetcher: Fetcher, url: str = config.POLICY_URL) -> dict:
    resp = fetcher.get(url)
    validate(resp, "html")
    month = resp.fetched_utc[:7]
    folder = policy_rel(month)
    blobs = archive.known_blobs()
    stored_at, new = archive.store(folder, "policy.html", resp.body, blobs,
                                   time_suffix(resp.fetched_utc))
    entry = file_entry("policy.html", resp)
    entry.update(stored_at=stored_at, newly_stored=new)
    manifest = {
        "schema_version": 1,
        "kind": "disclosure-policy-monthly",
        "month": month,
        "our_fetch_utc": resp.fetched_utc,
        "user_agent": config.USER_AGENT,
        "files": [entry],
    }
    archive.save_json(f"{folder}/MANIFEST.json", manifest)
    return manifest
