"""Receipts found after the run that asked for them.

When an earlier run is still waiting for an Internet Archive receipt, later
runs ask the availability API whether a snapshot dated after that run's fetch
now exists. What they find is APPENDED to the earlier day's MANIFEST.json as a
dated note in "appended_notes". Nothing already written is changed.

The same pass retries raw-copy checks that could not be done at the time.

It also works out whether the Archive has given no receipt at all for several
consecutive capture days, which is the only Archive problem that opens an issue.
"""

from __future__ import annotations

import json
import re
from datetime import date, timedelta

from . import config
from .archive_org import ArchiveClient
from .net import utc_now
from .store import Archive

NOTE_RECEIPT = "late-archive-receipt"
NOTE_RAW = "late-raw-check"
NOTE_DIAG = "archive-raw-diagnostic"


def day_manifests(archive: Archive) -> list[tuple[str, str]]:
    """(YYYY-MM-DD, manifest path) for every daily capture folder, oldest first."""
    out = []
    for m in archive.manifests():
        parts = m.relative_to(archive.root).parts  # captures/YYYY/MM/DD/MANIFEST.json
        if len(parts) == 5 and parts[1].isdigit() and parts[2].isdigit() and parts[3].isdigit():
            out.append((f"{parts[1]}-{parts[2]}-{parts[3]}", "/".join(parts)))
    return sorted(out)


def _files(run: dict) -> dict[str, dict]:
    return {f["name"]: f for f in run.get("files", [])}


def run_items(run: dict) -> list[dict]:
    """Normalise a run's Archive record (old or new format) into items with a status."""
    ia = run.get("internet_archive")
    files = _files(run)
    if not isinstance(ia, dict):
        return []
    if "items" in ia:
        return ia["items"]
    # Phase 1 format (Nov 8-9, 2026): one request, for the dashboard only.
    f = files.get("dashboard.html")
    if not f:
        return []
    item = {"name": "dashboard.html", "url": f["url"], "our_fetched_utc": f["fetched_utc"],
            "our_sha256": f["sha256"], "status": "receipt" if ia.get("ok") else "pending"}
    if ia.get("ok") and ia.get("snapshot_timestamp"):
        item["receipt"] = {"snapshot_timestamp": ia["snapshot_timestamp"], "source": "save-page-now"}
    return [item]


def _resolved(notes: list[dict], run_id: str, name: str, kind: str) -> bool:
    return any(n.get("note_type") == kind and n.get("run_id") == run_id and n.get("name") == name
               for n in notes)


def append_notes(archive: Archive, manifest_rel: str, new_notes: list[dict]) -> None:
    """Append notes without changing anything already in the manifest."""
    before = archive.read_bytes(manifest_rel)
    m = json.loads(before)
    original = json.dumps({k: v for k, v in m.items() if k != "appended_notes"}, sort_keys=True)
    old_notes = list(m.get("appended_notes", []))
    m["appended_notes"] = old_notes + new_notes
    after = json.dumps({k: v for k, v in m.items() if k != "appended_notes"}, sort_keys=True)
    assert original == after and m["appended_notes"][:len(old_notes)] == old_notes
    archive.save_json(manifest_rel, m)


def find_late_receipts(archive: Archive, client: ArchiveClient, today: str,
                       skip_run_id: str | None = None,
                       lookback_days: int = config.LATE_RECEIPT_LOOKBACK_DAYS) -> list[dict]:
    """Look for receipts for earlier runs still pending. Returns the notes appended."""
    cutoff = (date.fromisoformat(today) - timedelta(days=lookback_days)).isoformat()
    appended: list[dict] = []
    for day, rel in day_manifests(archive):
        if day < cutoff:
            continue
        m = archive.load_json(rel)
        notes = m.get("appended_notes", [])
        new: list[dict] = []
        for run in m.get("runs", []):
            rid = run.get("run_id")
            if rid == skip_run_id or not rid:
                continue
            for item in run_items(run):
                name = item["name"]
                if item.get("status") == "pending" and not _resolved(notes, rid, name, NOTE_RECEIPT):
                    av = client.availability(item["url"], item["our_fetched_utc"])
                    if av.get("result") == "found_after_our_fetch":
                        new.append({
                            "note_type": NOTE_RECEIPT,
                            "appended_utc": utc_now(),
                            "run_id": rid,
                            "name": name,
                            "url": item["url"],
                            "our_fetched_utc": item["our_fetched_utc"],
                            "availability_check": av,
                            "receipt": client.receipt(item, av["closest_timestamp"], "availability-api"),
                        })
                rc = (item.get("receipt") or {}).get("raw_check")
                if (rc and rc.get("result") == "unavailable"
                        and not _resolved(notes, rid, name, NOTE_RAW)):
                    check = client.raw_check(item["url"], item["receipt"]["snapshot_timestamp"],
                                             item["our_sha256"], name)
                    if check["result"] != "unavailable":
                        new.append({"note_type": NOTE_RAW, "appended_utc": utc_now(),
                                    "run_id": rid, "name": name, "raw_check": check})
        new += _diagnose_earlier_mismatches(m, notes, client, skip_run_id)
        if new:
            append_notes(archive, rel, new)
            appended += new
    return appended


def _mismatches_without_diagnostic(m: dict, notes: list[dict]):
    """(run_id, name, snapshot_ts, where) for every recorded raw-copy mismatch
    that has no diagnostic yet, in the run records or in appended notes."""
    for run in m.get("runs", []):
        for item in run_items(run):
            r = item.get("receipt") or {}
            rc = r.get("raw_check") or {}
            if rc.get("result") == "mismatch" and "diagnostic" not in rc:
                yield run.get("run_id"), item["name"], r.get("snapshot_timestamp"), "run record"
    for n in notes:
        rc = (n.get("receipt") or {}).get("raw_check") or n.get("raw_check") or {}
        ts = (n.get("receipt") or {}).get("snapshot_timestamp")
        if ts is None and rc.get("raw_url"):
            mt = re.search(r"/web/(\d{14})id_/", rc["raw_url"])
            ts = mt.group(1) if mt else None
        if rc.get("result") == "mismatch" and "diagnostic" not in rc:
            yield n.get("run_id"), n.get("name"), ts, f"appended note ({n.get('note_type')})"


def _diagnose_earlier_mismatches(m: dict, notes: list[dict], client: ArchiveClient,
                                 skip_run_id: str | None) -> list[dict]:
    if client.on_mismatch is None:
        return []
    items = {(run.get("run_id"), i["name"]): i for run in m.get("runs", []) for i in run_items(run)}
    new, seen = [], set()
    for rid, name, ts, where in _mismatches_without_diagnostic(m, notes):
        key = (rid, name, ts)
        if (rid == skip_run_id or key in seen or not ts or (rid, name) not in items
                or any(n.get("note_type") == NOTE_DIAG and n.get("run_id") == rid
                       and n.get("name") == name and n.get("snapshot_timestamp") == ts
                       for n in notes)):
            continue
        seen.add(key)
        item = items[(rid, name)]
        check = client.raw_check(item["url"], ts, item["our_sha256"], name)
        new.append({"note_type": NOTE_DIAG, "appended_utc": utc_now(), "run_id": rid,
                    "name": name, "snapshot_timestamp": ts, "mismatch_recorded_in": where,
                    "raw_check": check})
    return new


def day_has_receipt(m: dict) -> bool:
    for run in m.get("runs", []):
        if any(i.get("status") == "receipt" for i in run_items(run)):
            return True
    return any(n.get("note_type") == NOTE_RECEIPT for n in m.get("appended_notes", []))


def days_without_receipt(archive: Archive) -> int:
    """How many of the most recent capture days, in a row, have no receipt at all."""
    streak = 0
    for _, rel in reversed(day_manifests(archive)):
        m = archive.load_json(rel)
        if not any(isinstance(r.get("internet_archive"), dict) for r in m.get("runs", [])):
            continue  # e.g. Jon's manual fixture day: no Archive request was made
        if day_has_receipt(m):
            break
        streak += 1
    return streak
