"""Later receipts: Internet Archive receipts found after the run that asked for them.

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

# Note types written from now on. Notes written before 2026-11-10 used the
# older names below; raw records are never edited, so both are read.
NOTE_RECEIPT = "later-archive-receipt"
NOTE_RAW = "later-raw-check"
RECEIPT_TYPES = frozenset({NOTE_RECEIPT, "late-archive-receipt"})
RAW_TYPES = frozenset({NOTE_RAW, "late-raw-check"})
TYPE_GROUPS = {NOTE_RECEIPT: RECEIPT_TYPES, NOTE_RAW: RAW_TYPES}
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
    kinds = TYPE_GROUPS.get(kind, {kind})
    return any(n.get("note_type") in kinds and n.get("run_id") == run_id and n.get("name") == name
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


def find_later_receipts(archive: Archive, client: ArchiveClient, today: str,
                       skip_run_id: str | None = None,
                       lookback_days: int = config.LATER_RECEIPT_LOOKBACK_DAYS) -> list[dict]:
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
            kind = ("later Archive receipt" if n.get("note_type") in RECEIPT_TYPES
                    else "later raw check" if n.get("note_type") in RAW_TYPES else "note")
            yield n.get("run_id"), n.get("name"), ts, f"appended note ({kind})"


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
    return any(n.get("note_type") in RECEIPT_TYPES for n in m.get("appended_notes", []))


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


# ---------------------------------------------------------------------------
# Raw copies identical after decompression (match_after_decoding)
# ---------------------------------------------------------------------------
NOTE_RECLASS = "later-raw-reclassification"
DEFINITE = frozenset({"match", "match_after_decoding", "mismatch"})


def _ts_of(n: dict, rc: dict) -> str | None:
    ts = (n.get("receipt") or {}).get("snapshot_timestamp") or n.get("snapshot_timestamp")
    if ts is None and rc.get("raw_url"):
        mt = re.search(r"/web/(\d{14})id_/", rc["raw_url"])
        ts = mt.group(1) if mt else None
    return ts


def _checks(m: dict):
    """(run_id, name, snapshot_ts, raw_check, where, note_type) for every raw-copy check recorded
    in a day manifest, in the order written: run records first, then appended notes."""
    for run in m.get("runs", []):
        for item in run_items(run):
            r = item.get("receipt") or {}
            if r.get("raw_check"):
                yield run.get("run_id"), item["name"], r.get("snapshot_timestamp"), r["raw_check"], "run record", None
    for n in m.get("appended_notes", []):
        rc = (n.get("receipt") or {}).get("raw_check") or n.get("raw_check")
        if rc:
            yield n.get("run_id"), n.get("name"), _ts_of(n, rc), rc, "appended note", n.get("note_type")


def reclassification_notes(m: dict) -> list[dict]:
    """New notes for recorded mismatches whose diagnostic found the Archive's copy identical
    to ours after decoding. Records already written are never changed."""
    done = {(n.get("run_id"), n.get("name"), n.get("snapshot_timestamp"))
            for n in m.get("appended_notes", []) if n.get("note_type") == NOTE_RECLASS}
    new = []
    for rid, name, ts, rc, where, ntype in _checks(m):
        d = rc.get("diagnostic") or {}
        if rc.get("result") == "mismatch" and d.get("identical_after_decoding") is True and \
                (rid, name, ts) not in done:
            done.add((rid, name, ts))
            kind = ("later Archive receipt" if ntype in RECEIPT_TYPES else "later raw check" if ntype in RAW_TYPES
                    else "diagnostic note" if ntype == NOTE_DIAG else "note") if ntype else None
            new.append({
                "note_type": NOTE_RECLASS, "appended_utc": utc_now(), "run_id": rid, "name": name,
                "snapshot_timestamp": ts, "result": "match_after_decoding",
                "decoding_method": d.get("decoding_method"),
                "based_on": where + (f" ({kind})" if kind else ""),
                "reason": (f"The diagnostic found the Internet Archive's copy identical to ours after "
                           f"decompression ({d.get('decoding_method')}). The earlier record says 'mismatch' "
                           "and is kept as written."),
            })
    return new


def reclassify_all(archive: Archive) -> list[dict]:
    """Append reclassification notes to every day's manifest that needs them (no network)."""
    appended = []
    for _, rel in day_manifests(archive):
        m = archive.load_json(rel)
        new = reclassification_notes(m)
        if new:
            append_notes(archive, rel, new)
            appended += new
    return appended


def final_raw_result(m: dict, run_id: str, name: str, snapshot_ts: str | None) -> tuple[str | None, str | None]:
    """The raw-copy result for one receipt after everything recorded since: (result, method).
    A later definite result (match, match_after_decoding, mismatch) replaces an earlier one; a
    later 'unavailable' never replaces a definite result."""
    result = method = None

    def apply(res, meth):
        nonlocal result, method
        if res in DEFINITE or result is None:
            result, method = res, meth
    for rid, nm, ts, rc, where, ntype in _checks(m):
        if rid == run_id and nm == name and (snapshot_ts is None or ts in (None, snapshot_ts)):
            res = rc.get("result")
            if res:
                apply(res, (rc.get("diagnostic") or {}).get("decoding_method") if res == "match_after_decoding" else None)
    for n in m.get("appended_notes", []):
        if n.get("note_type") == NOTE_RECLASS and n.get("run_id") == run_id and n.get("name") == name and \
                (snapshot_ts is None or n.get("snapshot_timestamp") in (None, snapshot_ts)):
            apply("match_after_decoding", n.get("decoding_method"))
    return result, method
