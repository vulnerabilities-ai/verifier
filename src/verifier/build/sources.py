"""Read the archive into a simple, ordered picture: our own daily captures,
the backfilled copies of the program's own archive, and the evidence (git
commit times and Internet Archive receipts) that supports each capture.

Read-only. No network.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

from ..late_receipts import NOTE_DIAG, NOTE_RAW, NOTE_RECEIPT, day_manifests, run_items
from ..store import Archive

# Jon's manual capture: no time of day was recorded (decision of 2026-11-10).
MANUAL_DAY = "2026-10-30"
MANUAL_BOUND_UTC = "2026-10-30T23:59:59Z"
MANUAL_BASIS = ("manual capture by Jon on 2026-10-30; time not recorded and not independently "
                "timestamped; the value is the latest possible time that day. The earliest "
                "independent evidence is the repository's first commit on 2026-11-08.")


@dataclass
class Run:
    day: str
    run_id: str
    manifest: str
    files: dict  # name -> file entry (sha256, stored_at, fetched_utc, ...)
    internet_archive: dict | None
    notes: list = field(default_factory=list)  # the day's appended notes for this run
    manual: bool = False

    def fetched(self, name: str) -> str:
        """Fetch time of a file; Jon's manual day uses the end-of-day bound."""
        if self.manual:
            return MANUAL_BOUND_UTC
        return self.files[name]["fetched_utc"]


@dataclass
class Backfill:
    label: str
    manifest: str
    our_fetch_utc: str
    files: dict  # name -> entry; names "index.html", "data/payload.json", "data/ledger.json"
    note: str


class Sources:
    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self.archive = Archive(self.root)
        self.runs = self._our_runs()
        self.backfills = self._backfills()

    # -- reading --------------------------------------------------------------
    def _our_runs(self) -> list[Run]:
        runs = []
        for day, rel in day_manifests(self.archive):
            m = self.archive.load_json(rel)
            notes = m.get("appended_notes", [])
            for r in m.get("runs", []):
                files = {f["name"]: f for f in r.get("files", [])}
                if not {"payload.json", "ledger.json"} <= set(files):
                    continue
                if any(not files[n].get("stored_at") for n in ("payload.json", "ledger.json")):
                    continue
                manual = files["ledger.json"].get("fetched_utc") is None
                if manual and day != MANUAL_DAY:
                    raise ValueError(f"{rel}: a run without fetch times other than Jon's manual capture")
                runs.append(Run(day, r.get("run_id"), rel, files, r.get("internet_archive"),
                                [n for n in notes if n.get("run_id") == r.get("run_id")], manual))
        return runs

    def _backfills(self) -> list[Backfill]:
        out = []
        base = self.root / "captures" / "anthropic-archive"
        if not base.exists():
            return out
        for m in sorted(base.glob("*/MANIFEST.json")):
            d = json.loads(m.read_text(encoding="utf-8"))
            out.append(Backfill(d["anthropic_snapshot_label"], m.relative_to(self.root).as_posix(),
                                d["our_fetch_utc"], {f["name"]: f for f in d["files"]}, d["note"]))
        return out

    @lru_cache(maxsize=None)
    def load_json_file(self, rel: str):
        return json.loads((self.root / rel).read_bytes())

    def bytes_of(self, rel: str) -> bytes:
        return (self.root / rel).read_bytes()

    # -- distinct states of our own captures -----------------------------------
    def states(self) -> list[dict]:
        """Distinct (payload, ledger) pairs in capture order, with the runs that saw each."""
        out, index = [], {}
        for r in self.runs:
            key = (r.files["payload.json"]["sha256"], r.files["ledger.json"]["sha256"])
            if key not in index:
                index[key] = len(out)
                out.append({"key": key, "first_run": r, "runs": []})
            out[index[key]]["runs"].append(r)
        return out

    # -- evidence --------------------------------------------------------------
    @lru_cache(maxsize=None)
    def git_first_commit_utc(self, rel: str) -> str | None:
        """UTC time of the first commit that introduced these exact bytes (any path).
        None outside a git checkout or in a shallow clone (the time would be wrong)."""
        try:
            def git(*a):
                return subprocess.run(["git", *a], cwd=self.root, capture_output=True,
                                      text=True, check=True).stdout.strip()
            if git("rev-parse", "--is-shallow-repository") != "false":
                return None
            blob = git("hash-object", rel)
            times = [int(t) for t in git("log", "--format=%ct", f"--find-object={blob}").split()]
        except (OSError, subprocess.CalledProcessError, ValueError):
            return None
        if not times:
            return None
        from datetime import datetime, timezone
        return datetime.fromtimestamp(min(times), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    def archive_receipt(self, run: Run, name: str) -> dict | None:
        """The Archive receipt for one file of one run, with the latest raw-check result
        recorded anywhere (the run record or later appended notes). None if no receipt."""
        receipt = None
        for item in run_items({"files": list(run.files.values()),
                               "internet_archive": run.internet_archive}):
            if item["name"] == name and item.get("status") == "receipt":
                receipt = item.get("receipt")
        for n in run.notes:
            if n.get("note_type") == NOTE_RECEIPT and n.get("name") == name and receipt is None:
                receipt = n.get("receipt")
        if not receipt or not receipt.get("snapshot_timestamp"):
            return None
        result = (receipt.get("raw_check") or {}).get("result")
        for n in run.notes:
            if n.get("name") == name and n.get("note_type") in (NOTE_RAW, NOTE_DIAG):
                if n.get("note_type") == NOTE_DIAG and n.get("snapshot_timestamp") not in (
                        None, receipt.get("snapshot_timestamp")):
                    continue
                result = (n.get("raw_check") or {}).get("result") or result
        ts = receipt["snapshot_timestamp"]
        return {"snapshot_utc": f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}T{ts[8:10]}:{ts[10:12]}:{ts[12:14]}Z",
                "raw_result": result, "run_day": run.day, "run_id": run.run_id}
