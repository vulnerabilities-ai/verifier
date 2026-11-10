"""Writing to the archive under captures/.

Rules:
- The pipeline only ever writes inside captures/.
- A raw capture file is never overwritten or deleted (files are opened in
  exclusive-create mode).
- Store-only-when-changed: if the exact bytes are already stored somewhere in
  the archive (same SHA-256), the manifest points at that copy instead of
  saving a duplicate. The SHA-256 in the manifest proves the bytes were the same.
- Only the bookkeeping files (MANIFEST.json, capture-log.csv, latest.json) are
  ever rewritten, and MANIFEST.json only gains new runs.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path, PurePosixPath

from .net import sha256_hex

METADATA_NAMES = {"MANIFEST.json", "capture-log.csv", "latest.json", "verification.json"}

LOG_COLUMNS = [
    "run_utc", "finished_utc", "run_id", "trigger", "mode", "status",
    "base_url", "new_files", "unchanged_files", "archive_snapshot", "message",
]


class PathOutsideCaptures(Exception):
    pass


class Archive:
    """A write-guarded area of the repository: captures/ by default, or cards/."""

    def __init__(self, root: Path, area: str = "captures"):
        self.root = Path(root).resolve()
        self.area = area
        self.captures = self.root / area

    # -- path safety ------------------------------------------------------
    def _resolve(self, rel: str) -> Path:
        p = PurePosixPath(rel)
        if p.is_absolute() or ".." in p.parts or not p.parts or p.parts[0] != self.area:
            raise PathOutsideCaptures(f"Refusing to write outside {self.area}/: {rel}")
        full = (self.root / Path(*p.parts)).resolve()
        if self.captures not in full.parents:
            raise PathOutsideCaptures(f"Refusing to write outside {self.area}/: {rel}")
        return full

    def write_raw(self, rel: str, data: bytes) -> str:
        """Write a raw capture file. Never overwrites."""
        full = self._resolve(rel)
        if full.name in METADATA_NAMES:
            raise PathOutsideCaptures(f"{rel} is a reserved bookkeeping name")
        full.parent.mkdir(parents=True, exist_ok=True)
        with open(full, "xb") as f:  # "x": fail if it already exists
            f.write(data)
        return rel

    def write_metadata(self, rel: str, text: str) -> None:
        full = self._resolve(rel)
        if full.name not in METADATA_NAMES:
            raise PathOutsideCaptures(f"{rel} is not a bookkeeping file")
        full.parent.mkdir(parents=True, exist_ok=True)
        full.write_text(text, encoding="utf-8", newline="\n")

    def exists(self, rel: str) -> bool:
        return self._resolve(rel).exists()

    def read_bytes(self, rel: str) -> bytes:
        return self._resolve(rel).read_bytes()

    # -- store-only-when-changed -----------------------------------------
    def manifests(self) -> list[Path]:
        if not self.captures.exists():
            return []
        return sorted(self.captures.rglob("MANIFEST.json"))

    def known_blobs(self) -> dict[str, str]:
        """Map SHA-256 -> stored path, for every file the manifests say is stored."""
        out: dict[str, str] = {}
        for m in self.manifests():
            data = json.loads(m.read_text(encoding="utf-8"))
            for entry in iter_file_entries(data):
                sha, stored = entry.get("sha256"), entry.get("stored_at")
                if sha and stored and sha not in out:
                    out[sha] = stored
        return out

    def find_identical(self, data: bytes, blobs: dict[str, str]) -> str | None:
        sha = sha256_hex(data)
        rel = blobs.get(sha)
        if rel and self.exists(rel) and sha256_hex(self.read_bytes(rel)) == sha:
            return rel
        return None

    def store(self, folder: str, name: str, data: bytes, blobs: dict[str, str],
              time_suffix: str) -> tuple[str, bool]:
        """Store bytes (or reuse an identical copy). Returns (stored_at, newly_stored)."""
        same = self.find_identical(data, blobs)
        if same:
            return same, False
        rel = f"{folder}/{name}"
        if self.exists(rel):  # different bytes, same name, same day
            stem, dot, ext = name.rpartition(".")
            rel = f"{folder}/{stem}.{time_suffix}.{ext}" if dot else f"{folder}/{name}.{time_suffix}"
        self.write_raw(rel, data)
        blobs[sha256_hex(data)] = rel
        return rel, True

    # -- bookkeeping ------------------------------------------------------
    def load_json(self, rel: str) -> dict | None:
        full = self._resolve(rel)
        if not full.exists():
            return None
        return json.loads(full.read_text(encoding="utf-8"))

    def save_json(self, rel: str, data: dict) -> None:
        self.write_metadata(rel, json.dumps(data, indent=2, ensure_ascii=False) + "\n")

    def append_log(self, row: dict) -> None:
        rel = "captures/capture-log.csv"
        full = self._resolve(rel)
        existing = full.read_text(encoding="utf-8") if full.exists() else ""
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=LOG_COLUMNS, lineterminator="\n")
        if not existing:
            w.writeheader()
        w.writerow({k: ("" if row.get(k) is None else row.get(k)) for k in LOG_COLUMNS})
        self.write_metadata(rel, existing + buf.getvalue())

    def read_log(self) -> list[dict]:
        full = self._resolve("captures/capture-log.csv")
        if not full.exists():
            return []
        return list(csv.DictReader(io.StringIO(full.read_text(encoding="utf-8"))))


def iter_file_entries(manifest):
    """Yield every stored-file record anywhere in a manifest: any object that
    has both "stored_at" and "sha256" (capture files, card copies, preimages,
    and saved Internet Archive raw copies)."""
    if isinstance(manifest, dict):
        if "stored_at" in manifest and "sha256" in manifest:
            yield manifest
        for v in manifest.values():
            yield from iter_file_entries(v)
    elif isinstance(manifest, list):
        for v in manifest:
            yield from iter_file_entries(v)
