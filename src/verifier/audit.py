"""Archive integrity check: anyone can run this to confirm the archive is intact.

For captures/ and cards/:
- every file a manifest says is stored exists, and its SHA-256 matches;
- every raw file is accounted for by some manifest.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .store import METADATA_NAMES, iter_file_entries

AREAS = ("captures", "cards")


def audit(root: Path) -> list[str]:
    root = Path(root).resolve()
    problems: list[str] = []
    referenced: set[str] = set()
    for area in AREAS:
        base = root / area
        if not base.exists():
            continue
        for m in sorted(base.rglob("MANIFEST.json")):
            rel_m = m.relative_to(root).as_posix()
            try:
                data = json.loads(m.read_text(encoding="utf-8"))
            except json.JSONDecodeError as e:
                problems.append(f"{rel_m}: not valid JSON ({e})")
                continue
            for entry in iter_file_entries(data):
                stored, sha = entry.get("stored_at"), entry.get("sha256")
                if not stored:
                    continue
                referenced.add(stored)
                f = root / stored
                if not f.exists():
                    problems.append(f"{rel_m}: {stored} is missing")
                elif hashlib.sha256(f.read_bytes()).hexdigest() != sha:
                    problems.append(f"{rel_m}: {stored} does not match its SHA-256")
    for area in AREAS:
        base = root / area
        if not base.exists():
            continue
        for f in sorted(base.rglob("*")):
            if f.is_file() and f.name not in METADATA_NAMES and f.name != ".gitkeep":
                rel = f.relative_to(root).as_posix()
                if rel not in referenced:
                    problems.append(f"{rel} is not listed in any manifest")
    return problems
