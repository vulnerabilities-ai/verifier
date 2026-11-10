"""Diagnostic for Internet Archive raw-copy mismatches.

When the Archive's raw copy (the "id_" address) of a file has a different
SHA-256 from ours, we keep the Archive's bytes under captures/archive-raw/
(never overwriting anything) and describe the difference:

- both sizes and the first differing byte position;
- whether both parse as JSON, and whether they are semantically identical;
- whether the difference is only line endings, only whitespace, or only an
  encoding (byte-order mark, gzip, deflate, Brotli, Latin-1/Windows-1252).

This adds detail only. A mismatch is still reported as "mismatch".
"""

from __future__ import annotations

import gzip
import json
import re
import zlib

from .net import sha256_hex, utc_now
from .store import Archive

_WS = re.compile(rb"\s+")


def first_difference(a: bytes, b: bytes) -> int | None:
    """Index of the first differing byte; the shorter length if one is a prefix; None if equal."""
    if a == b:
        return None
    n = min(len(a), len(b))
    for i in range(n):
        if a[i] != b[i]:
            return i
    return n


def _json(data: bytes):
    try:
        return True, json.loads(data.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        return False, None


def _decodings(data: bytes):
    """Yield (method, bytes) for each decoding we try, in a fixed order."""
    if data.startswith(b"\xef\xbb\xbf"):
        yield "utf8_byte_order_mark", data[3:]
    try:
        yield "gzip", gzip.decompress(data)
    except (OSError, EOFError, zlib.error):
        pass
    for name, wbits in (("deflate", zlib.MAX_WBITS), ("raw_deflate", -zlib.MAX_WBITS)):
        try:
            yield name, zlib.decompress(data, wbits)
        except zlib.error:
            pass
    try:
        import brotli  # optional; not installed by default
        try:
            yield "brotli", brotli.decompress(data)
        except Exception:  # noqa: BLE001 - any failure means "not Brotli"
            pass
    except ImportError:
        pass
    for enc in ("latin-1", "cp1252"):
        try:
            yield f"{enc}_as_utf8", data.decode("utf-8").encode(enc)
        except (UnicodeDecodeError, UnicodeEncodeError):
            pass
        try:
            yield f"utf8_from_{enc}", data.decode(enc).encode("utf-8")
        except (UnicodeDecodeError, UnicodeEncodeError):
            pass


def diagnose(ours: bytes, theirs: bytes) -> dict:
    ok_ours, j_ours = _json(ours)
    ok_theirs, j_theirs = _json(theirs)
    line_endings = ours.replace(b"\r\n", b"\n") == theirs.replace(b"\r\n", b"\n")
    whitespace = _WS.sub(b"", ours) == _WS.sub(b"", theirs)
    decoded_by = next((m for m, d in _decodings(theirs) if d == ours), None)
    semantic = bool(ok_ours and ok_theirs and j_ours == j_theirs)
    if ours == theirs:
        summary = "identical"
    elif line_endings:
        summary = "line_endings_only"
    elif whitespace:
        summary = "whitespace_only"
    elif decoded_by:
        summary = f"encoding_only ({decoded_by})"
    elif semantic:
        summary = "json_semantically_identical"
    else:
        summary = "other"
    return {
        "diagnosed_utc": utc_now(),
        "our_size": len(ours),
        "archive_size": len(theirs),
        "first_difference_offset": first_difference(ours, theirs),
        "our_parses_as_json": ok_ours,
        "archive_parses_as_json": ok_theirs,
        "json_semantically_identical": semantic if (ok_ours and ok_theirs) else None,
        "identical_ignoring_line_endings": line_endings,
        "identical_ignoring_whitespace": whitespace,
        "identical_after_decoding": decoded_by is not None,
        "decoding_method": decoded_by,
        "difference_summary": summary,
    }


def _safe(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", name)


class MismatchDiagnoser:
    """Called by ArchiveClient.raw_check on a mismatch. Saves the Archive's
    raw bytes under captures/archive-raw/ and returns the diagnostic."""

    def __init__(self, archive: Archive):
        self.archive = archive
        self._saved: dict[str, str] = {}  # copies saved during this run

    def __call__(self, name: str, snapshot_ts: str, ours_sha256: str, theirs: bytes) -> dict:
        blobs = {**self.archive.known_blobs(), **self._saved}
        ours_rel = blobs.get(ours_sha256)
        today = utc_now()
        folder = f"captures/archive-raw/{today[0:4]}/{today[5:7]}/{today[8:10]}"
        stem, dot, ext = (name or "file").rpartition(".")
        fname = _safe(f"{stem}.{snapshot_ts}.id_.{ext}" if dot else f"{name}.{snapshot_ts}.id_")
        stored_at, _ = self.archive.store(folder, fname, theirs, blobs, "T" + today[11:19].replace(":", "") + "Z")
        saved = {"stored_at": stored_at, "sha256": sha256_hex(theirs)}
        self._saved[saved["sha256"]] = stored_at
        if not ours_rel:
            return {"diagnosed_utc": today, "saved_copy": saved,
                    "difference_summary": "not_diagnosed",
                    "error": "Our copy with that SHA-256 was not found in the archive."}
        ours = self.archive.read_bytes(ours_rel)
        return {**diagnose(ours, theirs), "our_copy": ours_rel, "saved_copy": saved}
