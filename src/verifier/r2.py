"""Rule R2: check a revealed finding's commitment hash against its preimage,
and read the other facts a finding card prints (timeline, severities, links).

Deterministic code only. Nothing here guesses: a part of the card that cannot
be found is recorded as missing, never inferred.
"""

from __future__ import annotations

import hashlib
import html
import json
import re
from urllib.parse import unquote_to_bytes

_DATA_LINK = re.compile(
    r'<a\b[^>]*\bdownload="[^"]*preimage[^"]*"[^>]*\bhref="(data:[^"]*)"'
    r'|<a\b[^>]*\bhref="(data:application/json[^"]*)"[^>]*\bdownload="[^"]*preimage', re.S)
_VISIBLE = re.compile(r'<pre class="preimage-body">(.*?)</pre>', re.S)
_HASH128 = re.compile(r"\b[0-9a-f]{128}\b")
_TIMELINE = re.compile(
    r'<span class="timeline-date">([^<]*)</span>\s*<span class="timeline-label">([^<]*)</span>', re.S)
_SEV_ITEM = re.compile(
    r'<span class="sev-compare-item">\s*([^<]+?)\s*<span class="sev-chip[^"]*">([^<]*)</span>', re.S)
_HREF = re.compile(r'<a\b[^>]*\bhref="(https?://[^"]+)"')
_KICKER = re.compile(r'<p class="kicker">\s*(Committed|Revealed)\s+([^<]+?)\s*</p>')

# Card label -> our neutral key (the card's own label is kept alongside).
SEVERITY_SOURCES = {"claude": "model", "security research firm": "firm", "maintainer": "maintainer"}
TIMELINE_KEYS = {
    "discovered or logged": "discovered_or_logged_date",
    "reported to tracker": "discovered_or_logged_date",  # label before the Aug 26, 2026 update
    "sent to maintainer": "report_date",
    "maintainer acknowledged": "acknowledged_date",
    "patch released": "patch_released_date",
    "publicly revealed": "reveal_date",
}


def sha3_512(data: bytes) -> str:
    return hashlib.sha3_512(data).hexdigest()


def canonical_bytes(obj) -> bytes:
    """Sorted keys, no whitespace between tokens, UTF-8, non-ASCII NOT escaped
    (escaping it would change the bytes and therefore the hash)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _section(text: str, marker: str) -> str:
    i = text.find(f'<div class="marker">{marker}</div>')
    if i < 0:
        return ""
    j = text.find('<div class="marker">', i + 10)
    return text[i: j if j > 0 else len(text)]


def extract_preimage(card: bytes) -> dict:
    """Return {"bytes": ..., "method": ...} or {"bytes": None, "error": ...}."""
    text = card.decode("utf-8", errors="replace")
    m = _DATA_LINK.search(text)
    if m:
        href = html.unescape(m.group(1) or m.group(2))
        _, _, payload = href.partition(",")
        if payload:
            return {"bytes": unquote_to_bytes(payload), "method": "download_link_data_address"}
    v = _VISIBLE.search(text)
    if v:
        try:
            obj = json.loads(html.unescape(v.group(1)))
            return {"bytes": canonical_bytes(obj), "method": "visible_text_canonical_rebuild"}
        except json.JSONDecodeError as e:
            return {"bytes": None, "error": f"visible preimage text is not valid JSON ({e})"}
    return {"bytes": None, "error": "no preimage download link or visible preimage text on the card"}


def parse_card(card: bytes) -> dict:
    text = card.decode("utf-8", errors="replace")
    missing = []
    prov = _section(text, "PROVENANCE")
    printed = _HASH128.search(prov) if prov else None
    if not printed:
        missing.append("provenance hash")
    times = {k.lower(): v for k, v in _KICKER.findall(prov)}
    timeline = [{"date": html.unescape(d).strip(), "label": html.unescape(l).strip()}
                for d, l in _TIMELINE.findall(text)]
    if not timeline:
        missing.append("timeline")
    dates = {}
    for t in timeline:
        key = TIMELINE_KEYS.get(t["label"].lower())
        if key and key not in dates:
            dates[key] = t["date"]
    sev = {}
    for label, value in _SEV_ITEM.findall(text):
        key = SEVERITY_SOURCES.get(html.unescape(label).strip().lower())
        if key:
            sev[key] = html.unescape(value).strip() or None
    if not sev:
        missing.append("severities")
    fix_links = _HREF.findall(_section(text, "UPSTREAM FIX"))
    adv_links = _HREF.findall(_section(text, "ADVISORY"))
    all_links = _HREF.findall(text)
    return {
        "printed_hash": printed.group(0) if printed else None,
        "committed_printed": times.get("committed"),
        "revealed_printed": times.get("revealed"),
        "timeline": timeline,
        "dates": dates,
        "severities": sev,
        "links": {
            "fix": fix_links,
            "advisory": adv_links,
            "nvd": sorted({u for u in all_links if "nvd.nist.gov" in u}),
            "ghsa": sorted({u for u in all_links if "github.com/advisories/" in u}),
        },
        "missing_parts": missing,
    }


def r2_check(preimage: bytes | None, ledger_hash: str | None, printed_hash: str | None,
             method: str | None = None) -> dict:
    """Compare SHA-3-512 of the preimage with the ledger hash and the card's printed hash."""
    rec = {"rule": "R2", "algorithm": "SHA-3-512", "ledger_hash": ledger_hash,
           "printed_hash": printed_hash, "extraction_method": method,
           "printed_hash_equals_ledger_hash": (printed_hash == ledger_hash)
           if printed_hash and ledger_hash else None}
    if preimage is None or not ledger_hash:
        rec.update(outcome="unavailable", raw_bytes_match=None, canonical_rebuild_match=None,
                   reason="no preimage" if preimage is None else "no ledger hash")
        return rec
    raw = sha3_512(preimage)
    try:
        canon = sha3_512(canonical_bytes(json.loads(preimage.decode("utf-8"))))
    except (UnicodeDecodeError, json.JSONDecodeError):
        canon = None
    rec.update(preimage_sha3_512=raw, canonical_rebuild_sha3_512=canon,
               raw_bytes_match=raw == ledger_hash,
               canonical_rebuild_match=(canon == ledger_hash) if canon else None)
    rec["outcome"] = "match" if (rec["raw_bytes_match"] or rec["canonical_rebuild_match"]) else "mismatch"
    return rec


def patch_before_discovery(dates: dict) -> bool | None:
    d, p = dates.get("discovered_or_logged_date"), dates.get("patch_released_date")
    if not d or not p:
        return None
    return p < d
