"""Finding cards: fetch them (rule R2 input) and write each card's derived
verification.json.

- Only revealed findings with no card yet are fetched; known cards are
  re-checked monthly (or at once if we only hold a manual copy).
- Addresses tried, in order: findings/<ID>.html, findings/<ID>/, findings/<ID>.
- Raw card bytes are stored exactly as served, never edited; a changed card
  is stored as a new time-suffixed copy. Fetches are only ever appended to
  the card's MANIFEST.json.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urljoin

from . import config
from .capture import file_entry, time_suffix, validate
from .net import CaptureError, Fetcher, RobotsDisallowed, sha256_hex, utc_now
from .r2 import (UNAVAILABLE_REASONS, card_hints, extract_preimage, parse_card,
                 patch_before_discovery, r2_check)
from .store import Archive

RECHECK_DAYS = 30


def card_addresses(base_url: str, fid: str) -> list[str]:
    return [urljoin(base_url, f"findings/{fid}.html"), urljoin(base_url, f"findings/{fid}/"),
            urljoin(base_url, f"findings/{fid}")]


def _manifest_rel(fid: str) -> str:
    return f"cards/{fid}/MANIFEST.json"


def _new_manifest(fid: str) -> dict:
    return {"schema_version": 1, "program": config.PROGRAM, "finding_id": fid,
            "about": ("Raw copies of this finding's card, exactly as served. Never edited; a changed card "
                      "is stored as a new, time-suffixed copy. Fetches are only ever appended."),
            "fetches": [], "unavailable": [], "preimages": []}


def is_due(manifest: dict | None, now: str, recheck_days: int = RECHECK_DAYS) -> bool:
    if not manifest or not manifest.get("fetches"):
        return True
    times = [f.get("fetched_utc") for f in manifest["fetches"]]
    if any(t is None for t in times) and all(f.get("url") is None for f in manifest["fetches"]):
        return True  # only a manual copy so far
    last = max(t for t in times if t)
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    return (datetime.strptime(now, fmt) - datetime.strptime(last, fmt)) >= timedelta(days=recheck_days)


def fetch_cards(root: Path, revealed: dict[str, str], fetcher: Fetcher,
                base_url: str = config.BASE_URL, now: str | None = None,
                recheck_days: int = RECHECK_DAYS) -> dict:
    """Fetch new or due cards. revealed: finding ID -> ledger hash. Returns a tally."""
    store = Archive(root, area="cards")
    now = now or utc_now()
    tally = {"fetched": 0, "new_copies": 0, "unchanged": 0, "unavailable": [], "unavailable_reasons": {},
             "not_due": 0}
    for fid in sorted(revealed):
        rel = _manifest_rel(fid)
        manifest = store.load_json(rel)
        if not is_due(manifest, now, recheck_days):
            tally["not_due"] += 1
            continue
        manifest = manifest or _new_manifest(fid)
        attempts, got = [], None
        for url in card_addresses(base_url, fid):
            try:
                resp = fetcher.get(url)
            except RobotsDisallowed:
                raise
            except CaptureError as e:
                attempts.append({"url": url, "error": str(e)})
                continue
            try:
                validate(resp, "html")
                if fid.encode() not in resp.body:
                    raise CaptureError(f"{url} does not mention {fid}")
            except CaptureError as e:
                attempts.append({"url": url, "status": resp.status, "error": str(e)})
                continue
            got = resp
            break
        folder = f"cards/{fid}"
        if got is None:
            manifest["unavailable"].append({"checked_utc": utc_now(), "attempts": attempts})
            store.save_json(rel, manifest)
            tally["unavailable"].append(fid)
            tally["unavailable_reasons"][fid] = fetch_failure_text(attempts)
            continue
        blobs = store.known_blobs()
        stored_at, new = store.store(folder, "card.html", got.body, blobs, time_suffix(got.fetched_utc))
        entry = file_entry("card.html", got)
        entry.update(stored_at=stored_at, newly_stored=new, attempts_before=attempts)
        manifest["fetches"].append(entry)
        pre = extract_preimage(got.body)
        if pre.get("bytes") is not None:
            p_at, p_new = store.store(folder, "preimage.json", pre["bytes"], blobs,
                                      time_suffix(got.fetched_utc))
            manifest["preimages"].append({
                "extracted_from": stored_at, "method": pre["method"], "extracted_utc": got.fetched_utc,
                "size_bytes": len(pre["bytes"]), "sha256": sha256_hex(pre["bytes"]),
                "stored_at": p_at, "newly_stored": p_new})
        store.save_json(rel, manifest)
        tally["fetched"] += 1
        tally["new_copies" if new else "unchanged"] += 1
    return tally


def fetch_failure_text(attempts: list[dict]) -> str:
    parts = []
    for a in attempts:
        what = f"HTTP {a['status']}" if a.get("status") is not None else "no response"
        parts.append(f"{a['url']} ({what}: {a.get('error', '')})".replace(": )", ")"))
    return "the card could not be fetched; addresses tried: " + "; ".join(parts)


def unavailable_reason(code: str, detail: str | None = None) -> dict:
    text = UNAVAILABLE_REASONS[code]
    return {"code": code, "text": f"{text}: {detail}" if detail and detail != text else text}


def write_verifications(root: Path, revealed: dict[str, str], ledger_source: str) -> dict[str, dict]:
    """(Re)write cards/<ID>/verification.json for every revealed finding that has a
    card folder. Deterministic. Returns finding ID -> {"outcome", "card_url"}."""
    store = Archive(root, area="cards")
    out: dict[str, dict] = {}
    base = Path(root) / "cards"
    for d in sorted(p for p in base.glob("*") if p.is_dir()) if base.exists() else []:
        fid = d.name
        manifest = store.load_json(_manifest_rel(fid))
        if manifest is None or fid not in revealed:
            continue
        ledger_hash = revealed[fid]
        rec = {"schema_version": 1, "program": config.PROGRAM, "finding_id": fid, "hash": ledger_hash,
               "ledger_source": ledger_source}
        fetches = manifest.get("fetches", [])
        if not fetches:
            attempts = (manifest.get("unavailable") or [{}])[-1].get("attempts", [])
            r2 = r2_check(None, ledger_hash, None)
            r2["unavailable_reason"] = unavailable_reason(
                "card_not_fetched", fetch_failure_text(attempts).split("; ", 1)[-1] if attempts else None)
            rec.update(card=None, r2=r2, hash_checked_at=None,
                       card_facts=None, notes=["No copy of the card could be fetched; see MANIFEST.json."])
        else:
            card = fetches[-1]
            body = store.read_bytes(card["stored_at"])
            pre = extract_preimage(body)
            method = pre.get("method")
            if pre.get("bytes") is None:
                manual = [p for p in manifest.get("preimages", []) if p.get("method") == "manual download"]
                if manual:
                    pre = {"bytes": store.read_bytes(manual[-1]["stored_at"])}
                    method = "manual download (card had no readable preimage)"
            facts = parse_card(body)
            notes = []
            if patch_before_discovery(facts["dates"]):
                notes.append(f"The card's 'Patch released' date ({facts['dates']['patch_released_date']}) is "
                             f"earlier than its 'Discovered or logged' date "
                             f"({facts['dates']['discovered_or_logged_date']}).")
            if facts["missing_parts"]:
                notes.append("Parts not found on the card: " + ", ".join(facts["missing_parts"]) + ".")
            rec.update(
                card={"stored_at": card["stored_at"], "sha256": card["sha256"],
                      "fetched_utc": card.get("fetched_utc"), "url": card.get("final_url") or card.get("url"),
                      "source": card.get("source", "fetched")},
                r2=r2_check(pre.get("bytes"), ledger_hash, facts["printed_hash"], method,
                            withheld=facts.get("withheld_statement")),
                hash_checked_at=card.get("fetched_utc"),
                card_facts=facts, notes=notes)
            if pre.get("note"):
                rec["notes"].append(pre["note"])
            if rec["r2"]["outcome"] == "preimage_withheld":
                rec["r2"]["withheld_statement_card"] = {"stored_at": card["stored_at"], "sha256": card["sha256"]}
            if rec["r2"]["outcome"] == "unavailable":
                code = "no_ledger_hash" if not ledger_hash else pre.get("code", "no_preimage_link")
                rec["r2"]["unavailable_reason"] = unavailable_reason(code, pre.get("error"))
                rec["card_hints"] = card_hints(body)
        rec["public_records"] = ("Rules R3, R4, R5 and R7 for this finding are in data/verification.json "
                                 "(raw responses under records/).")
        store.save_json(f"cards/{fid}/verification.json", rec)
        url = (rec.get("card") or {}).get("url")
        out[fid] = {"outcome": rec["r2"]["outcome"], "card_url": url,
                    "unavailable_reason": rec["r2"].get("unavailable_reason"),
                    "withheld_statement": rec["r2"].get("withheld_statement")}
    return out


def card_tally(checks: dict[str, dict], revealed: dict[str, str]) -> dict:
    t = {"revealed": len(revealed), "with_card_folder": len(checks), "match": 0, "mismatch": 0,
         "preimage_withheld": 0, "unavailable": 0, "not_checked": len(set(revealed) - set(checks))}
    for c in checks.values():
        t[c["outcome"]] = t.get(c["outcome"], 0) + 1
    return t


def dumps(obj) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False)
