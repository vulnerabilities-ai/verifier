"""Build the published rows from the archive. Deterministic: the same captures,
cards and git history give the same rows."""

from __future__ import annotations

import json
from collections import Counter

from .. import config
from ..parse_headline import parse_headline
from .schema import GAPS_LABEL, columns
from .sources import MANUAL_BASIS, MANUAL_BOUND_UTC, Sources

PROGRAM = config.PROGRAM
BREAK_AS_OF = "2026-08-26"
BREAK_NOTE = ("First snapshot after the program's August 26, 2026 update: dates change from Pacific time to "
              "UTC, and the card label 'Reported to tracker' becomes 'Discovered or logged'. Values before "
              "and after this point are not directly comparable.")
MANUAL_NOTE = ("Jon's manual capture on 2026-10-30; time of day not recorded, so capture_utc is the "
               "end-of-day bound.")
BACKFILL_NOTE = ("Copy of the program's own archived snapshot, copied by us at capture_utc; not evidence of when "
                 "we first saw anything.")

# Program's ledger field -> published field name (events "field" column).
FIELD_NAMES = {
    "ant_id": "finding_id", "claude_severity": "model_severity", "reveal_tier": "tier",
    "is_fixed_in_response": "fixed_in_response", "vendor_confirmed": "firm_confirmed",
    "vendor_severity": "firm_severity", "vendor_severity_sealed": "firm_severity_sealed",
}
# Never published for an entry that is not revealed.
WITHHELD_UNLESS_REVEALED = {"ant_id", "project", "bug_class", "cve_ids", "ghsa_ids",
                            "corrected_cve_ids", "corrected_ghsa_ids", "merged_into", "superseded_by"}


def _blank(v):
    return None if v == "" else v


def _norm(entry: dict) -> dict:
    return {k: _blank(v) for k, v in entry.items()}


def _text(v) -> str | None:
    if v is None:
        return None
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (list, dict)):
        return json.dumps(v, ensure_ascii=False, sort_keys=True)
    return str(v)


class Builder:
    def __init__(self, src: Sources):
        self.src = src
        self.states = src.states()

    # -- snapshot definitions shared by snapshots, gaps and withdrawals --------
    def snapshot_defs(self) -> list[dict]:
        if getattr(self, "_defs", None) is None:
            self._defs = self._snapshot_defs()
        return self._defs

    def _snapshot_defs(self) -> list[dict]:
        defs, seen = [], set()
        for st in self.states:
            r = st["first_run"]
            psha = r.files["payload.json"]["sha256"]
            if psha in seen:
                continue
            seen.add(psha)
            defs.append({"source_kind": "our_capture", "label": None,
                         "payload": r.files["payload.json"]["stored_at"],
                         "ledger": r.files["ledger.json"]["stored_at"],
                         "dashboard": r.files["dashboard.html"],
                         "capture_utc": r.fetched("dashboard.html"),
                         "first_seen": r.fetched("payload.json"),
                         "note": MANUAL_NOTE if r.manual else None})
        for b in self.src.backfills:
            if "data/payload.json" not in b.files:
                continue
            defs.append({"source_kind": "program_archive_backfill", "label": b.label,
                         "payload": b.files["data/payload.json"]["stored_at"],
                         "ledger": (b.files.get("data/ledger.json") or {}).get("stored_at"),
                         "dashboard": b.files["index.html"],
                         "capture_utc": b.our_fetch_utc, "first_seen": None, "note": BACKFILL_NOTE})
        for d in defs:
            d["payload_obj"] = self.src.load_json_file(d["payload"])
            d["ledger_obj"] = (self.src.load_json_file(d["ledger"]) if d["ledger"]
                               else d["payload_obj"]["ledger"])
        defs.sort(key=lambda d: (d["payload_obj"]["as_of"], d["source_kind"] != "our_capture",
                                 d["capture_utc"]))
        first_after_break = next((d for d in defs if d["payload_obj"]["as_of"][:10] >= BREAK_AS_OF), None)
        if first_after_break is not None:
            first_after_break["break"] = True
        return defs

    # -- snapshots -----------------------------------------------------------------
    def snapshots(self) -> list[dict]:
        rows = []
        for d in self.snapshot_defs():
            note = " ".join(n for n in (d["note"], BREAK_NOTE if d.get("break") else None) if n) or None
            row = parse_headline(d["payload_obj"], capture_utc=d["capture_utc"],
                                 source_sha256=d["dashboard"]["sha256"], note=note)
            row.update(source_kind=d["source_kind"], program_snapshot_label=d["label"],
                       first_seen_by_us=d["first_seen"])
            rows.append({c: row[c] for c in columns("snapshots")})
        return rows

    # -- gaps and withdrawals ---------------------------------------------------------
    def gaps(self) -> list[dict]:
        rows = []
        for d in self.snapshot_defs():
            p, led = d["payload_obj"], [_norm(e) for e in d["ledger_obj"]]
            h = p["headline"]
            has_flag = any("withdrawn" in e for e in led)

            def ids(*keys):
                return len({x for e in led for k in keys for x in (e.get(k) or [])})
            rows.append({
                "program": PROGRAM, "capture_utc": d["capture_utc"], "revision": p["revision"],
                "source_kind": d["source_kind"], "program_snapshot_label": d["label"],
                "patched_claimed": h["fixed_in_response"],
                "patched_itemized": sum(1 for e in led if e.get("is_fixed_in_response")),
                "cves_claimed": h["cves"], "cves_itemized": ids("cve_ids", "corrected_cve_ids"),
                "ghsas_claimed": h["ghsas"], "ghsas_itemized": ids("ghsa_ids", "corrected_ghsa_ids"),
                "reported_claimed": h["disclosed"],
                "reported_flagged_in_ledger": sum(1 for e in led if e.get("was_disclosed")),
                "revealed_itemized": sum(1 for e in led if e.get("reveal_tier") == "revealed"),
                "revealed_payload_count": p["revealed"]["count"],
                "withdrawn_flag": sum(1 for e in led if e.get("withdrawn")) if has_flag else None,
                "withdrawn_status": sum(1 for e in led if e.get("status") == "withdrawn"),
                "merged_status": sum(1 for e in led if e.get("status") == "merged"),
                "merged_with_target": sum(1 for e in led if e.get("status") == "merged" and e.get("merged_into")),
                "label": GAPS_LABEL,
            })
        return [{c: r[c] for c in columns("gaps")} for r in rows]

    def withdrawals(self) -> list[dict]:
        rows = []
        for d in self.snapshot_defs():
            led = [_norm(e) for e in d["ledger_obj"]]
            views = {
                "by_flag": [e for e in led if e.get("withdrawn")],
                "by_status": [e for e in led if e.get("status") == "withdrawn"],
                "by_reason_all_entries": [e for e in led if e.get("withdrawn_reason")],
            }
            for view, entries in views.items():
                counts = Counter(e.get("withdrawn_reason") for e in entries)
                for reason in sorted(counts, key=lambda r: (r is None, r or "")):
                    rows.append({"program": PROGRAM, "capture_utc": d["capture_utc"],
                                 "revision": d["payload_obj"]["revision"], "source_kind": d["source_kind"],
                                 "program_snapshot_label": d["label"], "view": view, "reason": reason,
                                 "count": counts[reason]})
        return rows

    # -- first-seen and evidence ---------------------------------------------------------
    def _ledger_hashes(self, rel: str) -> set[str]:
        return {e["hash"] for e in self.src.load_json_file(rel)}

    def first_seen(self) -> dict[str, dict]:
        """hash -> {"utc", "basis"} from our own captures only."""
        out: dict[str, dict] = {}
        receipts_by_ledger: dict[str, list] = {}
        for r in self.src.runs:
            rec = self.src.archive_receipt(r, "ledger.json")
            if rec:
                receipts_by_ledger.setdefault(r.files["ledger.json"]["stored_at"], []).append(rec)
        ledger_sets = {}
        for st in self.states:
            rel = st["first_run"].files["ledger.json"]["stored_at"]
            ledger_sets.setdefault(rel, self._ledger_hashes(rel))
        for st in self.states:
            r = st["first_run"]
            rel = r.files["ledger.json"]["stored_at"]
            for h in ledger_sets[rel]:
                if h not in out:
                    out[h] = {"run": r, "utc": r.fetched("ledger.json"), "ledger": rel}
        # earliest Archive receipt among ledgers that contain the hash
        best: dict[str, dict] = {}
        # The same Archive snapshot can be checked by several runs (it reuses snapshots);
        # use the latest raw-check result recorded for it, in capture order.
        # A later definite result replaces an earlier one; "unavailable" never replaces a definite one.
        latest_result: dict[str, tuple] = {}
        for recs in receipts_by_ledger.values():
            for x in recs:
                if not x["raw_result"]:
                    continue
                prev = latest_result.get(x["snapshot_utc"])
                if prev is None or x["raw_result"] != "unavailable":
                    latest_result[x["snapshot_utc"]] = (x["raw_result"], x.get("raw_method"))
        for rel, recs in receipts_by_ledger.items():
            earliest = dict(min(recs, key=lambda x: x["snapshot_utc"]))
            earliest["raw_result"], earliest["raw_method"] = latest_result.get(
                earliest["snapshot_utc"], (earliest["raw_result"], earliest.get("raw_method")))
            for h in ledger_sets.get(rel, self._ledger_hashes(rel)):
                if h not in best or earliest["snapshot_utc"] < best[h]["snapshot_utc"]:
                    best[h] = earliest
        cache: dict[tuple, str] = {}
        for h, fs in out.items():
            rec = best.get(h)
            key = (fs["ledger"], fs["utc"], json.dumps(rec, sort_keys=True))
            if key not in cache:
                cache[key] = self._basis(fs["run"], fs["ledger"], fs["utc"], rec)
            fs["basis"] = cache[key]
        return out

    def _basis(self, run, ledger_rel: str, fetched: str, rec: dict | None) -> str:
        commit = self.src.git_first_commit_utc(ledger_rel)
        git_part = (f"GitHub commit of that capture at {commit}" if commit
                    else "GitHub commit time not available at build time")
        if rec:
            a = f"Internet Archive snapshot of ledger.json dated {rec['snapshot_utc']} (requested by our run of {rec['run_day']})"
            if rec["snapshot_utc"] < fetched:
                a += ", an existing snapshot the Archive reused, dated before our fetch"
            if rec["raw_result"] == "match":
                a += "; its raw copy is byte-identical to ours"
            elif rec["raw_result"] == "match_after_decoding":
                a += (f"; the Internet Archive's copy is identical to ours after decompression "
                      f"({rec.get('raw_method') or 'method not recorded'})")
            else:
                a += f"; byte comparison unresolved (the raw-copy check says {rec['raw_result'] or 'not yet checked'})"
        else:
            a = "no Internet Archive receipt for ledger.json yet"
        if run.manual:
            return f"{MANUAL_BASIS} {git_part[0].upper()}{git_part[1:]}. {a[0].upper()}{a[1:]}."
        return (f"First daily capture containing this hash: ledger.json fetched {fetched} "
                f"(run {run.run_id}, {run.manifest.rsplit('/', 1)[0]}). Earliest independent evidence "
                f"at build time: {git_part}; {a}.")

    # -- commitments --------------------------------------------------------------------------
    def commitments(self, card_checks: dict[str, dict], fix_merged: dict[str, str] | None = None) -> list[dict]:
        latest: dict[str, dict] = {}
        for st in self.states:
            for e in self.src.load_json_file(st["first_run"].files["ledger.json"]["stored_at"]):
                latest[e["hash"]] = _norm(e)
        revealed_ids = {e["ant_id"] for e in latest.values() if e.get("reveal_tier") == "revealed" and e.get("ant_id")}
        fs = self.first_seen()
        rows = []
        for h, e in latest.items():
            rev = e.get("reveal_tier") == "revealed"
            fid = e.get("ant_id") if rev else None
            check = card_checks.get(fid) if fid else None
            rows.append({
                "program": PROGRAM, "hash": h, "hash_short": h[:12], "committed_at": e.get("committed_at"),
                "first_seen_by_us": fs[h]["utc"], "first_seen_basis": fs[h]["basis"],
                "tier": e.get("reveal_tier"), "status": e.get("status"), "withdrawn": e.get("withdrawn"),
                "withdrawn_reason": e.get("withdrawn_reason"),
                "merged_into": e.get("merged_into") if e.get("merged_into") in revealed_ids else None,
                "model_severity": e.get("claude_severity"), "revealed": e.get("revealed"),
                "finding_id": fid,
                "project": e.get("project") if rev else None,
                "bug_class": e.get("bug_class") if rev else None,
                "cve_ids": (e.get("cve_ids") or []) if rev else [],
                "ghsa_ids": (e.get("ghsa_ids") or []) if rev else [],
                "fixed_in_response": e.get("is_fixed_in_response") if rev else None,
                "patched_at": e.get("patched_at") if rev else None,
                "revealed_at": e.get("revealed_at") if rev else None,
                "card_url": ((check or {}).get("card_url") or f"{config.BASE_URL}findings/{fid}.html") if rev else None,
                "hash_check": (check or {}).get("outcome", "not_checked") if rev else "not_applicable",
                "fix_merged": ((fix_merged or {}).get(fid) or "not_checked") if rev else "not_applicable",
            })
        rows.sort(key=lambda r: (r["committed_at"] or "", r["hash"]), reverse=True)
        return [{c: r[c] for c in columns("commitments")} for r in rows]

    # -- events ----------------------------------------------------------------------------------
    def events(self) -> list[dict]:
        rows = []
        for prev, cur in zip(self.states, self.states[1:]):
            r = cur["first_run"]
            when = r.fetched("ledger.json")
            a = {e["hash"]: _norm(e) for e in self.src.load_json_file(prev["first_run"].files["ledger.json"]["stored_at"])}
            b = {e["hash"]: _norm(e) for e in self.src.load_json_file(r.files["ledger.json"]["stored_at"])}

            def ident(h, entry):
                return entry.get("ant_id") if entry.get("reveal_tier") == "revealed" and entry.get("ant_id") else h
            for h in sorted(set(b) - set(a)):
                rows.append(self._event(when, "new_commitment", ident(h, b[h]), None, None, b[h].get("reveal_tier")))
            for h in sorted(set(a) - set(b)):
                rows.append(self._event(when, "removed_commitment", ident(h, a[h]), None, a[h].get("reveal_tier"), None))
            for h in sorted(set(a) & set(b)):
                old, new = a[h], b[h]
                revealed_now = new.get("reveal_tier") == "revealed"
                for k in sorted(set(old) | set(new)):
                    if k == "hash" or old.get(k) == new.get(k):
                        continue
                    if k in WITHHELD_UNLESS_REVEALED and not revealed_now:
                        continue
                    name = FIELD_NAMES.get(k, k)
                    if k == "status":
                        t = {"merged": "merged", "withdrawn": "withdrawn"}.get(new.get(k), "status_change")
                    elif k == "reveal_tier" and new.get(k) == "revealed":
                        t = "revealed"
                    else:
                        t = "field_change"
                    rows.append(self._event(when, t, ident(h, new), name, old.get(k), new.get(k)))
            ha = parse_headline(self.src.load_json_file(prev["first_run"].files["payload.json"]["stored_at"]),
                                capture_utc=None, source_sha256=None)
            hb = parse_headline(self.src.load_json_file(r.files["payload.json"]["stored_at"]),
                                capture_utc=None, source_sha256=None)
            for k in ha:
                if k in ("program", "capture_utc", "source_sha256", "label", "note"):
                    continue
                if ha[k] != hb[k]:
                    rows.append(self._event(when, "headline_change", None, k, ha[k], hb[k]))
        return [{c: r[c] for c in columns("events")} for r in rows]

    @staticmethod
    def _event(when, etype, ident, field, old, new) -> dict:
        return {"program": PROGRAM, "capture_utc": when, "event_type": etype, "hash_or_finding_id": ident,
                "field": field, "old_value": _text(old), "new_value": _text(new)}
