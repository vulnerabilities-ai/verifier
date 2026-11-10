"""Rebuild data/ from captures/ and cards/ (deterministic, no network).

Writes, for each published file, a CSV and a JSON copy in the shape of the
data contract, plus data/schema/<file>.json. Writes only under data/.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path

from .. import config
from ..cards import card_tally, write_verifications
from ..columns import check_published
from ..records_read import RecordReader
from ..wording import check_rows
from .phase3 import policy_source, programs_rows, severity_rows, summary_row, verification_rows
from .schema import FILES, SUMMARY_DOC, columns, schema_doc
from .sources import Sources
from .tables import Builder

SOURCE_TEXT = (f"{config.BASE_URL} (the program's published dashboard and data files), as captured by "
               "the vulnerabilities.ai verifier; see captures/ and METHODOLOGY.md")


class DataWriter:
    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self.data = self.root / "data"

    def _path(self, rel: str) -> Path:
        full = (self.data / rel).resolve()
        if self.data not in full.parents:
            raise ValueError(f"Refusing to write outside data/: {rel}")
        full.parent.mkdir(parents=True, exist_ok=True)
        return full

    def write_text(self, rel: str, text: str) -> None:
        self._path(rel).write_text(text, encoding="utf-8", newline="\n")


def _cell(v):
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (list, dict)):
        return json.dumps(v, ensure_ascii=False)
    return v


def to_csv(rows: list[dict], cols: list[str]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, lineterminator="\n")
    w.writerow(cols)
    for r in rows:
        w.writerow([_cell(r[c]) for c in cols])
    return buf.getvalue()


def to_json(rows: list[dict], generated_utc: str) -> str:
    """The contract's JSON shape, with one row per line (small, and easy to compare
    between versions). It is ordinary JSON: any JSON reader loads it."""
    head = json.dumps({"schema_version": 1, "generated_utc": generated_utc, "source": SOURCE_TEXT,
                       "sample_data": False}, ensure_ascii=False)[:-1]
    body = ",\n".join(json.dumps(r, ensure_ascii=False, separators=(",", ":")) for r in rows)
    return f'{head}, "rows": [\n{body}\n]}}\n' if rows else f'{head}, "rows": []}}\n'


def latest_ledger(src: Sources) -> tuple[str, dict[str, str]]:
    """(ledger path, finding ID -> hash) for revealed findings in our latest capture."""
    states = src.states()
    rel = states[-1]["first_run"].files["ledger.json"]["stored_at"] if states else None
    revealed = {}
    if rel:
        for e in src.load_json_file(rel):
            if e.get("reveal_tier") == "revealed" and e.get("ant_id"):
                revealed[e["ant_id"]] = e["hash"]
    return rel, revealed


def build(root: Path, reader=None) -> dict:
    src = Sources(root)
    ledger_rel, revealed = latest_ledger(src)
    checks = write_verifications(root, revealed, ledger_rel)
    b = Builder(src)
    tables = {
        "snapshots": b.snapshots(),
        "events": b.events(),
        "gaps": b.gaps(),
        "withdrawals": b.withdrawals(),
    }
    # Phase 3: per-finding verification (R2-R5, R7), from stored records only.
    entries = {}
    if ledger_rel:
        for e in src.load_json_file(ledger_rel):
            if e.get("reveal_tier") == "revealed" and e.get("ant_id"):
                entries[e["ant_id"]] = {k: (None if v == "" else v) for k, v in e.items()}
    reader = reader or RecordReader(root)
    tables["verification"] = verification_rows(root, entries, checks, reader)
    fix = {r["finding_id"]: r["fix_merged"] for r in tables["verification"]}
    tables["commitments"] = b.commitments(checks, fix)
    tables["severity"] = severity_rows(tables["verification"])
    tables["programs"] = programs_rows(root, tables["snapshots"])
    summary = summary_row(tables["snapshots"], tables["commitments"], tables["gaps"], tables["withdrawals"],
                          tables["verification"], policy_source(root))
    for name, rows in tables.items():
        check_rows(rows, f"data/{name}")
    check_rows([summary], "data/summary")
    times = [r.fetched("ledger.json") for r in src.runs] + [bf.our_fetch_utc for bf in src.backfills]
    generated = max(times) if times else None
    w = DataWriter(root)
    for name, rows in tables.items():
        cols = columns(name)
        if name != "programs":
            check_published(cols)
        w.write_text(f"{name}.csv", to_csv(rows, cols))
        w.write_text(f"{name}.json", to_json(rows, generated))
        w.write_text(f"schema/{name}.json", json.dumps(schema_doc(name), indent=2, ensure_ascii=False) + "\n")
    w.write_text("summary.json", to_json([summary], generated))
    w.write_text("schema/summary.json", json.dumps(SUMMARY_DOC, indent=2, ensure_ascii=False) + "\n")
    return {"generated_utc": generated, "rows": {k: len(v) for k, v in tables.items()},
            "cards": card_tally(checks, revealed), "tables": tables, "summary": summary}


__all__ = ["build", "FILES", "DataWriter", "to_csv", "to_json", "latest_ledger"]
