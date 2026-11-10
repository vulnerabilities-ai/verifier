"""Phase 2 tables built from the real archive (Oct 30 golden fixtures and the
Nov 8 capture of revision 40), checked against known numbers."""

import hashlib
import json
import re
import shutil
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from helpers import frozen_archive

from verifier.build import build
from verifier.build.schema import FILES, columns, schema_doc
from verifier.build.sources import MANUAL_BASIS, MANUAL_BOUND_UTC, Sources
from verifier.columns import SNAPSHOT_HEADLINE_COLUMNS

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_DOC = ROOT / "docs/data-contract-additions-phase2.md"
R_B = ROOT / "docs/design-handoff/claude-design-R-B-02-data-contract.md"
R_E = ROOT / "docs/design-handoff/claude-design-R-E-02-data-contract-additions.md"
NOV8_LEDGER_FETCH = None  # read from the manifest below


def _copy_archive(dst: Path):
    frozen_archive(dst)  # fixed inputs: never the live archive's growing state


class RealArchive(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name)
        _copy_archive(cls.root)
        cls.result = build(cls.root)
        cls.t = cls.result["tables"]
        m = json.loads((cls.root / "captures/2026/11/08/MANIFEST.json").read_text())
        files = {f["name"]: f for f in m["runs"][0]["files"]}
        cls.nov8_ledger = files["ledger.json"]["fetched_utc"]
        cls.nov8_payload = files["payload.json"]["fetched_utc"]

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def snap(self, revision, kind="our_capture"):
        return next(s for s in self.t["snapshots"] if s["revision"] == revision and s["source_kind"] == kind)

    # -- snapshots ----------------------------------------------------------------
    def test_five_snapshots(self):
        rows = [(s["revision"], s["source_kind"], s["program_snapshot_label"]) for s in self.t["snapshots"]]
        self.assertEqual(rows, [
            (1, "program_archive_backfill", "2026-05-22-1027"),
            (32, "program_archive_backfill", "2026-08-26-1155"),
            (35, "our_capture", None),
            (35, "program_archive_backfill", "2026-10-02-1947"),
            (40, "our_capture", None)])

    def test_october_numbers(self):
        s = self.snap(35)
        self.assertEqual((s["candidates"], s["confirmed_valid"], s["reported_after_triage"],
                          s["reported_without_review"], s["reported_total"], s["acknowledged"],
                          s["patched_lab_count"], s["advisories"], s["cves"], s["ghsas"],
                          s["projects_reported"], s["ledger_entries"], s["revealed_entries"]),
                         (29439, 5674, 1333, 4824, 6157, 5103, 516, 584, 219, 365, 591, 6597, 237))
        self.assertEqual(s["capture_utc"], MANUAL_BOUND_UTC)
        self.assertEqual(s["first_seen_by_us"], MANUAL_BOUND_UTC)

    def test_november_numbers(self):
        s = self.snap(40)
        self.assertEqual(s["as_of_utc"], "2026-11-02T19:30:24Z")
        self.assertEqual((s["candidates"], s["reported_total"], s["acknowledged"], s["patched_lab_count"],
                          s["ledger_entries"], s["revealed_entries"]),
                         (37966, 5087, 3635, 629, 7349, 237))
        self.assertEqual(s["first_seen_by_us"], self.nov8_payload)
        self.assertTrue(s["first_seen_by_us"].startswith("2026-11-08"))

    def test_backfills_never_first_seen(self):
        for s in self.t["snapshots"]:
            if s["source_kind"] == "program_archive_backfill":
                self.assertIsNone(s["first_seen_by_us"])
                self.assertIn("not evidence of when we first saw", s["note"])

    def test_quirk8_break_marked_on_august_row(self):
        marked = [s["revision"] for s in self.t["snapshots"] if "August 26, 2026" in (s["note"] or "")]
        self.assertEqual(marked, [32])

    # -- commitments and first-seen -------------------------------------------------
    def test_commitments_first_seen(self):
        rows = self.t["commitments"]
        self.assertEqual(len(rows), 7349)
        c = Counter(r["first_seen_by_us"] for r in rows)
        self.assertEqual(c, {MANUAL_BOUND_UTC: 6597, self.nov8_ledger: 752})
        oct30 = next(r for r in rows if r["first_seen_by_us"] == MANUAL_BOUND_UTC)
        self.assertTrue(oct30["first_seen_basis"].startswith(MANUAL_BASIS))
        self.assertIn("first commit on 2026-11-08", oct30["first_seen_basis"])
        new = next(r for r in rows if r["first_seen_by_us"] == self.nov8_ledger)
        self.assertIn("First daily capture containing this hash", new["first_seen_basis"])
        # outside a git checkout the commit time is reported as not available, never guessed
        self.assertIn("GitHub commit time not available at build time", new["first_seen_basis"])

    def test_archive_evidence_and_unresolved_wording(self):
        for r in self.t["commitments"][:50]:
            b = r["first_seen_basis"]
            if "Internet Archive snapshot of ledger.json" in b:
                m = re.search(r"the raw-copy check says (\w+)", b)
                if m:
                    self.assertIn("byte comparison unresolved", b)
                    self.assertIn(m.group(1), ("mismatch", "unavailable", "not"))
            else:
                self.assertIn("no Internet Archive receipt for ledger.json yet", b)

    def test_no_values_for_unrevealed(self):
        for r in self.t["commitments"]:
            if r["tier"] != "revealed":
                self.assertIsNone(r["finding_id"])
                self.assertIsNone(r["project"])
                self.assertIsNone(r["bug_class"])
                self.assertEqual((r["cve_ids"], r["ghsa_ids"]), ([], []))
                self.assertIsNone(r["card_url"])
                self.assertEqual(r["hash_check"], "not_applicable")

    def test_hash_checks(self):
        c = Counter(r["hash_check"] for r in self.t["commitments"] if r["tier"] == "revealed")
        self.assertEqual(c, {"match": 1, "not_checked": 236})
        w = next(r for r in self.t["commitments"] if r["finding_id"] == "ANT-2026-87DJGDRB")
        self.assertEqual(w["hash_check"], "match")
        v = json.loads((self.root / "cards/ANT-2026-87DJGDRB/verification.json").read_text())
        self.assertEqual(v["r2"]["outcome"], "match")
        self.assertEqual(v["hash"], w["hash"])

    # -- events -----------------------------------------------------------------------
    def test_events(self):
        ev = self.t["events"]
        self.assertEqual({e["capture_utc"] for e in ev}, {self.nov8_ledger})  # only our own captures
        status = Counter((e["old_value"], e["new_value"]) for e in ev if e["field"] == "status")
        self.assertEqual(status[("disclosed", "merged")], 1603)
        self.assertEqual(status[("withdrawn", "merged")], 48)
        self.assertEqual(status[(None, "merged")], 1)
        types = Counter(e["event_type"] for e in ev)
        self.assertEqual(types["new_commitment"], 752)
        self.assertEqual(types["removed_commitment"], 0)
        self.assertEqual(types["merged"], 1652)
        self.assertEqual(types["withdrawn"], 219)
        heads = {e["field"]: (e["old_value"], e["new_value"]) for e in ev if e["event_type"] == "headline_change"}
        self.assertEqual(heads["candidates"], ("29439", "37966"))
        self.assertEqual(heads["revision"], ("35", "40"))

    def test_events_withhold_unrevealed_values(self):
        withheld = {"finding_id", "project", "bug_class", "cve_ids", "ghsa_ids", "merged_into"}
        revealed = {r["finding_id"] for r in self.t["commitments"] if r["finding_id"]}
        for e in self.t["events"]:
            if e["field"] in withheld:
                self.assertIn(e["hash_or_finding_id"], revealed)

    # -- gaps and withdrawals -------------------------------------------------------------
    def test_gaps_quirk2_and_label(self):
        g = next(x for x in self.t["gaps"] if x["revision"] == 35 and x["source_kind"] == "our_capture")
        self.assertEqual((g["revealed_itemized"], g["revealed_payload_count"]), (237, 235))
        self.assertEqual((g["reported_flagged_in_ledger"], g["reported_claimed"]), (6154, 6157))
        self.assertEqual((g["withdrawn_flag"], g["withdrawn_status"]), (243, 246))
        self.assertEqual(g["label"], "Independently verified (our count from the program's published files)")
        g40 = next(x for x in self.t["gaps"] if x["revision"] == 40)
        self.assertEqual((g40["merged_status"], g40["merged_with_target"], g40["withdrawn_status"]), (1654, 2, 419))

    def test_three_withdrawal_views(self):
        def view(rev, v):
            return {r["reason"]: r["count"] for r in self.t["withdrawals"]
                    if r["revision"] == rev and r["view"] == v and r["source_kind"] == "our_capture"}
        self.assertEqual(sum(view(35, "by_flag").values()), 243)
        self.assertEqual(view(35, "by_flag")["duplicate"], 83)
        self.assertEqual(sum(view(35, "by_status").values()), 246)
        self.assertEqual(view(35, "by_status")["report_withdrawn"], 3)
        self.assertEqual(view(35, "by_reason_all_entries")["duplicate"], 85)
        self.assertEqual(sum(view(40, "by_flag").values()), 415)
        self.assertEqual(view(40, "by_flag")["duplicate"], 44)
        self.assertEqual(sum(view(40, "by_status").values()), 419)
        self.assertEqual(view(40, "by_status").get(None), 1)
        self.assertEqual(view(40, "by_reason_all_entries")["duplicate"], 1698)
        for r in self.t["withdrawals"]:
            self.assertNotIn("error", json.dumps(r).lower())

    # -- quirks from the October fixtures -----------------------------------------------------
    def test_quirks_3_4_5_6_7(self):
        p = json.loads((ROOT / "captures/2026/10/30/payload.json").read_bytes())
        led = json.loads((ROOT / "captures/2026/10/30/ledger.json").read_bytes())
        self.assertEqual(sum(1 for e in led if e["passed_triage"]), 232)  # quirk 3
        self.assertEqual(sum(1 for e in led if e["vendor_confirmed"]), 232)
        s = self.snap(35)  # quirk 4: the fix rate is fixed of REVEALED
        self.assertEqual((s["program_fix_rate_pct"], s["program_revealed_count"]), (92.8, 235))
        self.assertEqual(round(100 * 218 / 235, 1), 92.8)
        recs = p["revealed"]["cve_records"] + p["revealed"]["ghsa_records"]  # quirk 5: many-to-many
        self.assertTrue(any(len(r["findings"]) == 3 and r["findings"][0]["project"] == "freerdp/freerdp" for r in recs))
        rv = [e for e in led if e["reveal_tier"] == "revealed"]
        both = [e for e in rv if e["cve_ids"] and e["ghsa_ids"]]
        self.assertTrue(both)
        early = [e for e in rv if e["patched_at"] and e["discovered_on"] and e["patched_at"] < e["discovered_on"]]
        self.assertEqual((len(early), sum(1 for e in early if e["is_fixed_in_response"])), (18, 16))  # quirk 6
        for raw in (ROOT / "captures/2026/10/30/payload.json", ROOT / "captures/2026/10/30/ledger.json"):
            self.assertNotEqual(hashlib.sha3_512(raw.read_bytes()).hexdigest(), p["manifest_sha3"])  # quirk 7

    # -- published files ----------------------------------------------------------------------
    def test_files_and_shape(self):
        for name in FILES:
            doc = json.loads((self.root / "data" / f"{name}.json").read_text())
            self.assertEqual(set(doc), {"schema_version", "generated_utc", "source", "sample_data", "rows"})
            self.assertFalse(doc["sample_data"])
            self.assertEqual(len(doc["rows"]), len(self.t[name]))
            header = (self.root / "data" / f"{name}.csv").read_text().splitlines()[0].split(",")
            self.assertEqual(header, columns(name))
            self.assertEqual(header[0], "program")

    def test_deterministic(self):
        before = {p.name: p.read_bytes() for p in (self.root / "data").rglob("*") if p.is_file()}
        build(self.root)
        after = {p.name: p.read_bytes() for p in (self.root / "data").rglob("*") if p.is_file()}
        self.assertEqual(before, after)


class Neutrality(unittest.TestCase):
    """Published column names and schema entry names are program-neutral.
    The schema's source_field values keep the program's own names (attribution)."""

    BANNED = ("anthropic", "claude", "ant_")

    def test_column_and_schema_names(self):
        for name in FILES:
            cols = columns(name)
            self.assertEqual(cols[0], "program")
            for c in cols:
                for b in self.BANNED:
                    self.assertNotIn(b, c.lower(), f"{name}.{c}")
            for entry in schema_doc(name)["columns"]:
                for b in self.BANNED:
                    self.assertNotIn(b, entry["name"].lower())
            self.assertEqual([e["name"] for e in schema_doc(name)["columns"]], cols)

    def test_source_fields_keep_attribution(self):
        src = {e["name"]: e["source_field"] for e in schema_doc("commitments")["columns"]}
        self.assertEqual(src["finding_id"], "ant_id")
        self.assertEqual(src["model_severity"], "claude_severity")

    def test_every_column_documented(self):
        for name in FILES:
            for e in schema_doc(name)["columns"]:
                self.assertTrue(e["meaning"], f"{name}.{e['name']}")


class ContractDocument(unittest.TestCase):
    def test_every_new_column_is_documented(self):
        known = set(re.findall(r"\b[a-z][a-z0-9_]+\b", R_B.read_text() + R_E.read_text()))
        doc = CONTRACT_DOC.read_text()
        for name in FILES:
            for c in columns(name):
                if c not in known or name == "withdrawals":
                    self.assertIn(f"`{c}`", doc, f"{name}.{c} is not in {CONTRACT_DOC.name}")
        for word in ("field_change", "removed_commitment", "withdrawals", "data/schema/",
                     "program_snapshot_label", "unavailable", MANUAL_BOUND_UTC):
            self.assertIn(word, doc)


class GitEvidence(unittest.TestCase):
    """Commit times are read from the real repository's history."""

    def test_first_commit_times(self):
        src = Sources(ROOT)
        oct30 = src.git_first_commit_utc("captures/2026/10/30/ledger.json")
        nov8 = src.git_first_commit_utc("captures/2026/11/08/ledger.json")
        if oct30 is None:
            self.skipTest("not a full git checkout")
        self.assertEqual(oct30, "2026-11-08T16:51:21Z")
        self.assertEqual(nov8, "2026-11-08T23:18:20Z")


class HeadlineColumnsUnchanged(unittest.TestCase):
    def test_headline_columns(self):
        self.assertEqual(SNAPSHOT_HEADLINE_COLUMNS[0], "program")


if __name__ == "__main__":
    unittest.main()
