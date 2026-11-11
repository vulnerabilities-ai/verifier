"""Internet Archive raw copies identical to ours after decompression (match_after_decoding).

Uses frozen copies of the real Nov 9, 10 and 11 capture records, whose diagnostics
show gzip compression as the only difference for several files."""

import gzip
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from helpers import CaptureCase, frozen_archive

from verifier.build import build
from verifier.later_receipts import NOTE_RECLASS, final_raw_result, reclassify_all
from verifier.report import weekly_report
from verifier.store import Archive

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests/fixtures/archive-diagnostics"
DAYS = ("09", "10", "11")
# (day, run id, file) whose real diagnostic says identical_after_decoding = true (gzip)
IDENTICAL = {
    ("09", "42694845658-1", "ledger.json"), ("09", "42694845658-1", "payload.json"),
    ("10", "42776268283-1", "ledger.json"),
    ("11", "42981029552-1", "dashboard.html"), ("11", "42981029552-1", "ledger.json"),
}


class RealDiagnostics(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = frozen_archive(Path(self.tmp.name))
        for d in DAYS:
            (self.root / f"captures/2026/11/{d}").mkdir(parents=True)
            shutil.copy(FIX / d / "MANIFEST.json", self.root / f"captures/2026/11/{d}/MANIFEST.json")
        self.archive = Archive(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def manifest(self, d):
        return json.loads((self.root / f"captures/2026/11/{d}/MANIFEST.json").read_text())

    def test_real_diagnostic_shapes(self):
        # The fixtures carry the real shape: result "mismatch" plus a diagnostic saying gzip.
        found = set()
        for d in DAYS:
            m = self.manifest(d)
            checks = [(r["run_id"], i["name"], i["receipt"]["raw_check"]) for r in m["runs"]
                      for i in (r.get("internet_archive") or {}).get("items", []) if (i.get("receipt") or {}).get("raw_check")]
            checks += [(n["run_id"], n["name"], n.get("raw_check") or {}) for n in m.get("appended_notes", [])]
            for rid, name, rc in checks:
                dg = rc.get("diagnostic") or {}
                if dg.get("identical_after_decoding") is True:
                    self.assertEqual(rc["result"], "mismatch")
                    self.assertEqual(dg["decoding_method"], "gzip")
                    self.assertEqual(dg["difference_summary"], "encoding_only (gzip)")
                    found.add((d, rid, name))
        self.assertEqual(found, IDENTICAL)

    def test_later_note_records_match_after_decoding_without_editing(self):
        before = {d: self.manifest(d) for d in DAYS}
        notes = reclassify_all(self.archive)
        got = {(n["run_id"], n["name"]) for n in notes}
        self.assertEqual(got, {(rid, name) for _, rid, name in IDENTICAL})
        for n in notes:
            self.assertEqual((n["note_type"], n["result"], n["decoding_method"]),
                             (NOTE_RECLASS, "match_after_decoding", "gzip"))
        for d in DAYS:
            after = self.manifest(d)
            self.assertEqual(after["runs"], before[d]["runs"])  # run records untouched
            old = before[d].get("appended_notes", [])
            self.assertEqual(after.get("appended_notes", [])[:len(old)], old)  # old notes untouched
        self.assertEqual(reclassify_all(self.archive), [])  # not repeated

    def test_final_results(self):
        reclassify_all(self.archive)
        m10, m11 = self.manifest("10"), self.manifest("11")
        self.assertEqual(final_raw_result(m11, "42981029552-1", "dashboard.html", None), ("match_after_decoding", "gzip"))
        self.assertEqual(final_raw_result(m11, "42981029552-1", "payload.json", None)[0], "unavailable")
        self.assertEqual(final_raw_result(m10, "42776268283-1", "ledger.json", None), ("match_after_decoding", "gzip"))
        # Nov 10 dashboard: recorded mismatch; the later re-fetch was unavailable. Stays mismatch.
        self.assertEqual(final_raw_result(m10, "42776268283-1", "dashboard.html", None)[0], "mismatch")

    def test_first_seen_basis_wording(self):
        rows = build(self.root)["tables"]["commitments"]
        self.assertTrue(all("byte comparison unresolved (the raw-copy check says mismatch)" in r["first_seen_basis"]
                            for r in rows))  # before the later notes exist
        reclassify_all(self.archive)
        rows = build(self.root)["tables"]["commitments"]
        for r in rows:
            self.assertIn("the Internet Archive's copy is identical to ours after decompression (gzip)",
                          r["first_seen_basis"])
            self.assertNotIn("unresolved", r["first_seen_basis"])

    def test_report(self):
        reclassify_all(self.archive)
        build(self.root)
        text = weekly_report(self.root, "2026-01-01")
        self.assertIn("Internet Archive copies identical to ours after decompression: 5", text)
        item = next(l for l in text.splitlines() if "raw copy differed from ours" in l)
        self.assertIn("unresolved or showing a real content difference", item)
        for listed in ("2026-11-08 dashboard.html", "2026-11-10 dashboard.html", "2026-11-10 payload.json"):
            self.assertIn(listed, item)
        for not_listed in ("2026-11-11", "2026-11-09", "2026-11-10 ledger.json"):
            self.assertNotIn(not_listed, item)
        self.assertIsNone(re.search(r"\blate\b", text))


class LiveRawCheck(CaptureCase):
    def test_gzip_copy_is_match_after_decoding_real_difference_is_mismatch(self):
        url = self.base
        self.ia.raw_override[url] = gzip.compress(self.ia.content[url], mtime=0)
        self.ia.raw_override[self.base + "data/ledger.json"] = b'["really different"]'
        out = self.capture()
        m = json.loads(sorted((self.root / "captures").glob("2*/*/*/MANIFEST.json"))[-1].read_text())
        items = {i["name"]: i for i in m["runs"][0]["internet_archive"]["items"]}
        dash = items["dashboard.html"]["receipt"]["raw_check"]
        self.assertEqual((dash["result"], dash["decoding_method"]), ("match_after_decoding", "gzip"))
        self.assertTrue(dash["diagnostic"]["identical_after_decoding"])
        self.assertEqual(items["ledger.json"]["receipt"]["raw_check"]["result"], "mismatch")
        warnings = " ".join(out.warnings)
        self.assertNotIn("dashboard.html differs", warnings)
        self.assertIn("ledger.json differs", warnings)


if __name__ == "__main__":
    unittest.main()
