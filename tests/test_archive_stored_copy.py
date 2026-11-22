"""Recorded Internet Archive raw-copy mismatches diagnosed from an Archive copy we already store
(same SHA-256), with no request to the Archive; and timed-out diagnostics tried again.

Uses tests/fixtures/ia-stored-copy/: real captured files (see its README). Where a test changes
a copy of them, it says MODIFIED FOR THIS TEST."""

import gzip
import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from verifier.later_receipts import (NOTE_DIAG, _diagnose_earlier_mismatches, _diagnosed, final_raw_result,
                                     reclassify_all)
from verifier.report import _archive_raw_results
from verifier.store import Archive

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests/fixtures/ia-stored-copy"
DAY = "captures/2026/11/08/MANIFEST.json"
RAW = "captures/archive-raw/2026/11/11/dashboard.20261111041608.id_.html"
RID, NAME, TS = "42534385479-1", "dashboard.html", "20261108231652"
ARCHIVE_SHA = "88c5464fb37b8245701a34bb7b6e5898e13ea9f9585611b23eafdcfa4d7ff50c"


class StoredCopy(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        shutil.copytree(FIX / "captures", self.root / "captures")
        self.a = Archive(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def manifest(self):
        return self.a.load_json(DAY)

    def test_real_case_is_identical_after_decompression(self):
        before = self.manifest()
        self.assertEqual(final_raw_result(before, RID, NAME, TS), ("mismatch", None))
        self.assertEqual(hashlib.sha256((self.root / RAW).read_bytes()).hexdigest(), ARCHIVE_SHA)
        notes = reclassify_all(self.a)
        mine = [n for n in notes if n["run_id"] == RID and n["name"] == NAME]
        self.assertEqual(len(mine), 1)
        rc = mine[0]["raw_check"]
        self.assertEqual((mine[0]["note_type"], mine[0]["snapshot_timestamp"]), (NOTE_DIAG, TS))
        self.assertEqual((rc["result"], rc["decoding_method"], rc["raw_sha256"]), ("match_after_decoding", "gzip", ARCHIVE_SHA))
        d = rc["diagnostic"]
        self.assertEqual(d["difference_summary"], "encoding_only (gzip)")
        self.assertEqual(d["archive_copy"]["stored_at"], RAW)
        self.assertIn("no new request to the Archive", d["archive_copy"]["basis"])
        after = self.manifest()
        self.assertEqual(final_raw_result(after, RID, NAME, TS), ("match_after_decoding", "gzip"))
        # records already written are never changed: only notes are appended
        self.assertEqual(after["runs"], before["runs"])
        self.assertEqual(after["appended_notes"][:len(before["appended_notes"])], before["appended_notes"])
        # the weekly report no longer lists it as a difference
        diff, same = _archive_raw_results(self.root)
        self.assertFalse(any(x.startswith("2026-11-08 dashboard.html") for x in diff))
        self.assertIn("2026-11-08 dashboard.html (gzip)", same)
        self.assertEqual(reclassify_all(self.a), [])  # idempotent

    def test_real_content_difference_stays_a_mismatch(self):
        # MODIFIED FOR THIS TEST: the stored Archive copy is replaced by our page with an injected
        # banner, gzip-compressed, and the recorded hashes are pointed at it.
        ours = (self.root / "captures/2026/11/08/dashboard.html").read_bytes()
        fake = gzip.compress(ours.replace(b"<body", b"<div id='wm-toolbar'></div><body", 1), mtime=0)
        sha = hashlib.sha256(fake).hexdigest()
        (self.root / RAW).write_bytes(fake)
        for rel in (DAY, "captures/2026/11/11/MANIFEST.json"):
            p = self.root / rel
            p.write_text(p.read_text().replace(ARCHIVE_SHA, sha))
        notes = [n for n in reclassify_all(Archive(self.root)) if n["run_id"] == RID and n["name"] == NAME]
        self.assertEqual(len(notes), 1)
        rc = notes[0]["raw_check"]
        self.assertEqual(rc["result"], "mismatch")
        self.assertEqual(rc["diagnostic"]["difference_summary"], "other")
        self.assertEqual(final_raw_result(self.manifest(), RID, NAME, TS)[0], "mismatch")

    def test_nothing_without_a_stored_copy(self):
        (self.root / RAW).unlink()  # MODIFIED FOR THIS TEST: the stored Archive copy is missing
        notes = [n for n in reclassify_all(Archive(self.root)) if n["run_id"] == RID and n["name"] == NAME]
        self.assertEqual(notes, [])
        self.assertEqual(final_raw_result(self.manifest(), RID, NAME, TS), ("mismatch", None))


class TimedOutDiagnosticsAreTriedAgain(unittest.TestCase):
    def test_unavailable_does_not_count_as_diagnosed(self):
        unavailable = {"note_type": NOTE_DIAG, "run_id": "R", "name": "x", "snapshot_timestamp": "T",
                       "raw_check": {"result": "unavailable", "error": "TimeoutError: timed out"}}
        reached = {**unavailable, "raw_check": {"result": "mismatch", "diagnostic": {}}}
        self.assertFalse(_diagnosed([unavailable], "R", "x", "T"))
        self.assertTrue(_diagnosed([unavailable, reached], "R", "x", "T"))

    def test_network_pass_retries_after_a_timeout(self):
        # The real 2026-11-08 manifest has a diagnostic note that timed out (2026-11-11).
        m = json.loads((FIX / DAY).read_text())
        notes = m["appended_notes"]
        self.assertTrue(any(n.get("note_type") == NOTE_DIAG and (n.get("raw_check") or {}).get("result") == "unavailable"
                            for n in notes))

        class FakeClient:  # no network: records what would be asked
            on_mismatch = object()
            asked = []

            def raw_check(self, url, ts, our_sha, name):
                self.asked.append((name, ts))
                return {"result": "unavailable", "error": "not fetched in this test"}
        c = FakeClient()
        _diagnose_earlier_mismatches(m, notes, c, skip_run_id=None)
        self.assertIn((NAME, TS), c.asked)


if __name__ == "__main__":
    unittest.main()
