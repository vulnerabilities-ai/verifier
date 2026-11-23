"""The test archive must not change when the live archive grows (new captures, appended notes,
new backfilled snapshots)."""

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import helpers
from helpers import FROZEN_CAPTURE_DIRS, FROZEN_CAPTURES, frozen_archive

ROOT = Path(__file__).resolve().parents[1]


class FrozenCaptures(unittest.TestCase):
    def test_manifests_come_from_the_frozen_copy(self):
        with tempfile.TemporaryDirectory() as t:
            root = frozen_archive(Path(t))
            for rel in FROZEN_CAPTURE_DIRS:
                self.assertEqual((root / rel / "MANIFEST.json").read_bytes(),
                                 (FROZEN_CAPTURES / rel / "MANIFEST.json").read_bytes(), rel)

    def test_1108_manifest_is_from_before_the_2026_11_23_notes(self):
        m = json.loads((FROZEN_CAPTURES / "captures/2026/11/08/MANIFEST.json").read_text())
        types = [n.get("note_type") for n in m.get("appended_notes", [])]
        self.assertEqual(sorted(types), ["archive-raw-diagnostic", "late-archive-receipt"])
        self.assertFalse(any(n.get("appended_utc", "") >= "2026-11-12" for n in m["appended_notes"]))
        same = (ROOT / "tests/fixtures/ia-stored-copy/captures/2026/11/08/MANIFEST.json").read_bytes()
        self.assertEqual((FROZEN_CAPTURES / "captures/2026/11/08/MANIFEST.json").read_bytes(), same)

    def test_live_changes_do_not_reach_the_tests(self):
        # A copy of the repository's live folders gains an appended note, a new day file and a
        # new backfilled snapshot (all MADE UP FOR THIS TEST); the frozen archive stays the same.
        with tempfile.TemporaryDirectory() as t:
            live = Path(t) / "live"
            for rel in FROZEN_CAPTURE_DIRS:
                shutil.copytree(ROOT / rel, live / rel)
            m = live / "captures/2026/11/08/MANIFEST.json"
            d = json.loads(m.read_text())
            d.setdefault("appended_notes", []).append({"note_type": "archive-raw-diagnostic", "made_up_for_test": True})
            m.write_text(json.dumps(d))
            (live / "captures/2026/11/08/extra.txt").write_text("made up for this test")
            (live / "captures/anthropic-archive/2099-01-01-0000").mkdir(parents=True)
            (live / "captures/anthropic-archive/2099-01-01-0000/MANIFEST.json").write_text("{}")
            old = helpers.REPO
            try:
                helpers.REPO = live
                a = frozen_archive(Path(t) / "a")
            finally:
                helpers.REPO = old
            b = frozen_archive(Path(t) / "b")
            files = lambda r: {str(p.relative_to(r)): hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in (r / "captures").rglob("*") if p.is_file()}
            self.assertEqual(files(a), files(b))

    def test_a_changed_raw_file_fails_loudly(self):
        with tempfile.TemporaryDirectory() as t:
            live = Path(t) / "live"
            for rel in FROZEN_CAPTURE_DIRS:
                shutil.copytree(ROOT / rel, live / rel)
            (live / "captures/2026/11/08/dashboard.html").write_bytes(b"changed for this test")
            old = helpers.REPO
            try:
                helpers.REPO = live
                with self.assertRaises(AssertionError):
                    frozen_archive(Path(t) / "a")
            finally:
                helpers.REPO = old


if __name__ == "__main__":
    unittest.main()
