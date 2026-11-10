"""Diagnostic for Internet Archive raw-copy mismatches (phase 2, item 0)."""

import gzip
import json
import unittest

from helpers import CaptureCase, files_under

from verifier.archive_diag import diagnose, first_difference
from verifier.audit import audit

OURS = b'{"b": [1, 2], "a": "x\\u2192y"}\n'


class DiagnoseUnit(unittest.TestCase):
    def test_labels(self):
        cases = {
            "line_endings_only": OURS.replace(b"\n", b"\r\n"),
            "whitespace_only": OURS.replace(b", ", b",    "),
            "encoding_only (gzip)": gzip.compress(OURS, mtime=0),
            "encoding_only (utf8_byte_order_mark)": b"\xef\xbb\xbf" + OURS,
            "json_semantically_identical": b'{"a":"x\\u2192y","b":[1,2]}',
            "other": OURS.replace(b"1", b"7"),
        }
        for label, theirs in cases.items():
            with self.subTest(label=label):
                d = diagnose(OURS, theirs)
                self.assertEqual(d["difference_summary"], label)
                self.assertEqual(d["our_size"], len(OURS))
                self.assertEqual(d["archive_size"], len(theirs))
                self.assertEqual(d["first_difference_offset"], first_difference(OURS, theirs))

    def test_json_fields(self):
        d = diagnose(OURS, b'{"a":"x\\u2192y","b":[1,2]}')
        self.assertTrue(d["our_parses_as_json"] and d["archive_parses_as_json"])
        self.assertTrue(d["json_semantically_identical"])
        d = diagnose(b"<html>a</html>", b"<html>b</html>")
        self.assertFalse(d["our_parses_as_json"])
        self.assertIsNone(d["json_semantically_identical"])

    def test_offsets(self):
        self.assertEqual(first_difference(b"abcd", b"abXd"), 2)
        self.assertEqual(first_difference(b"abc", b"abcdef"), 3)  # prefix: the shorter length
        self.assertIsNone(first_difference(b"same", b"same"))


def ia_items(root):
    m = sorted((root / "captures").glob("2*/*/*/MANIFEST.json"))[-1]
    return json.loads(m.read_text()), m


class DiagnosticInCapture(CaptureCase):
    def test_mismatch_saved_and_described_reporting_unchanged(self):
        url = self.base  # the dashboard
        ours = self.ia.content[url]
        self.ia.raw_override[url] = ours.replace(b"<body>", b"<body>\r\n")
        out = self.capture()
        self.assertEqual(out.status, "ok")  # unchanged: mismatch never changes the status
        self.assertTrue(any("differs from ours" in w for w in out.warnings))  # unchanged warning
        m, _ = ia_items(self.root)
        dash = m["runs"][0]["internet_archive"]["items"][0]
        rc = dash["receipt"]["raw_check"]
        self.assertEqual(rc["result"], "mismatch")  # unchanged
        d = rc["diagnostic"]
        self.assertEqual(d["difference_summary"], "whitespace_only")
        self.assertEqual(d["first_difference_offset"], ours.index(b"<body>") + 6)
        saved = self.root / d["saved_copy"]["stored_at"]
        self.assertTrue(d["saved_copy"]["stored_at"].startswith("captures/archive-raw/"))
        self.assertEqual(saved.read_bytes(), self.ia.raw_override[url])
        self.assertEqual(audit(self.root), [])

    def test_saved_copy_never_overwritten_and_not_duplicated(self):
        url = self.base
        self.ia.behaviour = "reuse"  # same snapshot every run
        self.ia.raw_override[url] = b"<html>archive version one</html>"
        self.capture(run_id="r1")
        first = [f for f in files_under(self.root) if "archive-raw" in f]
        self.assertEqual(len(first), 1)
        original = (self.root / first[0]).read_bytes()
        self.capture(run_id="r2")  # identical bytes again: referenced, not saved twice
        self.assertEqual([f for f in files_under(self.root) if "archive-raw" in f], first)
        self.ia.raw_override[url] = b"<html>archive version two</html>"
        self.capture(run_id="r3")  # different bytes, same snapshot: a new file
        now = [f for f in files_under(self.root) if "archive-raw" in f]
        self.assertEqual(len(now), 2)
        self.assertEqual((self.root / first[0]).read_bytes(), original)
        self.assertEqual(audit(self.root), [])

    def test_earlier_mismatch_is_diagnosed_later_by_appended_note(self):
        url = self.base
        self.ia.raw_override[url] = b"<html>different</html>"
        self.capture(run_id="r1")
        m, path = ia_items(self.root)
        # Simulate a record made before this diagnostic existed (as on Nov 10).
        for item in m["runs"][0]["internet_archive"]["items"]:
            rc = (item.get("receipt") or {}).get("raw_check") or {}
            saved = rc.pop("diagnostic", {}).get("saved_copy")
            if saved:
                (self.root / saved["stored_at"]).unlink()
        path.write_text(json.dumps(m, indent=2))
        before = json.loads(path.read_text())
        self.capture(run_id="r2")
        after = json.loads(path.read_text())
        self.assertEqual(after["runs"][0], before["runs"][0])  # the old record is untouched
        notes = [n for n in after.get("appended_notes", []) if n["note_type"] == "archive-raw-diagnostic"]
        self.assertEqual([(n["run_id"], n["name"]) for n in notes], [("r1", "dashboard.html")])
        self.assertEqual(notes[0]["raw_check"]["result"], "mismatch")
        self.assertEqual(notes[0]["raw_check"]["diagnostic"]["difference_summary"], "other")
        self.assertEqual(audit(self.root), [])
        # Not repeated by a third run.
        self.capture(run_id="r3")
        again = json.loads(path.read_text())
        self.assertEqual(len([n for n in again["appended_notes"] if n["note_type"] == "archive-raw-diagnostic"]), 1)


if __name__ == "__main__":
    unittest.main()
