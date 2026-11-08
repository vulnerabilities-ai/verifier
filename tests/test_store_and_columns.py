"""Write guards (only captures/, never overwrite) and published column names."""

import tempfile
import unittest
from pathlib import Path

from verifier.columns import FORBIDDEN_PUBLISHED, SNAPSHOT_COLUMNS, check_published
from verifier.parse_headline import FormatChanged, parse_headline
from verifier.store import Archive, PathOutsideCaptures


class WriteGuards(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.a = Archive(Path(self.tmp.name))

    def tearDown(self):
        self.tmp.cleanup()

    def test_refuses_outside_captures(self):
        for bad in ["data/x.csv", "README.md", "captures/../README.md", "/etc/x", "captures"]:
            with self.subTest(path=bad), self.assertRaises(PathOutsideCaptures):
                self.a.write_raw(bad, b"x")

    def test_never_overwrites_raw(self):
        self.a.write_raw("captures/2026/11/09/payload.json", b"1")
        with self.assertRaises(FileExistsError):
            self.a.write_raw("captures/2026/11/09/payload.json", b"2")

    def test_metadata_names_only(self):
        with self.assertRaises(PathOutsideCaptures):
            self.a.write_metadata("captures/2026/11/09/payload.json", "x")
        with self.assertRaises(PathOutsideCaptures):
            self.a.write_raw("captures/2026/11/09/MANIFEST.json", b"x")


class PublishedColumns(unittest.TestCase):
    def test_snapshot_columns_are_program_neutral(self):
        self.assertEqual(SNAPSHOT_COLUMNS[0], "program")
        self.assertFalse(set(SNAPSHOT_COLUMNS) & FORBIDDEN_PUBLISHED)
        self.assertIn("program_fix_rate_pct", SNAPSHOT_COLUMNS)
        self.assertIn("program_revealed_count", SNAPSHOT_COLUMNS)
        for c in SNAPSHOT_COLUMNS:
            self.assertNotIn("anthropic", c)
            self.assertNotIn("claude", c)

    def test_check_rejects_anthropic_names(self):
        for bad in FORBIDDEN_PUBLISHED:
            with self.subTest(name=bad), self.assertRaises(ValueError):
                check_published(["program", bad])
        with self.assertRaises(ValueError):
            check_published(["finding_id", "program"])

    def test_parser_fails_loudly_on_format_change(self):
        with self.assertRaises(FormatChanged):
            parse_headline(b'{"ledger": [], "as_of": "2026-10-02T00:00:00Z"}',
                           capture_utc=None, source_sha256=None)


if __name__ == "__main__":
    unittest.main()
