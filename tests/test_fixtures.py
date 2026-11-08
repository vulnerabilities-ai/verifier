"""Golden fixtures: Jon's manual capture of October 30, 2026 (spec section 7)."""

import hashlib
import json
import unittest
from pathlib import Path

from verifier.audit import audit
from verifier.parse_headline import parse_headline, tier_counts

ROOT = Path(__file__).resolve().parents[1]
DAY = ROOT / "captures" / "2026" / "10" / "30"

GOLDEN_SHA256 = {
    "dashboard.html": "07570f8dffddefd8a8ee27a5870aa90331eff2cdad13a64a1f35a71d57f93b64",
    "about.html": "c022329f17815b0eb09e3773dea3e603b2c2d65da55c763eeb0a19178221a5f5",
    "archive.html": "94135f2f080cc6fa79f343eb6b29b80828192aa1b5d119ef59c81835d8c8d3c8",
    "ledger.json": "c366fc69afa1dcaac3c0a89da46867a78faaa682dd3be375fee32ccf03099ba4",
    "payload.json": "22b45c8fe1695b940609be0282a5e07e9522516c540ead8891af9ed402da38d3",
}


class GoldenFixtures(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.payload = (DAY / "payload.json").read_bytes()
        cls.row = parse_headline(cls.payload, capture_utc=None,
                                 source_sha256=GOLDEN_SHA256["dashboard.html"])

    def test_golden_hashes(self):
        for name, sha in GOLDEN_SHA256.items():
            with self.subTest(name=name):
                self.assertEqual(hashlib.sha256((DAY / name).read_bytes()).hexdigest(), sha)

    def test_manifest_hashes_match_files(self):
        m = json.loads((DAY / "MANIFEST.json").read_text())
        files = {f["name"]: f["sha256"] for f in m["runs"][0]["files"]}
        self.assertEqual(files, GOLDEN_SHA256)

    def test_whole_archive_audits_clean(self):
        self.assertEqual(audit(ROOT), [])

    def test_headline_numbers(self):
        expected = {
            "revision": 35,
            "as_of_utc": "2026-10-02T19:47:20Z",
            "candidates": 29439,
            "reviewed_by_firms": 6123,
            "confirmed_valid": 5674,
            "reported_after_triage": 1333,
            "reported_without_review": 4824,
            "reported_total": 6157,  # "disclosed" in the spec
            "acknowledged": 5103,
            "patched_lab_count": 516,
            "advisories": 584,
            "cves": 219,
            "ghsas": 365,
            "projects_reported": 591,
            "ledger_entries": 6597,
            "revealed_entries": 237,
            # quirk 2 and 4: Anthropic's own revealed count and the fix rate built on it
            "program_revealed_count": 235,
            "program_fix_rate_pct": 92.8,
            "label": "Lab-reported",
            "program": "anthropic-cvd",
        }
        for k, v in expected.items():
            with self.subTest(field=k):
                self.assertEqual(self.row[k], v)

    def test_tiers(self):
        self.assertEqual(tier_counts(self.payload), {
            "acknowledged_by_maintainer": 4868, "sent": 1054, "discovered": 438, "revealed": 237})

    def test_ledger_and_payload_have_same_hashes(self):
        # quirk 1: the ledger appears twice; the sets of hashes are identical
        ledger = json.loads((DAY / "ledger.json").read_bytes())
        payload = json.loads(self.payload)["ledger"]
        self.assertEqual({e["hash"] for e in ledger}, {e["hash"] for e in payload})


if __name__ == "__main__":
    unittest.main()
