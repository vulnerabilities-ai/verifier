"""Rule R2 and finding cards."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from urllib.parse import quote

from fakeserver import FakeSite

from verifier.audit import audit
from verifier.cards import card_addresses, fetch_cards, is_due, write_verifications
from verifier.net import Fetcher
from verifier.r2 import canonical_bytes, extract_preimage, parse_card, r2_check, sha3_512

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/wolfssl-card"  # frozen copy; the live card folder keeps growing
CARD = FIXTURE / "card.html"
PREIMAGE = FIXTURE / "preimage.json"
WOLF_ID = "ANT-2026-87DJGDRB"
WOLF_HASH = ("f35e4f410ec58dab28431670e173e03fd1e5105f8afefc79c7edd5117d684d3a"
             "a377d218762d2f1ab70c6262e31227885bacaf2062958b077e305e5aebc6c37d")


class R2Golden(unittest.TestCase):
    def test_wolfssl_match(self):
        card = CARD.read_bytes()
        pre = extract_preimage(card)
        self.assertEqual(pre["method"], "download_link_data_address")
        self.assertEqual(pre["bytes"], PREIMAGE.read_bytes())
        facts = parse_card(card)
        r = r2_check(pre["bytes"], WOLF_HASH, facts["printed_hash"], pre["method"])
        self.assertEqual(r["outcome"], "match")
        self.assertTrue(r["raw_bytes_match"])
        self.assertTrue(r["canonical_rebuild_match"])
        self.assertTrue(r["printed_hash_equals_ledger_hash"])

    def test_wolfssl_card_facts(self):
        f = parse_card(CARD.read_bytes())
        self.assertEqual(f["dates"], {"discovered_or_logged_date": "2026-03-24", "report_date": "2026-03-27",
                                      "acknowledged_date": "2026-03-27", "patch_released_date": "2026-06-25",
                                      "reveal_date": "2026-08-17"})
        self.assertEqual(f["severities"], {"model": "high", "firm": "high", "maintainer": "low"})
        self.assertEqual(f["links"]["fix"], ["https://github.com/wolfSSL/wolfssl/commit/6bfb53f084a25198835a50796eca83f463a0e7be"])
        self.assertEqual(f["links"]["advisory"], ["https://github.com/wolfSSL/wolfssl/pull/10641"])
        self.assertEqual(f["missing_parts"], [])

    # quirk 9: non-ASCII characters are not escaped in the committed bytes
    def test_non_ascii_not_escaped(self):
        raw = PREIMAGE.read_bytes()
        self.assertIn("→".encode("utf-8"), raw)
        obj = json.loads(raw)
        self.assertEqual(canonical_bytes(obj), raw)
        escaped = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
        self.assertNotEqual(sha3_512(escaped), WOLF_HASH)  # escaping changes the hash
        self.assertEqual(sha3_512(canonical_bytes(obj)), WOLF_HASH)

    def test_tampered_and_missing(self):
        raw = PREIMAGE.read_bytes().replace(b"sha.c:733", b"sha.c:734")
        self.assertEqual(r2_check(raw, WOLF_HASH, WOLF_HASH)["outcome"], "mismatch")
        self.assertEqual(r2_check(None, WOLF_HASH, WOLF_HASH)["outcome"], "unavailable")
        self.assertIsNone(extract_preimage(b"<html>no preimage here</html>")["bytes"])

    def test_visible_text_fallback(self):
        card = CARD.read_text(encoding="utf-8")
        start = card.index('<a download="')
        end = card.index("</a>", start) + 4
        no_link = card[:start] + card[end:]
        pre = extract_preimage(no_link.encode())
        self.assertEqual(pre["method"], "visible_text_canonical_rebuild")
        self.assertEqual(r2_check(pre["bytes"], WOLF_HASH, None)["outcome"], "match")


def card_with(fid: str, preimage: bytes) -> bytes:
    return (f'<!doctype html><html><body><h1>{fid}</h1><div class="marker">PROVENANCE</div>'
            f'<p class="hash full">{sha3_512(preimage)}</p>'
            f'<a download="{fid}-preimage.json" href="data:application/json;charset=utf-8,'
            f'{quote(preimage.decode())}">Verify</a></body></html>').encode()


class CardFetching(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.pre = {f"ANT-2026-T{i}": json.dumps({"ant_id": f"ANT-2026-T{i}", "n": i}).encode() for i in range(3)}
        routes = {"/robots.txt": (200, b"User-agent: *\nAllow: /\n", {}),
                  "/2026/cvd/findings/ANT-2026-T0.html": (200, card_with("ANT-2026-T0", self.pre["ANT-2026-T0"]), {}),
                  "/2026/cvd/findings/ANT-2026-T1": (200, card_with("ANT-2026-T1", self.pre["ANT-2026-T1"]), {})}
        self.site = FakeSite(routes)
        self.base = self.site.url + "/2026/cvd/"
        self.revealed = {fid: sha3_512(p) for fid, p in self.pre.items()}

    def tearDown(self):
        self.site.close()
        self.tmp.cleanup()

    def fetch(self, now=None):
        return fetch_cards(self.root, self.revealed, Fetcher(min_interval=0), self.base, now=now)

    def test_addresses_in_order(self):
        self.assertEqual(card_addresses("https://x/2026/cvd/", "ANT-1"),
                         ["https://x/2026/cvd/findings/ANT-1.html", "https://x/2026/cvd/findings/ANT-1/",
                          "https://x/2026/cvd/findings/ANT-1"])

    def test_fetch_fallbacks_unavailable_and_r2(self):
        t = self.fetch()
        self.assertEqual(t["fetched"], 2)
        self.assertEqual(t["unavailable"], ["ANT-2026-T2"])
        paths = [p for p in self.site.paths() if "T1" in p]
        self.assertEqual(paths, ["/2026/cvd/findings/ANT-2026-T1.html", "/2026/cvd/findings/ANT-2026-T1/",
                                 "/2026/cvd/findings/ANT-2026-T1"])  # the no-extension address worked
        checks = write_verifications(self.root, self.revealed, "ledger")
        self.assertEqual(checks["ANT-2026-T0"]["outcome"], "match")
        self.assertEqual(checks["ANT-2026-T1"]["outcome"], "match")
        self.assertEqual(checks["ANT-2026-T2"]["outcome"], "unavailable")
        m = json.loads((self.root / "cards/ANT-2026-T2/MANIFEST.json").read_text())
        self.assertEqual(len(m["unavailable"][0]["attempts"]), 3)
        self.assertEqual(audit(self.root), [])

    def test_only_new_then_monthly(self):
        self.fetch(now="2026-11-10T00:00:00Z")
        n = len(self.site.requests)
        t = self.fetch(now="2026-11-20T00:00:00Z")  # 10 days later: known cards not due
        self.assertEqual(t["not_due"], 2)
        self.assertEqual(len([p for p in self.site.paths()[n:] if "T0" in p]), 0)
        later = (self.root / "cards/ANT-2026-T0/MANIFEST.json")
        last = json.loads(later.read_text())["fetches"][-1]["fetched_utc"]
        self.assertTrue(is_due(json.loads(later.read_text()), "2099-01-01T00:00:00Z"))
        self.assertFalse(is_due(json.loads(later.read_text()), last))

    def test_changed_card_new_copy_raw_never_edited(self):
        self.fetch(now="2026-11-10T00:00:00Z")
        first = (self.root / "cards/ANT-2026-T0/card.html").read_bytes()
        changed = card_with("ANT-2026-T0", self.pre["ANT-2026-T0"]).replace(b"<h1>", b"<h1>updated ")
        self.site.routes["/2026/cvd/findings/ANT-2026-T0.html"] = (200, changed, {})
        self.fetch(now="2099-01-01T00:00:00Z")
        self.assertEqual((self.root / "cards/ANT-2026-T0/card.html").read_bytes(), first)
        copies = sorted(p.name for p in (self.root / "cards/ANT-2026-T0").glob("card*.html"))
        self.assertEqual(len(copies), 2)
        self.assertEqual(audit(self.root), [])

    def test_manual_copy_is_due_and_identical_fetch_points_to_it(self):
        d = self.root / "cards" / WOLF_ID
        d.mkdir(parents=True)
        for f in ("card.html", "preimage.json", "MANIFEST.json"):
            shutil.copy(FIXTURE / f, d / f)
        self.assertTrue(is_due(json.loads((d / "MANIFEST.json").read_text()), "2026-11-10T00:00:00Z"))
        self.site.routes[f"/2026/cvd/findings/{WOLF_ID}.html"] = (200, CARD.read_bytes(), {})
        fetch_cards(self.root, {WOLF_ID: WOLF_HASH}, Fetcher(min_interval=0), self.base)
        m = json.loads((d / "MANIFEST.json").read_text())
        self.assertEqual(m["fetches"][-1]["stored_at"], f"cards/{WOLF_ID}/card.html")
        self.assertFalse(m["fetches"][-1]["newly_stored"])
        self.assertEqual(sorted(p.name for p in d.iterdir()), ["MANIFEST.json", "card.html", "preimage.json"])
        checks = write_verifications(self.root, {WOLF_ID: WOLF_HASH}, "ledger")
        self.assertEqual(checks[WOLF_ID]["outcome"], "match")
        self.assertEqual(audit(self.root), [])


if __name__ == "__main__":
    unittest.main()
