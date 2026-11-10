"""Fixes after Verify run #1:
1. tests do not depend on the live archive's growing state (invariants, and a
   simulated growth of the card archive);
2. every unavailable card has a plain reason, in verification.json and in the
   review summary;
3. the review branch keeps the fetched cards even when later checks fail."""

import base64
import json
import os
import shutil
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from urllib.parse import quote

from fakeserver import FakeSite
from helpers import WOLF_ID, frozen_archive

from verifier.build import build
from verifier.build.sources import Sources
from verifier.build import latest_ledger
from verifier.cards import fetch_cards, write_verifications
from verifier.net import Fetcher
from verifier.r2 import extract_preimage, sha3_512
from verifier.review import review_pr, review_summary, unavailable_cards

ROOT = Path(__file__).resolve().parents[1]
OUTCOMES = {"match", "mismatch", "preimage_withheld", "unavailable", "not_checked"}


def assert_invariants(tc: unittest.TestCase, result: dict, root: Path):
    """What must always hold, however many cards have been fetched."""
    rows = result["tables"]["commitments"]
    revealed = [r for r in rows if r["tier"] == "revealed"]
    counts = {k: sum(1 for r in revealed if r["hash_check"] == k) for k in OUTCOMES}
    tc.assertEqual(sum(counts.values()), len(revealed))
    tc.assertEqual(set(r["hash_check"] for r in revealed) - OUTCOMES, set())
    tc.assertEqual({r["hash_check"] for r in rows if r["tier"] != "revealed"} - {"not_applicable"}, set())
    card = result["cards"]
    tc.assertEqual(card["match"] + card["mismatch"] + card["preimage_withheld"] + card["unavailable"]
                   + card["not_checked"], card["revealed"])
    # a mismatch is a recorded fact, never labelled an error
    for v in (root / "cards").glob("*/verification.json"):
        rec = json.loads(v.read_text())
        if rec["r2"]["outcome"] == "mismatch":
            tc.assertNotIn("error", json.dumps(rec["r2"]).lower())
    text = review_summary(root)
    for line in text.splitlines():
        if "mismatch" in line.lower():
            tc.assertNotIn("error", line.lower())
            tc.assertNotIn("fail", line.lower())


# ---------------------------------------------------------------------------
# 1. Independence from the live archive
# ---------------------------------------------------------------------------
class LiveArchiveInvariants(unittest.TestCase):
    """Builds a temporary copy of whatever the live archive holds today and checks
    only invariants, so more captures or cards can never make it fail."""

    def test_invariants_on_live_copy(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            shutil.copytree(ROOT / "captures", root / "captures")
            shutil.copytree(ROOT / "cards", root / "cards")
            if (ROOT / "records").exists():
                shutil.copytree(ROOT / "records", root / "records")
            (root / "data").mkdir()
            shutil.copy(ROOT / "data" / "programs-manual.csv", root / "data" / "programs-manual.csv")
            assert_invariants(self, build(root), root)


class CardArchiveGrowth(unittest.TestCase):
    """Simulates more cards being fetched (a match, a mismatch, unavailable ones)
    on top of the frozen archive. Every invariant still holds."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = frozen_archive(Path(self.tmp.name))
        _, revealed = latest_ledger(Sources(self.root))
        self.ids = sorted(i for i in revealed if i != WOLF_ID)[:4]
        self.revealed = {i: revealed[i] for i in self.ids}
        pre = json.dumps({"ant_id": self.ids[0]}).encode()
        routes = {"/robots.txt": (200, b"User-agent: *\nAllow: /\n", {})}
        # ids[0]: a preimage that does not hash to the ledger value -> mismatch
        routes[f"/2026/cvd/findings/{self.ids[0]}.html"] = (200, _card(self.ids[0], pre), {})
        # ids[1]: a card with no preimage at all -> unavailable (no_preimage_link)
        routes[f"/2026/cvd/findings/{self.ids[1]}.html"] = (
            200, f"<!doctype html><html><body>{self.ids[1]}</body></html>".encode(), {})
        # ids[2]: a broken base64 link -> unavailable (unreadable_data_link)
        routes[f"/2026/cvd/findings/{self.ids[2]}.html"] = (200, _card(self.ids[2], None, b64="!!notbase64!!"), {})
        # ids[3]: not served at any address -> unavailable (card_not_fetched)
        self.site = FakeSite(routes)
        self.base = self.site.url + "/2026/cvd/"

    def tearDown(self):
        self.site.close()
        self.tmp.cleanup()

    def test_growth_keeps_invariants_and_reasons(self):
        tally = fetch_cards(self.root, self.revealed, Fetcher(min_interval=0), self.base)
        self.assertEqual(tally["unavailable"], [self.ids[3]])
        self.assertIn("could not be fetched", tally["unavailable_reasons"][self.ids[3]])
        result = build(self.root)
        assert_invariants(self, result, self.root)
        c = result["cards"]
        self.assertEqual((c["match"], c["mismatch"], c["unavailable"]), (1, 1, 3))
        reasons = dict(unavailable_cards(self.root))
        self.assertEqual(set(reasons), set(self.ids[1:]))
        self.assertIn("no preimage download link", reasons[self.ids[1]])
        self.assertIn("could not be read", reasons[self.ids[2]])
        self.assertIn("could not be fetched", reasons[self.ids[3]])
        self.assertIn("findings/" + self.ids[3], reasons[self.ids[3]])
        text = review_summary(self.root)
        for fid, why in reasons.items():
            self.assertIn(f"- {fid}: {why}", text)


def _card(fid, preimage, b64=None):
    href = (f"data:application/json;base64,{b64}" if b64 is not None
            else "data:application/json;charset=utf-8," + quote(preimage.decode()))
    return (f'<!doctype html><html><body><h1>{fid}</h1><div class="marker">PROVENANCE</div>'
            f'<p class="hash full">{"0" * 128}</p><a download="{fid}-preimage.json" href="{href}">Verify</a>'
            f"</body></html>").encode()


# ---------------------------------------------------------------------------
# 2. Plain reasons for unavailable results
# ---------------------------------------------------------------------------
class UnavailableReasons(unittest.TestCase):
    def test_extraction_reason_codes(self):
        self.assertEqual(extract_preimage(b"<html>nothing</html>")["code"], "no_preimage_link")
        bad = _card("ANT-X", None, b64="!!notbase64!!")
        r = extract_preimage(bad)
        self.assertEqual(r["code"], "unreadable_data_link")
        self.assertIn("base64", r["error"])
        visible_bad = b'<html><pre class="preimage-body">{not json</pre></html>'
        self.assertEqual(extract_preimage(visible_bad)["code"], "unreadable_visible_text")
        empty_link = (b'<html><a download="X-preimage.json" href="data:application/json;charset=utf-8,">v</a>'
                      b'<pre class="preimage-body">{&#34;a&#34;: 1}</pre></html>')
        r = extract_preimage(empty_link)
        self.assertEqual(r["method"], "visible_text_canonical_rebuild")  # fell back, with a note
        self.assertIn("could not be read", r["note"])

    def test_base64_link_is_decoded(self):
        pre = '{"ant_id":"ANT-X","s":"a→b"}'.encode()
        card = _card("ANT-X", None, b64=base64.b64encode(pre).decode())
        r = extract_preimage(card)
        self.assertEqual(r["bytes"], pre)

    def test_verification_json_has_reason_and_hints(self):
        with tempfile.TemporaryDirectory() as t:
            root = Path(t)
            d = root / "cards" / "ANT-X"
            d.mkdir(parents=True)
            body = b"<!doctype html><html><body>ANT-X</body></html>"
            (d / "card.html").write_bytes(body)
            (d / "MANIFEST.json").write_text(json.dumps({"fetches": [{
                "fetched_utc": "2026-01-01T00:00:00Z", "url": "u", "sha256": sha256(body),
                "stored_at": "cards/ANT-X/card.html"}], "unavailable": [], "preimages": []}))
            write_verifications(root, {"ANT-X": "a" * 128}, "ledger")
            v = json.loads((d / "verification.json").read_text())
            self.assertEqual(v["r2"]["outcome"], "unavailable")
            self.assertEqual(v["r2"]["unavailable_reason"]["code"], "no_preimage_link")
            self.assertTrue(v["r2"]["unavailable_reason"]["text"])
            self.assertEqual(v["card_hints"]["download_links"], 0)


def sha256(b):
    import hashlib
    return hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------------------
# 3. Fetched cards are never lost on a later failure
# ---------------------------------------------------------------------------
class ReviewTitleAndBody(unittest.TestCase):
    def test_all_pass(self):
        with tempfile.TemporaryDirectory() as t:
            title, body = review_pr(Path(t), {k: "success" for k in ("cards", "build", "tests", "audit")},
                                    "2026-11-16", {"fetched": 3, "unavailable": []})
        self.assertEqual(title, "Weekly review 2026-11-16")
        self.assertNotIn("Checks failed", body)

    def test_failure_stated_first(self):
        with tempfile.TemporaryDirectory() as t:
            title, body = review_pr(Path(t), {"cards": "success", "build": "success", "tests": "failure",
                                              "audit": "success"}, "2026-11-16", None)
        self.assertEqual(title, "Weekly review 2026-11-16 (checks failed)")
        self.assertTrue(body.startswith("## Checks failed"))
        self.assertIn("Tests (failure)", body)
        self.assertIn("Do not merge", body)

    def test_build_failed_lists_fetch_and_reasons(self):
        fetch = {"fetched": 237, "new_copies": 236, "unchanged": 1, "unavailable": ["ANT-Q"],
                 "unavailable_reasons": {"ANT-Q": "the card could not be fetched; addresses tried: x"}}
        with tempfile.TemporaryDirectory() as t:
            title, body = review_pr(Path(t), {"build": "failure"}, "2026-11-16", fetch)
        self.assertIn("(checks failed)", title)
        self.assertIn("only the raw card files", body)
        self.assertIn("- ANT-Q: the card could not be fetched", body)


class ReviewCommitScript(unittest.TestCase):
    """Runs scripts/review_commit.sh in a throwaway git repository with a local
    'remote' and a stand-in for the GitHub CLI."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.remote, self.repo = t / "remote.git", t / "repo"
        git = lambda *a, cwd=t: subprocess.run(["git", *a], cwd=cwd, check=True, capture_output=True)
        git("init", "-q", "--bare", str(self.remote))
        git("init", "-q", "-b", "main", str(self.repo))
        self.git = lambda *a: subprocess.run(["git", *a], cwd=self.repo, check=True,
                                             capture_output=True, text=True).stdout
        for rel, text in {"data/snapshots.json": "main data\n", "cards/A/card.html": "card A\n",
                          "cards/A/verification.json": "main verification\n", "README.md": "x\n"}.items():
            (self.repo / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.repo / rel).write_text(text)
        self.git("add", "-A")
        self.git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "main")
        self.git("remote", "add", "origin", str(self.remote))
        self.gh_log = t / "gh.log"
        gh = t / "gh"
        gh.write_text(f'#!/usr/bin/env bash\necho "$@" >> "{self.gh_log}"\n')
        gh.chmod(gh.stat().st_mode | stat.S_IEXEC)
        self.gh = str(gh)
        self.title, self.body = t / "title.txt", t / "review.md"

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, build="success", title="Weekly review 2026-11-16 (checks failed)"):
        self.title.write_text(title)
        self.body.write_text("## Checks failed\n\nTests (failure).\n")
        env = {**os.environ, "BUILD_OUTCOME": build, "TITLE_FILE": str(self.title),
               "BODY_FILE": str(self.body), "GH": self.gh, "GITHUB_REPOSITORY": "o/r",
               "GITHUB_RUN_ID": "1"}
        return subprocess.run(["bash", str(ROOT / "scripts/review_commit.sh")], cwd=self.repo, env=env,
                              capture_output=True, text=True)

    def remote_file(self, rel):
        return subprocess.run(["git", "--git-dir", str(self.remote), "show", f"review/weekly:{rel}"],
                              capture_output=True, text=True).stdout

    def test_build_failed_keeps_raw_cards_only(self):
        (self.repo / "cards/B").mkdir()
        (self.repo / "cards/B/card.html").write_text("new raw card B\n")
        (self.repo / "cards/B/verification.json").write_text("half-built\n")
        (self.repo / "cards/A/verification.json").write_text("half-built\n")
        (self.repo / "data/snapshots.json").write_text("half-built\n")
        r = self.run_script(build="failure")
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertEqual(self.remote_file("cards/B/card.html"), "new raw card B\n")  # evidence kept
        self.assertEqual(self.remote_file("data/snapshots.json"), "main data\n")  # derived put back
        self.assertEqual(self.remote_file("cards/A/verification.json"), "main verification\n")
        self.assertEqual(self.remote_file("cards/B/verification.json"), "")
        log = self.gh_log.read_text()
        self.assertIn("pr create", log)
        self.assertIn("Weekly review 2026-11-16 (checks failed)", log)

    def test_tests_failed_keeps_rebuilt_data_too(self):
        (self.repo / "cards/B").mkdir()
        (self.repo / "cards/B/card.html").write_text("new raw card B\n")
        (self.repo / "data/snapshots.json").write_text("rebuilt\n")
        r = self.run_script(build="success")
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        self.assertEqual(self.remote_file("cards/B/card.html"), "new raw card B\n")
        self.assertEqual(self.remote_file("data/snapshots.json"), "rebuilt\n")

    def test_guard_refuses_changes_outside_cards_and_data(self):
        (self.repo / "cards/B").mkdir()
        (self.repo / "cards/B/card.html").write_text("new raw card B\n")
        (self.repo / "README.md").write_text("changed\n")
        r = self.run_script(build="failure")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("outside cards/, data/, records/ and reports/", r.stdout + r.stderr)
        self.assertEqual(self.remote_file("cards/B/card.html"), "")  # nothing pushed


class VerifyWorkflowShape(unittest.TestCase):
    def test_commit_always_runs_after_checks(self):
        wf = (ROOT / ".github/workflows/verify.yml").read_text()
        for step in ("id: build", "id: tests", "id: audit"):
            block = wf[wf.index(step):wf.index(step) + 120]
            self.assertIn("continue-on-error: true", block)
        commit = wf[wf.index("name: Commit to the review branch"):]
        self.assertIn("if: always()", commit[:120])
        self.assertIn("bash scripts/review_commit.sh", commit)
        self.assertLess(wf.index("name: Commit to the review branch"),
                        wf.index("name: Fail the run if any check failed"))
        self.assertIn("fetch-depth: 0", wf)


if __name__ == "__main__":
    unittest.main()
