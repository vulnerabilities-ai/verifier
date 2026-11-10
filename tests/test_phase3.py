"""Phase 3: preimage_withheld, public records (R3, R4), intervals (R5), severity (R7),
summary, verification, programs, the report and wording guard, publishing."""

import json
import re
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from fakeserver import FakeSite
from helpers import WOLF_ID, frozen_archive

from verifier import config
from verifier.build import build
from verifier.cards import card_tally, write_verifications
from verifier.net import Fetcher, RobotsDisallowed
from verifier.r2 import extract_preimage, r2_check, withheld_statement
from verifier.records import RecordFetcher, choose_sample, fix_targets, run_lookups
from verifier.records_read import RecordReader
from verifier.report import weekly_report
from verifier.sitepub import build_site
from verifier.wording import WordingError, check_text, find

ROOT = Path(__file__).resolve().parents[1]
WITHHELD = ROOT / "tests/fixtures/withheld-cards"
WOLF_HASH = ("f35e4f410ec58dab28431670e173e03fd1e5105f8afefc79c7edd5117d684d3a"
             "a377d218762d2f1ab70c6262e31227885bacaf2062958b077e305e5aebc6c37d")
SHA = "6bfb53f084a25198835a50796eca83f463a0e7be"
STATEMENTS = {
    "ANT-2026-7DG11TPA": "The preimage for this commitment is withheld because it references findings that are not yet "
                         "disclosed. The commitment hash remains in the ledger and the full preimage will be published "
                         "when the referenced findings are revealed.",
    "ANT-2026-A5580GNM": "The preimage for this commitment is withheld: the report was withdrawn after publication, and "
                         "the sealed preimage is that report. The commitment hash remains in the ledger as published.",
    "ANT-2026-VS18SA90": "The preimage for this commitment is withheld: this entry's own report was withdrawn after "
                         "publication, and the sealed preimage is that report. The commitment hash remains in the "
                         "ledger as published.",
}

# Hand-built from the public advisory page, in the documented API shapes. The sample
# run (Verify with sample_only) checks the real shapes before a full run.
WOLF_ADVISORY = {
    "ghsa_id": "GHSA-q349-x427-xg3w", "cve_id": "CVE-2026-12340", "type": "unreviewed", "severity": "medium",
    "published_at": "2026-06-25T18:31:20Z", "updated_at": "2026-06-25T18:31:21Z",
    "cvss_severities": {"cvss_v3": {"vector_string": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L", "score": 6.3},
                        "cvss_v4": {"vector_string": None, "score": None}},
    "cwes": [{"cwe_id": "CWE-125", "name": "Out-of-bounds Read"}],
    "source_code_location": "https://github.com/wolfSSL/wolfssl",
    "vulnerabilities": [], "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-12340"], "credits": [],
}
WOLF_NVD = {"totalResults": 1, "vulnerabilities": [{"cve": {
    "id": "CVE-2026-12340", "published": "2026-06-25T19:15:51.123", "lastModified": "2026-06-26T10:00:00.000",
    "vulnStatus": "Awaiting Analysis", "metrics": {},
    "weaknesses": [{"description": [{"lang": "en", "value": "CWE-125"}]}], "references": []}}]}


def j(obj, status=200, headers=None):
    h = {"Content-Type": "application/json", "X-RateLimit-Remaining": "4000", "X-RateLimit-Reset": "0"}
    h.update(headers or {})
    return (status, json.dumps(obj).encode(), h)


def github_routes(overrides=None):
    r = {
        "/robots.txt": (200, b"User-agent: *\nDisallow: /\n", {}),  # like api.github.com: crawlers only
        "/advisories/GHSA-q349-x427-xg3w": j(WOLF_ADVISORY),
        "/advisories?cve_id=CVE-2026-12340": j([WOLF_ADVISORY]),
        "/repos/wolfSSL/wolfssl": j({"default_branch": "master", "full_name": "wolfSSL/wolfssl"}),
        f"/repos/wolfSSL/wolfssl/commits/{SHA}": j({"sha": SHA}),
        "/repos/wolfSSL/wolfssl/pulls/10641": j({"number": 10641, "merged": True,
                                                 "merged_at": "2026-06-10T16:02:11Z", "base": {"ref": "master"}}),
        f"/repos/wolfSSL/wolfssl/compare/master...{SHA}": j({"status": "behind"}),
    }
    r.update(overrides or {})
    return r


def nvd_routes(overrides=None):
    r = {"/robots.txt": (200, b"User-agent: *\nDisallow: /\n", {}),
         "/rest/json/cves/2.0?cveId=CVE-2026-12340": j(WOLF_NVD)}
    r.update(overrides or {})
    return r


class FakeClock:
    def __init__(self):
        self.t, self.sleeps = 1000.0, []

    def clock(self):
        return self.t

    def sleep(self, s):
        self.sleeps.append(s)
        self.t += s


class Phase3Case(unittest.TestCase):
    """Frozen archive + the five withheld cards + fake GitHub and NVD servers."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = frozen_archive(Path(self.tmp.name))
        for f in WITHHELD.glob("*.html"):
            d = self.root / "cards" / f.stem
            d.mkdir(parents=True)
            shutil.copy(f, d / "card.html")
            import hashlib
            (d / "MANIFEST.json").write_text(json.dumps({"fetches": [{
                "fetched_utc": "2026-01-01T00:00:00Z", "url": "frozen fixture",
                "sha256": hashlib.sha256(f.read_bytes()).hexdigest(), "stored_at": f"cards/{f.stem}/card.html"}],
                "unavailable": [], "preimages": []}))
        self.gh = FakeSite(github_routes())
        self.nvd = FakeSite(nvd_routes())
        self.fake = FakeClock()

    def tearDown(self):
        self.gh.close()
        self.nvd.close()
        self.tmp.cleanup()

    def record_fetcher(self, **kw):
        gh_host, nvd_host = self.gh.url.split("//")[1], self.nvd.url.split("//")[1]
        f = Fetcher(min_interval=0, credential_destinations=frozenset({self.gh.url}),
                    robots_exempt_hosts=frozenset({gh_host, nvd_host}))
        args = dict(token="TOKEN-should-never-be-written", fetcher=f, github_api=self.gh.url,
                    nvd_api=self.nvd.url + "/rest/json/cves/2.0", sleep=self.fake.sleep, clock=self.fake.clock,
                    wall=lambda: 0.0)
        args.update(kw)
        return RecordFetcher(self.root, **args)

    def inputs(self):
        from verifier.build import latest_ledger
        from verifier.build.phase3 import finding_inputs
        from verifier.build.sources import Sources
        src = Sources(self.root)
        rel, revealed = latest_ledger(src)
        write_verifications(self.root, revealed, rel)
        entries = {e["ant_id"]: e for e in src.load_json_file(rel)
                   if e.get("reveal_tier") == "revealed" and e.get("ant_id")}
        return finding_inputs(self.root, entries)

    def wolf_only(self):
        return {WOLF_ID: self.inputs()[WOLF_ID]}


# ---------------------------------------------------------------------------
# preimage_withheld
# ---------------------------------------------------------------------------
class PreimageWithheld(unittest.TestCase):
    def test_verbatim_statements(self):
        for fid, text in STATEMENTS.items():
            card = (WITHHELD / f"{fid}.html").read_bytes()
            self.assertEqual(withheld_statement(card), text)
            r = r2_check(extract_preimage(card).get("bytes"), "a" * 128, None, None, withheld_statement(card))
            self.assertEqual(r["outcome"], "preimage_withheld")
            self.assertEqual(r["withheld_statement"], text)
            self.assertEqual(r["withheld_statement_source"], "the program's finding card")
        self.assertEqual(len(list(WITHHELD.glob("*.html"))), 5)
        for f in WITHHELD.glob("*.html"):
            self.assertTrue(withheld_statement(f.read_bytes()).startswith("The preimage for this commitment is withheld"))

    def test_normal_card_has_none(self):
        self.assertIsNone(withheld_statement((ROOT / "tests/fixtures/wolfssl-card/card.html").read_bytes()))

    def test_counts_never_mismatch_or_unavailable(self):
        t = card_tally({"a": {"outcome": "preimage_withheld"}, "b": {"outcome": "match"}}, {"a": 1, "b": 1})
        self.assertEqual((t["preimage_withheld"], t["mismatch"], t["unavailable"]), (1, 0, 0))


# ---------------------------------------------------------------------------
# R3, R4 against fake servers; robots exemption; tolerance; rate limits
# ---------------------------------------------------------------------------
class PublicRecords(Phase3Case):
    def test_wolfssl_expected_result(self):
        rf = self.record_fetcher()
        tally = run_lookups(self.root, self.wolf_only(), rf)
        self.assertIsNone(tally["github_stopped"])
        r = build(self.root)
        w = next(v for v in r["tables"]["verification"] if v["finding_id"] == WOLF_ID)
        self.assertEqual(w["ids_exist"], "verified")
        self.assertEqual(w["advisory_published"], "2026-06-25")
        self.assertEqual(w["severity_github"], "medium")  # GitHub's website shows it as "Moderate"
        self.assertEqual((w["cvss_github_score"], w["cvss_github_version"]), (6.3, "3.1"))
        self.assertEqual(w["cwe_github"], ["CWE-125"])
        self.assertEqual(w["advisory_review_status"], "unreviewed")
        self.assertEqual(w["fix_merged"], "yes")
        self.assertEqual(w["fix_merged_at"][:10], "2026-06-10")
        self.assertEqual(w["fix_merge_base"], "master")
        self.assertEqual((w["days_report_to_patch"], w["days_patch_to_reveal"], w["days_report_to_reveal"],
                          w["days_report_to_merge"]), (90, 53, 143, 75))
        self.assertEqual((w["severity_model"], w["severity_firm"], w["severity_maintainer"]), ("high", "high", "low"))
        self.assertEqual(w["lookup_status"], "ok")
        self.assertEqual(w["checked"], "yes")
        c = next(x for x in r["tables"]["commitments"] if x["finding_id"] == WOLF_ID)
        self.assertEqual(c["fix_merged"], "yes")

    def test_token_only_to_github_and_never_written(self):
        run_lookups(self.root, self.wolf_only(), self.record_fetcher())
        self.assertTrue(all(r.headers.get("Authorization") == "Bearer TOKEN-should-never-be-written"
                            for r in self.gh.requests if r.path != "/robots.txt"))
        self.assertFalse(any("Authorization" in r.headers for r in self.nvd.requests))
        for f in (self.root / "records").rglob("*"):
            if f.is_file():
                self.assertNotIn(b"TOKEN-should", f.read_bytes())
        self.assertNotIn("TOKEN", repr(self.record_fetcher()))

    def test_robots_exemption_only_the_two_apis(self):
        self.assertEqual(config.API_ROBOTS_EXEMPT, frozenset({"api.github.com", "services.nvd.nist.gov"}))
        rf = RecordFetcher(self.root)
        self.assertEqual(rf.fetcher.robots_exempt_hosts, config.API_ROBOTS_EXEMPT)
        self.assertEqual(Fetcher().robots_exempt_hosts, frozenset())  # captures, cards, Archive: none
        run_lookups(self.root, self.wolf_only(), self.record_fetcher())
        self.assertNotIn("/robots.txt", self.gh.paths())  # exempt host: robots.txt never read
        other = FakeSite({"/robots.txt": (200, b"User-agent: *\nDisallow: /\n", {}), "/x": (200, b"x", {})})
        try:
            f = Fetcher(min_interval=0, robots_exempt_hosts=frozenset({self.gh.url.split("//")[1]}))
            with self.assertRaises(RobotsDisallowed):
                f.get(other.url + "/x")  # any other host keeps the robots check
        finally:
            other.close()

    def test_nvd_pacing_five_per_thirty_seconds(self):
        cves = [f"CVE-2026-{n}" for n in range(10000, 10007)]
        for c in cves:
            self.nvd.routes[f"/rest/json/cves/2.0?cveId={c}"] = j({"totalResults": 0, "vulnerabilities": []})
            self.gh.routes[f"/advisories?cve_id={c}"] = j([])
        rf = self.record_fetcher()
        stamps = []
        orig = rf._pace_nvd

        def spy():
            orig()
            stamps.append(self.fake.t)
        rf._pace_nvd = spy
        run_lookups(self.root, {"X": {"cve_ids": cves, "ghsa_ids": [], "fix_links": [], "advisory_links": []}}, rf)
        self.assertEqual(len(stamps), 7)
        for i in range(len(stamps) - 5):
            self.assertGreaterEqual(stamps[i + 5] - stamps[i], 30)

    def test_not_on_github_and_commit_without_pull(self):
        t = fix_targets(["https://gitlab.com/x/y/-/commit/abc1234"], [])
        self.assertEqual(t["not_on_github"], ["https://gitlab.com/x/y/-/commit/abc1234"])
        fm = RecordReader(self.root).fix_merged(["https://gitlab.com/x/y/-/commit/abc1234"], [])
        self.assertEqual(fm["fix_merged"], "not_checked")
        self.assertIn("gitlab.com", fm["address"])
        self.gh.routes[f"/repos/wolfSSL/wolfssl/commits/{SHA}/pulls"] = j(
            [{"merged_at": "2026-06-10T16:02:11Z", "base": {"ref": "master"}}])
        inp = {"F": {"cve_ids": [], "ghsa_ids": [], "advisory_links": [],
                     "fix_links": [f"https://github.com/wolfSSL/wolfssl/commit/{SHA}"]}}
        run_lookups(self.root, inp, self.record_fetcher())
        fm = RecordReader(self.root).fix_merged(inp["F"]["fix_links"], [])
        self.assertEqual((fm["fix_merged"], fm["fix_merged_at"]), ("yes", "2026-06-10T16:02:11Z"))

    def test_sample_only_five_with_wolfssl(self):
        ids = sorted(self.inputs())
        s1, s2 = choose_sample(ids), choose_sample(list(reversed(ids)))
        self.assertEqual(s1, s2)
        self.assertEqual(len(s1), 5)
        self.assertEqual(s1[0], WOLF_ID)
        tally = run_lookups(self.root, self.inputs(), self.record_fetcher(), sample_only=True)
        self.assertEqual(tally["sample_ids"], s1)


class TolerantParsing(Phase3Case):
    CASES = {
        "not JSON": (200, b"<html>maintenance</html>", {}),
        "empty body": (200, b"", {}),
        "list instead of object": j([1, 2]),
        "missing ghsa_id": j({"severity": "high"}),
        "wrong type": j({"ghsa_id": 123}),
        "unexpected status": j({"message": "boom"}, status=500),
        "truncated": (200, b'{"ghsa_id": "GHSA-q3', {}),
    }

    def test_malformed_advisory_responses(self):
        for name, resp in self.CASES.items():
            with self.subTest(case=name):
                shutil.rmtree(self.root / "records", ignore_errors=True)
                self.gh.routes["/advisories/GHSA-q349-x427-xg3w"] = resp
                tally = run_lookups(self.root, self.wolf_only(), self.record_fetcher())  # never raises
                self.assertIsNone(tally["github_stopped"])
                a = RecordReader(self.root).github_advisory("GHSA-q349-x427-xg3w")
                self.assertEqual(a["status"], "lookup_unreadable", a)
                self.assertTrue(a["reason"])
                r = build(self.root)  # the build completes
                w = next(v for v in r["tables"]["verification"] if v["finding_id"] == WOLF_ID)
                self.assertEqual(w["lookup_status"], "lookup_unreadable")
                self.assertIn("GHSA-q349-x427-xg3w", w["notes"])
                m = json.loads((self.root / "records/github/advisories/GHSA-q349-x427-xg3w/MANIFEST.json").read_text())
                if resp[1]:
                    self.assertTrue(m["attempts"][-1]["stored_at"])  # raw response kept

    def test_malformed_nvd_and_pull(self):
        self.nvd.routes["/rest/json/cves/2.0?cveId=CVE-2026-12340"] = j({"vulnerabilities": "nope"})
        self.gh.routes["/repos/wolfSSL/wolfssl/pulls/10641"] = j({"merged": True})  # no base.ref
        run_lookups(self.root, self.wolf_only(), self.record_fetcher())
        rr = RecordReader(self.root)
        self.assertEqual(rr.nvd_cve("CVE-2026-12340")["status"], "lookup_unreadable")
        fm = rr.fix_merged(*[self.wolf_only()[WOLF_ID][k] for k in ("fix_links", "advisory_links")])
        self.assertEqual(fm["fix_merged"], "yes")  # the commit is on the default branch (compare: behind)
        r = build(self.root)
        w = next(v for v in r["tables"]["verification"] if v["finding_id"] == WOLF_ID)
        self.assertEqual(w["lookup_status"], "lookup_unreadable")


class RateLimits(Phase3Case):
    def test_stops_cleanly_records_rate_limited_and_resumes(self):
        calls = {"n": 0}

        def limited(req):
            calls["n"] += 1
            if calls["n"] >= 3:
                return (403, b'{"message": "API rate limit exceeded"}',
                        {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "0"})
            return github_routes()[req.path]
        for path in list(github_routes()):
            if path != "/robots.txt":
                self.gh.routes[path] = limited
        tally = run_lookups(self.root, self.wolf_only(), self.record_fetcher())  # does not raise
        self.assertIn("rate limit", tally["github_stopped"].lower())
        self.assertGreater(tally["rate_limited"], 0)
        r = build(self.root)
        w = next(v for v in r["tables"]["verification"] if v["finding_id"] == WOLF_ID)
        self.assertEqual(w["lookup_status"], "rate_limited")
        stopped_at = calls["n"]
        self.assertEqual(stopped_at, 3)  # no calls after the limit
        # next run: limit reset; the skipped lookups go first and complete
        self.gh.routes.update(github_routes())
        rf = self.record_fetcher()
        order = []
        orig = rf.fetch
        rf.fetch = lambda k: (order.append(k.path), orig(k))[1]
        run_lookups(self.root, self.wolf_only(), rf)
        r = build(self.root)
        w = next(v for v in r["tables"]["verification"] if v["finding_id"] == WOLF_ID)
        self.assertEqual(w["lookup_status"], "ok")
        self.assertEqual(w["fix_merged"], "yes")

    def test_stops_when_remaining_runs_low_and_on_429(self):
        def low(req):
            return j(github_routes()[req.path] and json.loads(github_routes()[req.path][1]),
                     headers={"X-RateLimit-Remaining": "50", "X-RateLimit-Reset": "0"})
        for path in list(github_routes()):
            if path != "/robots.txt":
                self.gh.routes[path] = low
        rf = self.record_fetcher()
        run_lookups(self.root, self.wolf_only(), rf)
        self.assertEqual(len([p for p in self.gh.paths()]), 1)  # one call, then it stopped (50 left)
        self.assertIn("requests left", rf.github_stopped)
        shutil.rmtree(self.root / "records")
        self.gh.requests.clear()
        self.gh.routes.update(github_routes())
        self.gh.routes["/advisories/GHSA-q349-x427-xg3w"] = (429, b"slow down", {"Retry-After": "60"})
        rf = self.record_fetcher()
        run_lookups(self.root, self.wolf_only(), rf)
        self.assertIn("Retry-After 60", rf.github_stopped)

    def test_spreads_calls_out(self):
        reset = 3600.0
        for path in list(github_routes()):
            if path != "/robots.txt":
                body = github_routes()[path]
                self.gh.routes[path] = (body[0], body[1], {**body[2], "X-RateLimit-Remaining": "150",
                                                           "X-RateLimit-Reset": str(reset)})
        rf = self.record_fetcher(wall=lambda: 0.0)
        run_lookups(self.root, self.wolf_only(), rf)
        self.assertTrue(any(s > 1.0 for s in self.fake.sleeps))  # 3600 s / 100 spare = 30 s between calls


# ---------------------------------------------------------------------------
# Published files, report and wording guard
# ---------------------------------------------------------------------------
class PublishedPhase3(Phase3Case):
    @classmethod
    def setUpClass(cls):
        pass

    def test_summary_programs_verification(self):
        r = build(self.root)
        s = r["summary"]
        self.assertEqual((s["revealed"], s["program_revealed_count"]), (237, 235))
        self.assertEqual(s["revealed_share_of_reported_pct"], 4.66)
        self.assertEqual(s["itemized_share_of_reported_pct"], s["revealed_share_of_reported_pct"])
        self.assertEqual(s["fixed_itemized_share_of_patched_claimed_pct"], 34.5)
        self.assertEqual(s["fixed_itemized_share_of_reported_pct"], 4.27)
        self.assertEqual(s["hash_preimage_withheld"], 5)
        self.assertEqual(s["hash_matches"], 1)
        self.assertEqual((s["withdrawn_by_flag"], s["withdrawn_by_status"]), (415, 419))
        ic = s["interval_comparisons"]["days_report_to_patch"]
        self.assertEqual(ic["within"] + ic["above"], ic["with_dates"])
        progs = r["tables"]["programs"]
        manual = (ROOT / "tests/fixtures/programs-manual.csv").read_text()
        self.assertEqual([p["program"] for p in progs], ["anthropic-cvd", "project-glasswing", "openai-daybreak",
                                                         "project-quiltworks", "gold-eagle", "akrites", "athena"])
        self.assertEqual(progs[0]["status"], "Dashboard last updated 2026-11-02 (revision 40)")
        self.assertEqual(progs[0]["as_of"], "2026-11-02")
        for p in progs[1:]:
            self.assertIn(p["status"], manual)
        v = {x["finding_id"]: x for x in r["tables"]["verification"]}
        self.assertEqual(len(v), 237)
        for fid, text in STATEMENTS.items():
            self.assertEqual(v[fid]["hash_check"], "preimage_withheld")
            self.assertEqual(v[fid]["withheld_statement"], text)
        sev = r["tables"]["severity"]
        for src in ("model", "firm", "maintainer", "github", "nvd"):
            self.assertEqual(sum(x["count"] for x in sev if x["source"] == src), 237)  # never merged
        summary_doc = json.loads((self.root / "data/summary.json").read_text())
        self.assertEqual(len(summary_doc["rows"]), 1)
        self.assertFalse((self.root / "data/summary.csv").exists())

    def test_report_and_guard(self):
        build(self.root)
        text = weekly_report(self.root, "2026-01-01")
        self.assertEqual(find(text), [])
        self.assertIn("The dashboard's data file states 235 revealed findings. The dashboard's ledger lists 237", text)
        for fid, quote in STATEMENTS.items():
            self.assertIn(f"> {quote}", text)
        self.assertIn("No language model wrote any part of this report", text)
        with self.assertRaises(WordingError):
            check_text(text + "\nThe patch is overdue.\n", "report")  # build fails on 'overdue'

    def test_report_never_says_late_even_with_old_note_types(self):
        nov8 = json.loads((self.root / "captures/2026/11/08/MANIFEST.json").read_text())
        nov8.setdefault("appended_notes", []).append(
            {"note_type": "late-archive-receipt", "run_id": "x", "name": "dashboard.html"})
        (self.root / "captures/2026/11/08/MANIFEST.json").write_text(json.dumps(nov8))
        build(self.root)
        text = weekly_report(self.root, "2026-01-01")
        self.assertIsNone(re.search(r"\blate\b", text, re.I))
        self.assertNotIn("late-archive-receipt", text)

    def test_build_fails_on_banned_words_in_published_text(self):
        from verifier.build import phase3
        real = phase3.verification_rows

        def bad(*a, **k):
            rows = real(*a, **k)
            rows[0]["notes"] = "This fix was deliberately delayed."
            return rows
        with mock.patch("verifier.build.verification_rows", bad), self.assertRaises(WordingError):
            build(self.root)

    def test_quotes_are_exempt(self):
        self.assertEqual(find("> The program says it was late.\n"), [])
        self.assertEqual(len(find("It was late.")), 1)
        for word in ("overdue", "violation", "violated", "knowingly", "negligent", "failed to", "concealed"):
            self.assertTrue(find(f"This was {word} here."), word)
        for ok in ("later receipt", "the latest snapshot", "translated", "related"):
            self.assertEqual(find(ok), [], ok)


class Publishing(unittest.TestCase):
    def test_site_data_zip(self):
        with tempfile.TemporaryDirectory() as t:
            root = frozen_archive(Path(t) / "repo")
            build(root)
            m1 = build_site(root, Path(t) / "site1", "abc123")
            build_site(root, Path(t) / "site2", "abc123")
            z1 = (Path(t) / "site1/site-data.zip").read_bytes()
            self.assertEqual(z1, (Path(t) / "site2/site-data.zip").read_bytes())  # deterministic
            with zipfile.ZipFile(Path(t) / "site1/site-data.zip") as z:
                names = z.namelist()
                self.assertIn("MANIFEST.sha256.json", names)
                self.assertIn("data/summary.json", names)
                self.assertNotIn("data/programs-manual.csv", names)
                man = json.loads(z.read("MANIFEST.sha256.json"))
                import hashlib
                for name, sha in man["files"].items():
                    self.assertEqual(hashlib.sha256(z.read(name)).hexdigest(), sha)
            self.assertEqual(m1["source_commit"], "abc123")

    def test_workflows(self):
        pub = (ROOT / ".github/workflows/publish.yml").read_text()
        for action in ("upload-pages-artifact@", "deploy-pages@", "upload-artifact@", "checkout@"):
            line = next(l for l in pub.splitlines() if action in l)
            self.assertRegex(line, r"@[0-9a-f]{40} # v\d")
        self.assertIn("pages: write", pub)
        self.assertIn('paths: ["data/**"]', pub)
        ver = (ROOT / ".github/workflows/verify.yml").read_text()
        self.assertIn("sample_only:", ver)
        self.assertIn("python3 -m verifier records", ver)
        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", ver)
        self.assertNotIn("secrets.", ver)  # no new secret
        self.assertNotIn("pages: write", ver)

    def test_records_readme(self):
        text = (ROOT / "records/README.md").read_text()
        for needle in ("GitHub Advisory Database", "National Vulnerability Database", "commits, pull requests",
                       "https://docs.github.com/en/site-policy/github-terms/github-terms-of-service",
                       "https://nvd.nist.gov/developers/terms-of-use", "counsel",
                       "not endorsed or certified by the NVD"):
            self.assertIn(needle, text)


class LaterReceiptWording(unittest.TestCase):
    def test_no_late_receipt_wording_in_our_text(self):
        for path in [ROOT / "METHODOLOGY.md", ROOT / "README.md", *(ROOT / "docs").glob("data-contract-*.md"),
                     *(ROOT / "src/verifier").rglob("*.py")]:
            text = path.read_text(encoding="utf-8")
            self.assertIsNone(re.search(r"\blate receipt", text, re.I), path)
            self.assertNotIn("late Archive note", text)


if __name__ == "__main__":
    unittest.main()
