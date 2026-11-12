"""Fixes after the first full Verify run: NVD pacing and retry on 429, the
github_refused_token status, and the diagnose_403 diagnostic."""

import json
import unittest
from pathlib import Path

from fakeserver import FakeSite
from test_phase3 import WOLF_ID, Phase3Case, github_routes, j

from verifier import config
from verifier.build import build
from verifier.diagnose403 import choose_ids, diagnose, refused_ids, report
from verifier.net import Fetcher
from verifier.records import run_lookups
from verifier.records_read import RecordReader

ROOT = Path(__file__).resolve().parents[1]
REAL_403 = (ROOT / "tests/fixtures/github-403/response.json").read_bytes()  # the real response
REFUSED = (403, REAL_403, {"Content-Type": "application/json", "X-RateLimit-Limit": "5000",
                           "X-RateLimit-Remaining": "4871", "X-RateLimit-Reset": "0"})
CVES = [f"CVE-2026-{n}" for n in range(20000, 20003)]


class NvdPacingAndRetry(Phase3Case):
    def setUp(self):
        super().setUp()
        for c in CVES:
            self.nvd.routes[f"/rest/json/cves/2.0?cveId={c}"] = j({"totalResults": 0, "vulnerabilities": []})
            self.gh.routes[f"/advisories?cve_id={c}"] = j([])
        self.inp = {"X": {"cve_ids": CVES, "ghsa_ids": [], "fix_links": [], "advisory_links": []}}

    def nvd_stamps(self, rf):
        stamps = []
        orig = rf._pace_nvd

        def spy():
            orig()
            stamps.append(self.fake.t)
        rf._pace_nvd = spy
        return stamps

    def test_defaults(self):
        self.assertEqual((config.NVD_MIN_GAP_SECONDS, config.NVD_RETRY_WAIT_SECONDS, config.NVD_RETRIES), (8.0, 35.0, 3))

    def test_one_request_every_eight_seconds(self):
        rf = self.record_fetcher()
        stamps = self.nvd_stamps(rf)
        run_lookups(self.root, self.inp, rf)
        self.assertEqual(len(stamps), 3)
        self.assertTrue(all(b - a >= 8 for a, b in zip(stamps, stamps[1:])))

    def test_429_is_retried_after_35_seconds(self):
        calls = {"n": 0}

        def busy_twice(req):
            calls["n"] += 1
            return (429, b"", {}) if calls["n"] <= 2 else j({"totalResults": 0, "vulnerabilities": []})
        self.nvd.routes[f"/rest/json/cves/2.0?cveId={CVES[0]}"] = busy_twice
        rf = self.record_fetcher()
        run_lookups(self.root, self.inp, rf)
        self.assertEqual(self.fake.sleeps.count(35.0), 2)
        self.assertIsNone(rf.nvd_stopped)
        m = json.loads((self.root / f"records/nvd/cves/{CVES[0]}/MANIFEST.json").read_text())
        self.assertEqual((m["attempts"][-1]["outcome"], m["attempts"][-1]["status"]), ("fetched", 200))
        self.assertEqual(m["attempts"][-1]["retries_after_429"], 2)
        self.assertEqual(RecordReader(self.root).nvd_cve(CVES[0])["status"], "not_found")  # read normally

    def test_429_after_three_retries_is_rate_limited_and_resumed_first(self):
        for c in CVES:
            self.nvd.routes[f"/rest/json/cves/2.0?cveId={c}"] = (429, b"", {})
        rf = self.record_fetcher()
        run_lookups(self.root, self.inp, rf)  # never raises
        self.assertEqual(self.fake.sleeps.count(35.0), 3)  # 3 retries, then stop
        nvd_calls = [p for p in self.nvd.paths() if p.startswith("/rest/")]
        self.assertEqual(len(nvd_calls), 4)  # 1 request + 3 retries; the rest are not made
        self.assertIn("after 3 retries", rf.nvd_stopped)
        for c in CVES:
            self.assertEqual(RecordReader(self.root).nvd_cve(c)["status"], "rate_limited")
        # next run: NVD answers again; the rate-limited lookups go first
        for c in CVES:
            self.nvd.routes[f"/rest/json/cves/2.0?cveId={c}"] = j({"totalResults": 0, "vulnerabilities": []})
        self.gh.routes["/advisories?cve_id=CVE-2026-99999"] = j([])
        self.nvd.routes["/rest/json/cves/2.0?cveId=CVE-2026-99999"] = j({"totalResults": 0, "vulnerabilities": []})
        inp = {"X": {**self.inp["X"], "cve_ids": CVES + ["CVE-2026-99999"]}}
        rf = self.record_fetcher()
        order = []
        orig = rf.fetch
        rf.fetch = lambda k: (order.append(k.path), orig(k))[1]
        run_lookups(self.root, inp, rf)
        first = order[:3]
        self.assertEqual(sorted(first), sorted(f"nvd/cves/{c}" for c in CVES))  # resumed before anything new
        for c in CVES:
            self.assertEqual(RecordReader(self.root).nvd_cve(c)["status"], "not_found")


class GithubRefusedToken(Phase3Case):
    def test_real_403_is_github_refused_token_with_exact_message(self):
        self.gh.routes["/advisories/GHSA-q349-x427-xg3w"] = REFUSED
        rf = self.record_fetcher()
        run_lookups(self.root, self.wolf_only(), rf)
        self.assertIsNone(rf.github_stopped)  # not a rate limit: lookups carry on
        a = RecordReader(self.root).github_advisory("GHSA-q349-x427-xg3w")
        self.assertEqual(a["status"], "github_refused_token")
        self.assertEqual(a["reason"], "Resource not accessible by integration")  # exactly as GitHub sent it
        r = build(self.root)
        w = next(v for v in r["tables"]["verification"] if v["finding_id"] == WOLF_ID)
        self.assertEqual(w["lookup_status"], "github_refused_token")
        self.assertIn('message "Resource not accessible by integration"', w["notes"])
        self.assertNotIn("lookup_unreadable", json.dumps(w))
        self.assertEqual(w["fix_merged"], "yes")  # the other lookups still ran
        self.assertEqual(w["checked"], "no")
        self.assertEqual(r["summary"]["lookups"].get("github_refused_token"), 1)

    def test_other_403_stays_unreadable(self):
        self.gh.routes["/advisories/GHSA-q349-x427-xg3w"] = (403, b'{"message": "Something else"}',
                                                            {"X-RateLimit-Remaining": "4000", "X-RateLimit-Reset": "0"})
        run_lookups(self.root, self.wolf_only(), self.record_fetcher())
        self.assertEqual(RecordReader(self.root).github_advisory("GHSA-q349-x427-xg3w")["status"], "lookup_unreadable")


class Diagnose403(Phase3Case):
    def setUp(self):
        super().setUp()
        self.gh.routes["/advisories/GHSA-q349-x427-xg3w"] = REFUSED
        run_lookups(self.root, self.wolf_only(), self.record_fetcher())

    def test_choose_ids(self):
        self.assertEqual(refused_ids(self.root), ["GHSA-q349-x427-xg3w"])
        self.assertEqual(choose_ids(self.root, "auto"), ["GHSA-q349-x427-xg3w"])
        self.assertEqual(len(choose_ids(self.root, ",".join(f"GHSA-{i}" for i in range(9)))), 5)

    def test_unauthenticated_then_repository_endpoint(self):
        ids = ["GHSA-q349-x427-xg3w", "GHSA-aaaa-bbbb-cccc", "GHSA-dddd-eeee-ffff"]
        unauth_calls = {"n": 0}
        adv = json.loads(github_routes()["/advisories/GHSA-q349-x427-xg3w"][1])

        def global_adv(req):
            if "Authorization" in req.headers:
                return REFUSED
            unauth_calls["n"] += 1
            if unauth_calls["n"] == 1:
                return j(adv, headers={"X-RateLimit-Remaining": "59", "X-RateLimit-Reset": "0"})
            return (403, b'{"message": "API rate limit exceeded for 1.2.3.4."}',
                    {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "0"})
        del self.gh.routes["/advisories/GHSA-q349-x427-xg3w"]  # every request goes through global_adv
        self.gh.routes["/advisories/*"] = global_adv
        self.gh.routes["/repos/wolfSSL/wolfssl/security-advisories/*"] = j({"message": "Not Found"}, status=404)
        findings = {WOLF_ID: {**self.wolf_only()[WOLF_ID], "ghsa_ids": ids, "project": "wolfssl/wolfssl"}}
        self.gh.requests.clear()
        host = self.gh.url.split("//")[1]
        res = diagnose(self.root, ids, findings, token="TOKEN-x", github_api=self.gh.url,
                       unauth_fetcher=Fetcher(min_interval=0, credential_destinations=frozenset(),
                                              robots_exempt_hosts=frozenset({host})),
                       auth_fetcher=Fetcher(min_interval=0, credential_destinations=frozenset({self.gh.url}),
                                            robots_exempt_hosts=frozenset({host})),
                       sleep=self.fake.sleep, clock=self.fake.clock, wall=lambda: 0.0)
        # unauthenticated requests never carry the token, are 70 s apart, and stop at the first rate limit
        unauth = [r for r in self.gh.requests if r.path.startswith("/advisories/")]
        self.assertEqual(len(unauth), 2)
        self.assertTrue(all("Authorization" not in r.headers for r in unauth))
        self.assertIn(70.0, self.fake.sleeps)
        self.assertEqual(res[0]["global_without_token"]["status"], 200)
        self.assertEqual(res[1]["global_without_token"]["status"], 403)
        self.assertEqual(res[2]["global_without_token"]["outcome"], "rate_limited")
        # repository advisory endpoint, with the token, for each ID
        repo_calls = [r for r in self.gh.requests if "/security-advisories/" in r.path]
        self.assertEqual(len(repo_calls), 3)
        self.assertTrue(all(r.headers.get("Authorization") == "Bearer TOKEN-x" for r in repo_calls))
        self.assertEqual(res[0]["repository"], "wolfSSL/wolfssl")
        self.assertEqual(res[0]["repository_advisory_with_token"]["status"], 404)
        # raw responses saved under records/diagnostic/
        self.assertTrue((self.root / "records/diagnostic/github/advisories-unauthenticated/GHSA-q349-x427-xg3w/response.json").exists())
        self.assertTrue((self.root / "records/diagnostic/github/repos/wolfSSL/wolfssl/security-advisories/GHSA-q349-x427-xg3w/MANIFEST.json").exists())
        text = report(res, "2026-01-01")
        self.assertIn("Global advisory readable without the token: 1 of 3", text)
        self.assertIn('message "API rate limit exceeded for 1.2.3.4."', text)
        for f in (self.root / "records").rglob("*"):
            if f.is_file():
                self.assertNotIn(b"TOKEN-x", f.read_bytes())

    def test_only_the_two_api_hosts(self):
        self.assertEqual(config.GITHUB_API, "https://api.github.com")
        wf = (ROOT / ".github/workflows/verify.yml").read_text()
        self.assertIn("diagnose_403:", wf)
        self.assertIn("python3 -m verifier diagnose-403", wf)
        self.assertNotIn("secrets.", wf)
        urls = set()
        import re
        for path in (ROOT / "src/verifier").rglob("*.py"):
            urls |= set(re.findall(r"https://([a-z0-9.-]+)", path.read_text()))
        api_hosts = {u for u in urls if u.startswith("api.") or "nvd" in u}
        self.assertEqual(api_hosts, {"api.github.com", "services.nvd.nist.gov"})


if __name__ == "__main__":
    unittest.main()
