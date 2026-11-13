"""Each Verify run makes progress on unfinished lookups and does not repeat finished ones.

What run #7 (run 43323868973) showed, and what these tests pin down:
- Several findings can share one GHSA ID. ANT-2026-H97FY6C8 and ANT-2026-HN9XZXJ9 carry the
  same three GHSA IDs as ANT-2026-RXYVE4DZ, but link no repository; RXYVE4DZ links
  FreeRDP/FreeRDP. Only the first finding's repository (none) was kept, so the three FreeRDP
  repository advisories were never looked up.
- Requests without the token were made in alphabetical order: every global confirmation before
  any repository advisory. The 45-minute budget ran out first, so no finding was completed.
- Every lookup with the token was made again on every run, before unfinished ones.

Response bodies: REAL_403, REAL_404 and FREERDP are real GitHub responses frozen in
tests/fixtures (the 404 and the FreeRDP advisory were captured for other IDs and are reused
here as the bodies of these answers). Finding IDs starting ANT-TEST- are invented."""

from pathlib import Path
from unittest import mock

from test_phase3 import Phase3Case

from verifier import config
from verifier.records import global_unauth_key, repo_advisory_key, run_lookups
from verifier.records_read import RecordReader

ROOT = Path(__file__).resolve().parents[1]
DIAG = ROOT / "tests/fixtures/diagnose-403/records/diagnostic/github"
REAL_403 = (ROOT / "tests/fixtures/github-403/response.json").read_bytes()
REAL_404 = (DIAG / "advisories-unauthenticated/GHSA-85fq-fc5f-7j7g/response.json").read_bytes()
FREERDP = (DIAG / "repos/FreeRDP/FreeRDP/security-advisories/GHSA-vv64-95pc-vj9v/response.json").read_bytes()
H = {"Content-Type": "application/json", "X-RateLimit-Remaining": "4800", "X-RateLimit-Reset": "0"}
UH = {"Content-Type": "application/json", "X-RateLimit-Remaining": "58", "X-RateLimit-Reset": "0"}

TRIO = ["GHSA-mpxh-8fq3-x8mh", "GHSA-mvpx-xj7r-3p3r", "GHSA-p6r2-4hgm-m6ff"]
RXYVE4DZ_FIX = "https://github.com/FreeRDP/FreeRDP/commit/d7508ebcd82842a691ae4941e5104d14240a89ae"


def finding(ghsas, links=()):
    return {"cve_ids": [], "ghsa_ids": list(ghsas), "fix_links": list(links), "advisory_links": []}


class Base(Phase3Case):
    def setUp(self):
        super().setUp()
        self.unauth = []  # paths requested WITHOUT the token, in order

        def global_adv(req):
            if "Authorization" in req.headers:
                return (403, REAL_403, H)  # the token is refused for every ID here
            self.unauth.append(req.path)
            return (404, REAL_404, UH)
        self.gh.routes["/advisories/*"] = global_adv

    def repo(self, owner_repo, ok_with_token: bool):
        def route(req):
            if "Authorization" in req.headers:
                return (200, FREERDP, H) if ok_with_token else (403, REAL_403, H)
            self.unauth.append(req.path)
            return (404, REAL_404, UH)
        self.gh.routes[f"/repos/{owner_repo}/security-advisories/*"] = route

    def run_once(self, findings, **kw):
        return run_lookups(self.root, findings, self.record_fetcher(), **kw)


class SharedGhsaIds(Base):
    def test_repository_advisory_looked_up_when_an_earlier_finding_links_no_repository(self):
        self.repo("FreeRDP/FreeRDP", ok_with_token=True)
        self.gh.routes["/repos/FreeRDP/FreeRDP"] = (200, b'{"default_branch": "master"}', H)
        findings = {"ANT-2026-H97FY6C8": finding(TRIO), "ANT-2026-HN9XZXJ9": finding(TRIO),
                    "ANT-2026-RXYVE4DZ": finding(TRIO, [RXYVE4DZ_FIX])}
        tally = self.run_once(findings)
        self.assertEqual(tally["without_token"]["repository_advisories_with_token"], 3)
        rr = RecordReader(self.root, self.gh.url, self.nvd.url + "/rest/json/cves/2.0")
        for g in TRIO:
            self.assertEqual(rr.repo_advisory(("FreeRDP", "FreeRDP"), g)["status"], "ok", g)
            self.assertEqual(rr.repo_advisory(None, g)["status"], "no_repository_known", g)
        asked = [r.path for r in self.gh.requests if "/security-advisories/" in r.path]
        self.assertEqual(sorted(asked), sorted(f"/repos/FreeRDP/FreeRDP/security-advisories/{g}" for g in TRIO))

    def test_every_repository_linked_for_one_id(self):
        self.repo("a/one", ok_with_token=True)
        self.repo("b/two", ok_with_token=True)
        g = "GHSA-aaaa-bbbb-cccc"
        self.run_once({"ANT-TEST-1": finding([g], ["https://github.com/a/one/commit/" + "1" * 40]),
                       "ANT-TEST-2": finding([g], ["https://github.com/b/two/commit/" + "2" * 40])})
        asked = {r.path for r in self.gh.requests if "/security-advisories/" in r.path}
        self.assertEqual(asked, {f"/repos/a/one/security-advisories/{g}", f"/repos/b/two/security-advisories/{g}"})


class OrderAndBudget(Base):
    """Three invented findings; budget for two requests without the token per run."""

    def setUp(self):
        super().setUp()
        self.repo("o/refused", ok_with_token=False)
        self.repo("o/fine", ok_with_token=True)
        self.findings = {
            # needs 2: global confirmation + repository advisory without the token
            "ANT-TEST-A": finding(["GHSA-zzzz-0001-aaaa"], ["https://github.com/o/refused/commit/" + "a" * 40]),
            # needs 2: two global confirmations (no repository linked)
            "ANT-TEST-B": finding(["GHSA-0000-0002-bbbb", "GHSA-0000-0003-bbbb"]),
            # needs 1: global confirmation (its repository advisory was read with the token)
            "ANT-TEST-C": finding(["GHSA-zzzz-0004-cccc"], ["https://github.com/o/fine/commit/" + "c" * 40]),
        }

    def run_budget(self):
        with mock.patch.object(config, "UNAUTH_BUDGET_SECONDS", 100):  # two requests, 70 s apart
            return self.run_once(self.findings)

    def test_fewest_first_and_repository_advisory_with_its_global(self):
        t = self.run_budget()
        self.assertEqual(self.unauth, ["/advisories/GHSA-zzzz-0004-cccc",          # C: 1 request
                                       "/advisories/GHSA-zzzz-0001-aaaa"])         # A: first of 2
        self.assertEqual((t["without_token"]["requests_made"], t["without_token"]["left_for_next_run"]), (2, 3))
        self.run_budget()
        # next run: A's repository advisory (completes A), then B's first
        self.assertEqual(self.unauth[2:], ["/repos/o/refused/security-advisories/GHSA-zzzz-0001-aaaa",
                                           "/advisories/GHSA-0000-0002-bbbb"])

    def test_each_run_progresses_and_nothing_is_asked_twice(self):
        for _ in range(3):
            self.run_budget()
        self.assertEqual(len(self.unauth), 5)
        self.assertEqual(len(set(self.unauth)), 5)  # no repeats
        n = len(self.gh.requests) + len(self.nvd.requests)
        t = self.run_budget()  # everything answered: nothing more to ask
        self.assertEqual(len(self.unauth), 5)
        self.assertEqual(len(self.gh.requests) + len(self.nvd.requests), n)
        self.assertEqual(t["without_token"]["planned"], 0)
        rr = RecordReader(self.root, self.gh.url, self.nvd.url + "/rest/json/cves/2.0")
        self.assertEqual(rr.repo_advisory(("o", "refused"), "GHSA-zzzz-0001-aaaa")["status"], "not_found")
        for g in ("GHSA-zzzz-0001-aaaa", "GHSA-0000-0002-bbbb", "GHSA-0000-0003-bbbb", "GHSA-zzzz-0004-cccc"):
            self.assertEqual(rr.github_advisory(g)["status"], "not_in_global_database", g)

    def test_rate_limited_requests_go_first_next_run(self):
        calls = {"n": 0}

        def limited_once(req):
            if "Authorization" in req.headers:
                return (403, REAL_403, H)
            calls["n"] += 1
            self.unauth.append(req.path)
            if calls["n"] == 2:
                return (403, b'{"message": "API rate limit exceeded for 1.2.3.4."}',
                        {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "0"})
            return (404, REAL_404, UH)
        self.gh.routes["/advisories/*"] = limited_once
        self.run_once(self.findings)
        self.assertEqual(len(self.unauth), 2)  # stopped at the first rate-limit answer
        rate_limited = self.unauth[1]
        self.run_once(self.findings)
        self.assertEqual(self.unauth[2], rate_limited)  # asked first on the next run
        self.assertEqual(len(set(self.unauth[2:])), len(self.unauth[2:]))


class NoRepeatsWithTheToken(Base):
    def test_answered_lookups_are_not_asked_again_within_a_week(self):
        self.run_once(self.wolf_only())
        first = len(self.gh.requests) + len(self.nvd.requests)
        self.assertGreater(first, 0)
        t = self.run_once(self.wolf_only())
        self.assertEqual(len(self.gh.requests) + len(self.nvd.requests), first)  # nothing repeated
        self.assertGreater(t["skipped_already_answered"], 0)
        self.run_once(self.wolf_only(), refresh_days=0)  # the weekly refresh asks them again
        self.assertGreater(len(self.gh.requests) + len(self.nvd.requests), first)

    def test_unfinished_lookups_are_asked_again(self):
        self.run_once(self.wolf_only())
        path = next(r.path for r in self.gh.requests if r.path.startswith("/repos/"))
        good = self.gh.routes.get(path)
        self.gh.routes[path] = (502, b"Bad Gateway", {})
        self.run_once(self.wolf_only(), refresh_days=0)  # refresh: the answer is now unreadable
        self.gh.routes[path] = good if good is not None else self.gh.routes.pop(path)
        before = [r.path for r in self.gh.requests].count(path)
        self.run_once(self.wolf_only())  # within the week, but unfinished: asked again
        self.assertEqual([r.path for r in self.gh.requests].count(path), before + 1)
        others = [r.path for r in self.gh.requests[-5:]]
        self.assertIn(path, others)


class Keys(Base):
    def test_unauthenticated_keys_are_separate(self):
        self.assertNotEqual(global_unauth_key("GHSA-x").path, repo_advisory_key("o", "r", "GHSA-x",
                                                                                unauthenticated=True).path)
