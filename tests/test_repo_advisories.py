"""GHSA IDs without a global-database entry, and repository advisories as their own source.

Uses the real responses from the diagnose_403 run (review/diagnose-403), frozen in
tests/fixtures/diagnose-403/: the global request without the token returned 404 for all five
IDs; the repository advisory with the token returned 200 for jetty/jetty.project and
FreeRDP/FreeRDP and 403 for facebook/hermes and php/php-src; one ID had no repository."""

import json
import unittest
from pathlib import Path

from test_phase3 import Phase3Case, j

from verifier import config
from verifier.build.phase3 import _ids_exist, _repo_columns, fully_checked
from verifier.diagnose403 import _describe
from verifier.records import refused_followups, run_lookups
from verifier.records_read import RecordReader

ROOT = Path(__file__).resolve().parents[1]
DIAG = ROOT / "tests/fixtures/diagnose-403/records/diagnostic/github"
REAL_403 = (ROOT / "tests/fixtures/github-403/response.json").read_bytes()
REAL_404 = (DIAG / "advisories-unauthenticated/GHSA-85fq-fc5f-7j7g/response.json").read_bytes()
JETTY = (DIAG / "repos/jetty/jetty.project/security-advisories/GHSA-85fq-fc5f-7j7g/response.json").read_bytes()
FREERDP = (DIAG / "repos/FreeRDP/FreeRDP/security-advisories/GHSA-vv64-95pc-vj9v/response.json").read_bytes()
REPO_403 = (DIAG / "repos/facebook/hermes/security-advisories/GHSA-9qm2-7vmf-h64f/response.json").read_bytes()
H = {"Content-Type": "application/json", "X-RateLimit-Remaining": "4800", "X-RateLimit-Reset": "0"}
UH = {"Content-Type": "application/json", "X-RateLimit-Remaining": "58", "X-RateLimit-Reset": "0"}

# Card links, as on the real cards of these findings.
FINDINGS = {
    "ANT-2026-Y9CTVKPP": ("GHSA-85fq-fc5f-7j7g", ["https://github.com/jetty/jetty.project/commit/b5bdc24629cac46ed51c12de11afd7a068cb3b48"]),
    "ANT-2026-YQ12XT7Y": ("GHSA-mrvp-58gg-8x22", []),
    "ANT-2026-S1E4Y69J": ("GHSA-vv64-95pc-vj9v", ["https://github.com/FreeRDP/FreeRDP/commit/0adf5e30d01be84e190a359a7bdd37bc51d740cc"]),
    "ANT-2026-YZAKBHEW": ("GHSA-9qm2-7vmf-h64f", ["https://github.com/facebook/hermes/commit/cb8a9a3fa39f9165f6db93dcee871cfa625a9753"]),
    "ANT-2026-KP4YD2Z6": ("GHSA-mh9x-w77w-65xw", ["https://github.com/php/php-src/commit/a9c7dfefbdcab6b6d2a5c5692f5dcfb5676814ae"]),
}


def findings():
    return {fid: {"cve_ids": [], "ghsa_ids": [g], "fix_links": links, "advisory_links": []}
            for fid, (g, links) in FINDINGS.items()}


class RepoAdvisories(Phase3Case):
    def setUp(self):
        super().setUp()
        self.unauth_paths = []

        def global_adv(req):
            if "Authorization" in req.headers:
                return (403, REAL_403, H)  # real: token refused
            self.unauth_paths.append(req.path)
            return (404, REAL_404, UH)  # real: no global entry
        self.gh.routes["/advisories/*"] = global_adv
        self.gh.routes["/repos/jetty/jetty.project/security-advisories/GHSA-85fq-fc5f-7j7g"] = (200, JETTY, H)
        self.gh.routes["/repos/FreeRDP/FreeRDP/security-advisories/GHSA-vv64-95pc-vj9v"] = (200, FREERDP, H)

        def hermes(req):  # real 403 with the token; without the token (not in the run): 404
            if "Authorization" in req.headers:
                return (403, REPO_403, H)
            self.unauth_paths.append(req.path)
            return (404, REAL_404, UH)

        def php(req):  # real 403 with the token; without the token (not in the run): 403 again
            if "Authorization" in req.headers:
                return (403, REPO_403, H)
            self.unauth_paths.append(req.path)
            return (403, b'{"message": "Must have admin rights to Repository."}', UH)
        self.gh.routes["/repos/facebook/hermes/security-advisories/GHSA-9qm2-7vmf-h64f"] = hermes
        self.gh.routes["/repos/php/php-src/security-advisories/GHSA-mh9x-w77w-65xw"] = php

    def run_all(self):
        run_lookups(self.root, findings(), self.record_fetcher())
        return RecordReader(self.root)

    def test_not_in_global_database_confirmed_without_token(self):
        rr = self.run_all()
        for _, (g, _) in FINDINGS.items():
            a = rr.github_advisory(g)
            self.assertEqual(a["status"], "not_in_global_database", g)
            self.assertEqual(a["reason"], "GitHub's global advisory database has no entry for this ID")
            self.assertIn('with the token: HTTP 403, message "Resource not accessible by integration"', a["evidence"])
            self.assertIn('without the token: HTTP 404, message "Not Found"', a["evidence"])
        # the requests without the token never carried it, and were paced one per 70 seconds
        unauth = [r for r in self.gh.requests if r.path.startswith(("/advisories/", "/repos/")) and "Authorization" not in r.headers]
        self.assertEqual(len(unauth), len(self.unauth_paths))
        self.assertGreaterEqual(self.fake.sleeps.count(70.0), len(self.unauth_paths) - 1)

    def test_repository_advisories(self):
        rr = self.run_all()
        jetty = rr.repo_advisory(("jetty", "jetty.project"), "GHSA-85fq-fc5f-7j7g")
        self.assertEqual((jetty["status"], jetty["read_with"], jetty["severity"], jetty["state"]),
                         ("ok", "token", "high", "published"))
        self.assertEqual(jetty["cve_id"], "CVE-2026-19204")
        self.assertEqual(jetty["cwes"], ["CWE-770", "CWE-789"])
        self.assertEqual((jetty["cvss_v31_score"], jetty["cvss_v40_score"]), (None, 8.7))  # v3 is a placeholder
        free = rr.repo_advisory(("FreeRDP", "FreeRDP"), "GHSA-vv64-95pc-vj9v")
        self.assertEqual((free["status"], free["cve_id"], free["cwes"]), ("ok", "CVE-2026-73242", ["CWE-122"]))
        self.assertEqual((free["cvss_v31_score"], free["cvss_v40_score"]), (None, None))  # placeholders only
        hermes = rr.repo_advisory(("facebook", "hermes"), "GHSA-9qm2-7vmf-h64f")
        self.assertEqual((hermes["status"], hermes["read_with"]), ("not_found", "no token"))
        php = rr.repo_advisory(("php", "php-src"), "GHSA-mh9x-w77w-65xw")
        self.assertEqual(php["status"], "lookup_unreadable")
        self.assertEqual(php["reason"], 'with the token: HTTP 403, message "Resource not accessible by integration"; '
                                        'without the token: unexpected HTTP 403, message "Must have admin rights to Repository."')
        none = rr.repo_advisory(None, "GHSA-mrvp-58gg-8x22")
        self.assertEqual(none["status"], "no_repository_known")
        self.assertIn("no repository known", none["reason"])
        # only refused repository advisories were retried without the token
        self.assertTrue(any("hermes" in p for p in self.unauth_paths))
        self.assertFalse(any("jetty" in p or "FreeRDP" in p for p in self.unauth_paths))
        for f in (self.root / "records").rglob("*"):
            if f.is_file():
                self.assertNotIn(b"TOKEN-should", f.read_bytes())

    def test_ids_exist_and_fully_checked(self):
        self.assertEqual(_ids_exist({"G": {"github": "not_in_global_database", "repository_advisory": "exists"}}), "verified")
        self.assertEqual(_ids_exist({"G": {"github": "not_in_global_database", "repository_advisory": "not_found"}}), "not_found")
        self.assertEqual(_ids_exist({"G": {"github": "not_in_global_database",
                                           "repository_advisory": "no_repository_known"}}), "no_repository_known")
        self.assertEqual(_ids_exist({"G": {"github": "not_in_global_database",
                                           "repository_advisory": "lookup_unreadable"}}), "lookup_unreadable")
        self.assertTrue(fully_checked("match", "verified", "yes"))  # a repository advisory counts as confirmed
        self.assertFalse(fully_checked("match", "no_repository_known", "yes"))

    def test_repo_columns_are_their_own_source(self):
        rr = self.run_all()
        cols = _repo_columns([rr.repo_advisory(("jetty", "jetty.project"), "GHSA-85fq-fc5f-7j7g")])
        self.assertEqual(cols["repo_advisory_repository"], "jetty/jetty.project")
        self.assertEqual(cols["repo_advisory_published"], "2026-09-16")
        self.assertEqual(cols["repo_advisory_cvss_v40_score"], 8.7)
        self.assertIsNone(cols["repo_advisory_cvss_v31_score"])
        self.assertEqual(_repo_columns([])["repo_advisory_cwes"], [])

    def test_stops_at_first_rate_limit_and_resumes(self):
        n = {"k": 0}

        def global_adv(req):
            if "Authorization" in req.headers:
                return (403, REAL_403, H)
            n["k"] += 1
            if n["k"] == 1:
                return (404, REAL_404, UH)
            return (403, b'{"message": "API rate limit exceeded for 1.2.3.4."}',
                    {"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "0"})
        self.gh.routes["/advisories/*"] = global_adv
        tally = run_lookups(self.root, findings(), self.record_fetcher())
        self.assertIn("rate limit", (tally["without_token"]["stopped"] or "").lower())
        self.assertEqual(n["k"], 2)  # no further requests without the token after the rate limit
        rr = RecordReader(self.root)
        statuses = sorted(rr.github_advisory(g)["status"] for g, _ in FINDINGS.values())
        self.assertEqual(statuses.count("not_in_global_database"), 1)
        self.assertEqual(statuses.count("github_refused_token"), 4)  # confirmation pending
        # next run: the rate-limited ones go first and complete
        self.gh.routes["/advisories/*"] = lambda req: (403, REAL_403, H) if "Authorization" in req.headers else (404, REAL_404, UH)
        rf = self.record_fetcher()
        run_lookups(self.root, findings(), rf)
        rr = RecordReader(self.root)
        self.assertTrue(all(rr.github_advisory(g)["status"] == "not_in_global_database" for g, _ in FINDINGS.values()))

    def test_only_api_github_used(self):
        self.assertEqual(config.GITHUB_API, "https://api.github.com")
        self.assertEqual(config.API_ROBOTS_EXEMPT, frozenset({"api.github.com", "services.nvd.nist.gov"}))


class DiagnosticReportIdenticalTo(unittest.TestCase):
    def test_identical_to_path(self):
        o = {"outcome": "fetched", "status": 404, "message": "Not Found",
             "stored_at": "records/diagnostic/github/advisories-unauthenticated/GHSA-85fq-fc5f-7j7g/response.json",
             "own_folder": "records/diagnostic/github/advisories-unauthenticated/GHSA-mrvp-58gg-8x22/"}
        text = _describe(o)
        self.assertIn("identical to `records/diagnostic/github/advisories-unauthenticated/GHSA-85fq-fc5f-7j7g/response.json`", text)
        o["own_folder"] = "records/diagnostic/github/advisories-unauthenticated/GHSA-85fq-fc5f-7j7g/"
        self.assertIn("raw response:", _describe(o))


if __name__ == "__main__":
    unittest.main()
