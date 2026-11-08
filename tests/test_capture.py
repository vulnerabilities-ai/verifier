"""Capture behaviour, tested against local fake servers (never the real sites)."""

import hashlib
import json
import tempfile
import time
import unittest
from pathlib import Path

from fakeserver import FakeSite, archive_routes, dashboard_routes, policy_routes, snapshot_routes

from verifier import config
from verifier.audit import audit
from verifier.capture import BACKFILL_NOTE, RunInfo
from verifier.net import Fetcher
from verifier.runner import EXIT_FAILED, EXIT_OK, EXIT_ROBOTS, run

LABELS = config.ANTHROPIC_SNAPSHOT_LABELS


def files_under(root: Path) -> list[str]:
    cap = root / "captures"
    if not cap.exists():
        return []
    return sorted(p.relative_to(root).as_posix() for p in cap.rglob("*") if p.is_file())


class CaptureTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        routes = dashboard_routes()
        routes.update(snapshot_routes(LABELS))
        self.site = FakeSite(routes)
        self.ia = FakeSite(archive_routes())
        self.policy = FakeSite(policy_routes())
        self.base = self.site.url + "/2026/cvd/"

    def tearDown(self):
        for s in (self.site, self.ia, self.policy):
            s.close()
        self.tmp.cleanup()

    def capture(self, mode="normal", base=None, run_id="r1"):
        return run(self.root, base_url=base or self.base,
                   run=RunInfo(run_id=run_id, trigger="test", mode=mode),
                   fetcher=Fetcher(min_interval=0),
                   spn_prefix=self.ia.url + "/save/",
                   policy_url=self.policy.url + "/coordinated-vulnerability-disclosure",
                   spn_retry_wait=0)

    def log(self):
        import csv
        with open(self.root / "captures" / "capture-log.csv", encoding="utf-8") as f:
            return list(csv.DictReader(f))

    # -- acceptance: a run succeeds and the manifest matches the files --------
    def test_successful_run(self):
        out = self.capture()
        self.assertEqual(out.exit_code, EXIT_OK, out.messages)
        self.assertEqual(out.status, "ok")
        manifests = list((self.root / "captures").glob("2*/*/*/MANIFEST.json"))
        self.assertEqual(len(manifests), 1)
        m = json.loads(manifests[0].read_text())
        r = m["runs"][0]
        self.assertEqual({f["name"] for f in r["files"]},
                         {"dashboard.html", "payload.json", "ledger.json", "about.html", "archive.html"})
        for f in r["files"]:
            data = (self.root / f["stored_at"]).read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), f["sha256"])
            self.assertTrue(f["fetched_utc"].endswith("Z"))
            self.assertIn("headers", f)
        dash = next(f for f in r["files"] if f["name"] == "dashboard.html")
        self.assertEqual(dash["etag"], '"abc"')
        self.assertEqual(dash["last_modified"], "Fri, 02 Oct 2026 19:47:20 GMT")
        self.assertEqual(r["internet_archive"]["snapshot_timestamp"], "20261030191525")
        self.assertTrue(r["internet_archive"]["ok"])
        self.assertIn("note", r["internet_archive"])  # dated before the request: recorded as is
        self.assertEqual(audit(self.root), [])
        latest = json.loads((self.root / "captures" / "latest.json").read_text())
        self.assertEqual(latest["manifest"], manifests[0].relative_to(self.root).as_posix())
        self.assertEqual(len(self.log()), 1)
        self.assertEqual(self.log()[0]["status"], "ok")

    def test_user_agent_and_robots_read_first_on_every_host(self):
        self.capture()
        for site in (self.site, self.ia, self.policy):
            paths = [p for p, _ in site.requests]
            self.assertEqual(paths[0], "/robots.txt", site.url)
            self.assertTrue(all(ua == config.USER_AGENT for _, ua in site.requests))
        self.assertIn("verifier@vulnerabilities.ai", config.USER_AGENT)

    # -- acceptance: a second run the same day adds a log row, no duplicate files
    def test_second_run_same_day(self):
        self.capture(run_id="r1")
        before = files_under(self.root)
        out = self.capture(run_id="r2")
        self.assertEqual(out.exit_code, EXIT_OK, out.messages)
        after = files_under(self.root)
        self.assertEqual(before, after)  # no new files (only bookkeeping changed)
        self.assertEqual(len(self.log()), 2)
        self.assertEqual(out.new_files, 0)
        self.assertEqual(out.unchanged_files, 5)
        m = json.loads(next((self.root / "captures").glob("2*/*/*/MANIFEST.json")).read_text())
        self.assertEqual([r["run_id"] for r in m["runs"]], ["r1", "r2"])
        self.assertTrue(all(not f["newly_stored"] for f in m["runs"][1]["files"]))

    def test_changed_file_same_day_gets_time_suffix(self):
        self.capture(run_id="r1")
        self.site.routes["/2026/cvd/data/payload.json"] = (200, b'{"ok": 2}', {})
        self.capture(run_id="r2")
        new = [f for f in files_under(self.root) if "payload." in f and "anthropic-archive" not in f]
        self.assertEqual(len(new), 2, new)
        self.assertTrue(any(".T" in f and f.endswith("Z.json") for f in new))
        self.assertEqual(audit(self.root), [])

    def test_unchanged_file_on_a_later_day_points_to_old_copy(self):
        # Pretend an earlier day already stored identical payload bytes.
        old = self.root / "captures/2026/10/30"
        old.mkdir(parents=True)
        (old / "payload.json").write_bytes(b'{"ok": 1}')
        (old / "MANIFEST.json").write_text(json.dumps({"runs": [{"files": [{
            "name": "payload.json", "sha256": hashlib.sha256(b'{"ok": 1}').hexdigest(),
            "stored_at": "captures/2026/10/30/payload.json"}]}]}))
        self.capture()
        m = json.loads(sorted((self.root / "captures").glob("2*/*/*/MANIFEST.json"))[-1].read_text())
        p = next(f for f in m["runs"][0]["files"] if f["name"] == "payload.json")
        self.assertEqual(p["stored_at"], "captures/2026/10/30/payload.json")
        self.assertFalse(p["newly_stored"])

    # -- backfill ----------------------------------------------------------------
    def test_backfill_manifest(self):
        self.capture()
        for lbl in LABELS:
            m = json.loads((self.root / f"captures/anthropic-archive/{lbl}/MANIFEST.json").read_text())
            self.assertEqual(m["anthropic_snapshot_label"], lbl)
            self.assertTrue(m["our_fetch_utc"].endswith("Z"))
            self.assertEqual(m["note"], BACKFILL_NOTE)
            self.assertIn("not evidence of when we first saw", m["note"])
            names = {f["name"] for f in m["files"]}
            self.assertEqual(names, {"index.html", "data/payload.json", "data/extra.json"})
            self.assertEqual([a["path"] for a in m["not_present"]], ["data/ledger.json"])
        # one-time: a second run does not fetch the snapshots again
        n = len(self.site.requests)
        self.capture(run_id="r2")
        later = [p for p, _ in self.site.requests[n:]]
        self.assertFalse(any("snapshots" in p for p in later))

    def test_backfill_failure_reported_and_retried(self):
        del self.site.routes[f"/2026/cvd/snapshots/{LABELS[2]}/index.html"]
        out = self.capture()
        self.assertEqual(out.exit_code, EXIT_FAILED)
        self.assertEqual(out.status, "ok-with-errors")
        self.assertFalse((self.root / f"captures/anthropic-archive/{LABELS[2]}").exists())
        self.assertTrue((self.root / "captures/latest.json").exists())  # main capture kept

    # -- policy page --------------------------------------------------------------
    def test_policy_copied_monthly(self):
        self.capture()
        pol = list((self.root / "captures/policy").glob("*/MANIFEST.json"))
        self.assertEqual(len(pol), 1)
        n = len(self.policy.requests)
        self.capture(run_id="r2")
        self.assertEqual(len(self.policy.requests), n)  # not again this month

    # -- failures: loud, and nothing half-written ---------------------------------
    def assert_failed_cleanly(self, out, status="failed", code=EXIT_FAILED):
        self.assertEqual(out.exit_code, code, out.messages)
        self.assertEqual(out.status, status)
        self.assertEqual(files_under(self.root), ["captures/capture-log.csv"])
        self.assertEqual(self.log()[-1]["status"], status)

    def test_404_fails(self):
        self.site.routes["/2026/cvd/data/ledger.json"] = (404, b"", {})
        out = self.capture()
        self.assert_failed_cleanly(out)
        self.assertIn("HTTP 404", out.messages[0])

    def test_empty_file_fails(self):
        self.site.routes["/2026/cvd/about/index.html"] = (200, b"", {})
        out = self.capture()
        self.assert_failed_cleanly(out)
        self.assertIn("empty", out.messages[0])

    def test_bad_json_fails(self):
        self.site.routes["/2026/cvd/data/payload.json"] = (200, b"<html>oops</html>", {})
        out = self.capture()
        self.assert_failed_cleanly(out)
        self.assertIn("not valid JSON", out.messages[0])

    def test_unreachable_host_fails(self):
        out = self.capture(base="http://127.0.0.1:9/2026/cvd/")
        self.assert_failed_cleanly(out)

    # -- robots.txt on every host --------------------------------------------------
    def test_robots_disallow_dashboard_host(self):
        self.site.routes["/robots.txt"] = (200, b"User-agent: *\nDisallow: /2026/cvd/data/\n", {})
        out = self.capture()
        self.assert_failed_cleanly(out, "stopped-robots", EXIT_ROBOTS)
        self.assertIn("Jon", out.messages[0])
        fetched = [p for p, _ in self.site.requests]
        self.assertEqual(fetched, ["/robots.txt"])  # nothing else fetched

    def test_robots_disallow_archive_host(self):
        self.ia.routes["/robots.txt"] = (200, b"User-agent: *\nDisallow: /save/\n", {})
        out = self.capture()
        self.assert_failed_cleanly(out, "stopped-robots", EXIT_ROBOTS)
        self.assertNotIn("/2026/cvd/", [p for p, _ in self.site.requests])

    def test_robots_disallow_policy_host(self):
        self.policy.routes["/robots.txt"] = (200, b"User-agent: *\nDisallow: /\n", {})
        out = self.capture()
        self.assert_failed_cleanly(out, "stopped-robots", EXIT_ROBOTS)

    def test_robots_rule_for_our_user_agent(self):
        self.site.routes["/robots.txt"] = (
            200, b"User-agent: vulnerabilities.ai-verifier\nDisallow: /\n\nUser-agent: *\nAllow: /\n", {})
        out = self.capture()
        self.assertEqual(out.exit_code, EXIT_ROBOTS)

    def test_missing_robots_means_allowed(self):
        del self.site.routes["/robots.txt"]
        self.assertEqual(self.capture().exit_code, EXIT_OK)

    # -- Internet Archive failure: capture kept, run red ----------------------------
    def test_archive_failure_keeps_capture(self):
        self.ia.routes["/save/*"] = (503, b"busy", {})
        out = self.capture()
        self.assertEqual(out.exit_code, EXIT_FAILED)
        self.assertEqual(out.status, "ok-archive-failed")
        m = json.loads(next((self.root / "captures").glob("2*/*/*/MANIFEST.json")).read_text())
        self.assertFalse(m["runs"][0]["internet_archive"]["ok"])
        self.assertEqual(len(m["runs"][0]["internet_archive"]["attempts"]), 2)

    # -- acceptance: deliberately broken address -------------------------------------
    def test_broken_address_test_mode_writes_only_a_log_row(self):
        out = self.capture(mode="test", base=self.site.url + "/no-such-place/")
        self.assertEqual(out.exit_code, EXIT_FAILED)
        self.assertEqual(files_under(self.root), ["captures/capture-log.csv"])
        row = self.log()[0]
        self.assertEqual(row["status"], "failed-test")
        self.assertEqual(row["mode"], "test")
        self.assertEqual(self.ia.requests, [])  # Archive never contacted in test mode
        self.assertEqual(self.policy.requests, [])

    def test_test_mode_never_stores_even_if_fetch_works(self):
        out = self.capture(mode="test")
        self.assertEqual(files_under(self.root), ["captures/capture-log.csv"])
        self.assertEqual(out.status, "passed-test")


class PolitenessTests(unittest.TestCase):
    def test_default_interval_is_one_second(self):
        self.assertGreaterEqual(config.MIN_INTERVAL_SECONDS, 1.0)
        self.assertGreaterEqual(Fetcher().min_interval, 1.0)

    def test_interval_enforced_per_host(self):
        site = FakeSite({"/robots.txt": (200, b"", {}), "/a": (200, b"x", {})})
        try:
            f = Fetcher(min_interval=0.3)
            f.get(site.url + "/a")
            t = time.monotonic()
            f.get(site.url + "/a")
            self.assertGreaterEqual(time.monotonic() - t, 0.25)
        finally:
            site.close()


if __name__ == "__main__":
    unittest.main()
