"""Internet Archive behaviour (the November 2026 review items)."""

import io
import json
import os
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

from fakeserver import FakeSite
from helpers import CaptureCase

from verifier import config
from verifier.runner import EXIT_ARCHIVE_STALE, EXIT_FAILED, EXIT_OK

ROOT = Path(__file__).resolve().parents[1]


def day_manifest(root):
    return sorted((root / "captures").glob("2*/*/*/MANIFEST.json"))[-1]


def ia_record(root, run_index=-1):
    return json.loads(day_manifest(root).read_text())["runs"][run_index]["internet_archive"]


def save_paths(ia):
    return [r for r in ia.requests if r.path.startswith("/save") and "/status/" not in r.path]


class ArchiveAnonymous(CaptureCase):
    # 5: dashboard, ledger.json and payload.json, at least 20 seconds apart
    def test_saves_three_files_spaced(self):
        out = self.capture()
        self.assertEqual(out.status, "ok")
        ia = ia_record(self.root)
        self.assertEqual(ia["mode"], "anonymous")
        self.assertEqual([i["name"] for i in ia["items"]], config.ARCHIVE_FILES)
        self.assertEqual(len(save_paths(self.ia)), 3)
        # two gaps of 20 s between the three requests (fake clock)
        self.assertEqual(self.fake.sleeps, [20, 20])

    # 6: raw "id_" copy compared with ours
    def test_raw_copy_match_and_mismatch(self):
        self.ia.raw_override[self.base + "data/ledger.json"] = b'["changed"]'
        self.capture()
        items = {i["name"]: i for i in ia_record(self.root)["items"]}
        self.assertEqual(items["dashboard.html"]["receipt"]["raw_check"]["result"], "match")
        self.assertIn("id_/", items["dashboard.html"]["receipt"]["raw_check"]["raw_url"])
        self.assertEqual(items["ledger.json"]["receipt"]["raw_check"]["result"], "mismatch")

    def test_reused_snapshot_is_recorded_as_such(self):
        self.ia.behaviour = "reuse"
        self.capture()
        r = ia_record(self.root)["items"][0]["receipt"]
        self.assertTrue(r["reused_existing_snapshot"])
        self.assertLess(r["seconds_after_our_fetch"], 0)
        self.assertEqual(r["snapshot_timestamp"], "20261030191525")

    # 1 and 2: busy Archive is a warning; retries after 1, 3 and 10 minutes
    def test_busy_archive_is_a_warning_with_backoff(self):
        self.ia.behaviour = "busy"
        out = self.capture()
        self.assertEqual(out.exit_code, EXIT_OK)
        self.assertEqual(out.status, "archive-pending")
        self.assertEqual(self.log()[-1]["status"], "archive-pending")
        self.assertTrue(any("No Internet Archive receipt" in w for w in out.warnings))
        ia = ia_record(self.root)
        self.assertFalse(ia["ok"])
        self.assertEqual(ia["pending"], config.ARCHIVE_FILES)
        for item in ia["items"]:
            self.assertEqual(len(item["attempts"]), 4)
            self.assertTrue(all(a["outcome"] == "busy" and "Archive busy" in a["error"]
                                for a in item["attempts"]))
        for wait in (60, 180, 600):
            self.assertIn(wait, self.fake.sleeps)
        self.assertTrue((self.root / "captures/latest.json").exists())

    def test_budget_limits_retries(self):
        self.ia.behaviour = "busy"
        self.capture(budget=400)  # room for the 1- and 3-minute retry rounds (plus 20 s spacing), not the 10-minute one
        self.assertNotIn(600, self.fake.sleeps)
        self.assertEqual(len(ia_record(self.root)["items"][0]["attempts"]), 3)

    def test_retry_succeeds_after_busy(self):
        url = self.base + "data/ledger.json"
        self.ia.behaviour_for[url] = "busy"
        orig = self.ia._save_get

        def flip(req):
            if len([r for r in save_paths(self.ia) if url in r.path]) >= 2:
                self.ia.behaviour_for.pop(url, None)
            return orig(req)
        self.ia.routes["/save/*"] = flip
        out = self.capture()
        self.assertEqual(out.status, "ok")
        item = next(i for i in ia_record(self.root)["items"] if i["name"] == "ledger.json")
        self.assertEqual([a["outcome"] for a in item["attempts"]], ["busy", "snapshot"])

    # 3: after a failed request, ask the availability API
    def test_error_but_saved_found_by_availability(self):
        self.ia.behaviour = "error-but-saved"
        out = self.capture()
        self.assertEqual(out.status, "ok")
        item = ia_record(self.root)["items"][0]
        self.assertEqual(item["attempts"][0]["outcome"], "error")
        self.assertEqual(item["availability_checks"][0]["result"], "found_after_our_fetch")
        self.assertEqual(item["receipt"]["source"], "availability-api")
        self.assertGreaterEqual(item["receipt"]["seconds_after_our_fetch"], 0)

    def test_dropped_connection_recorded(self):
        self.ia.behaviour = "drop"
        out = self.capture()
        self.assertEqual((out.exit_code, out.status), (EXIT_OK, "archive-pending"))
        a = ia_record(self.root)["items"][0]["attempts"][0]
        self.assertEqual(a["outcome"], "error")
        self.assertIn("Could not reach", a["error"])
        self.assertEqual(ia_record(self.root)["items"][0]["availability_checks"][0]["result"], "none")

    # 7: receipts found later are appended to the earlier record
    def test_late_receipt_appended_without_overwriting(self):
        self.ia.behaviour = "drop"
        self.capture(run_id="r1")
        path = day_manifest(self.root)
        before = json.loads(path.read_text())
        # The Archive later holds a snapshot made just after our fetch.
        for item in before["runs"][0]["internet_archive"]["items"]:
            self.ia.snapshots[item["url"]] = [item["our_fetched_utc"].replace("-", "")
                                              .replace(":", "").replace("T", "").rstrip("Z")]
        self.ia.behaviour = "ok"
        out = self.capture(run_id="r2")
        after = json.loads(path.read_text())
        self.assertEqual(after["runs"][0], before["runs"][0])  # first run untouched
        notes = after["appended_notes"]
        self.assertEqual({n["name"] for n in notes}, set(config.ARCHIVE_FILES))
        self.assertTrue(all(n["note_type"] == "late-archive-receipt" and n["run_id"] == "r1"
                            for n in notes))
        self.assertTrue(any("late Archive note" in m for m in out.messages))
        # A third run does not add the same notes again.
        self.capture(run_id="r3")
        self.assertEqual(len(json.loads(path.read_text())["appended_notes"]), 3)

    def test_old_format_pending_run_is_checked(self):
        # Phase 1 format, as in the real Nov 8 run 1 record (dated yesterday here).
        from datetime import datetime, timedelta, timezone
        y = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=1)
        day = self.root / f"captures/{y:%Y/%m/%d}"
        day.mkdir(parents=True)
        url = self.base
        m = {"runs": [{"run_id": "old-1", "files": [{
            "name": "dashboard.html", "url": url, "fetched_utc": f"{y:%Y-%m-%dT%H:%M:%SZ}",
            "sha256": "0" * 64, "stored_at": None}],
            "internet_archive": {"ok": False, "error": "Connection refused"}}]}
        (day / "MANIFEST.json").write_text(json.dumps(m))
        self.ia.snapshots[url] = [f"{y + timedelta(seconds=7):%Y%m%d%H%M%S}"]
        self.capture(run_id="new")
        notes = json.loads((day / "MANIFEST.json").read_text())["appended_notes"]
        self.assertEqual(len(notes), 1)
        self.assertEqual(notes[0]["receipt"]["seconds_after_our_fetch"], 7)
        self.assertEqual(notes[0]["receipt"]["raw_check"]["result"], "mismatch")  # sha was dummy

    # 1: no receipt for 3 consecutive days -> issue (exit 4), still a green capture
    def test_three_days_without_receipt(self):
        for d in ("2026-11-05", "2026-11-06"):
            y, mo, dd = d.split("-")
            p = self.root / f"captures/{y}/{mo}/{dd}"
            p.mkdir(parents=True)
            (p / "MANIFEST.json").write_text(json.dumps({"runs": [{
                "run_id": d, "files": [],
                "internet_archive": {"ok": False, "items": [
                    {"name": "dashboard.html", "status": "pending", "url": "x",
                     "our_fetched_utc": f"{d}T06:23:00Z", "our_sha256": "0"}]}}]}))
        self.ia.behaviour = "busy"
        out = self.capture()
        self.assertEqual(out.days_without_receipt, 3)
        self.assertEqual(out.exit_code, EXIT_ARCHIVE_STALE)
        self.assertEqual(out.status, "archive-pending")

    def test_two_days_without_receipt_is_only_a_warning(self):
        p = self.root / "captures/2026/11/06"
        p.mkdir(parents=True)
        (p / "MANIFEST.json").write_text(json.dumps({"runs": [{
            "run_id": "x", "files": [], "internet_archive": {"ok": False, "items": [
                {"name": "dashboard.html", "status": "pending", "url": "x",
                 "our_fetched_utc": "2026-11-06T06:23:00Z", "our_sha256": "0"}]}}]}))
        self.ia.behaviour = "busy"
        self.assertEqual(self.capture().exit_code, EXIT_OK)

    def test_capture_failure_still_fails(self):
        self.site.routes["/2026/cvd/data/ledger.json"] = (404, b"", {})
        self.assertEqual(self.capture().exit_code, EXIT_FAILED)


class ArchiveAuthenticated(CaptureCase):
    access_key = "AKEY-should-never-appear"
    secret_key = "SKEY-should-never-appear"

    # 4: authenticated SPN when keys exist, and keys never written anywhere
    def test_authenticated_mode_and_keys_never_written(self):
        out = self.capture()
        self.assertEqual(out.status, "ok")
        ia = ia_record(self.root)
        self.assertEqual(ia["mode"], "authenticated")
        self.assertTrue(all(i["attempts"][0].get("job_id") for i in ia["items"]))
        self.assertTrue(self.ia.auth_seen)
        self.assertTrue(all(a == f"LOW {self.access_key}:{self.secret_key}" for a in self.ia.auth_seen))
        posts = [r for r in self.ia.requests if r.method == "POST"]
        self.assertEqual(len(posts), 3)
        # Only Save Page Now requests carry the key; never the other hosts.
        for site in (self.site, self.policy):
            self.assertFalse(any("Authorization" in r.headers for r in site.requests))
        for f in (self.root / "captures").rglob("*"):
            if f.is_file():
                text = f.read_bytes()
                self.assertNotIn(b"AKEY", text, f)
                self.assertNotIn(b"SKEY", text, f)
        self.assertNotIn("AKEY", repr(self.client(None)))

    def test_cli_reads_keys_from_environment_and_never_prints_them(self):
        from verifier import __main__ as cli
        captured = {}

        def fake_run(root, **kw):
            captured["mode"] = kw["client"].mode
            from verifier.runner import Outcome
            return Outcome("ok", 0, ["done"], ["a warning"])
        buf = io.StringIO()
        env = {"IA_ACCESS_KEY": "AKEY-x", "IA_SECRET_KEY": "SKEY-y", "GITHUB_ACTIONS": "true"}
        with mock.patch.dict(os.environ, env), mock.patch.object(cli, "run", fake_run), \
                redirect_stdout(buf):
            cli.main(["capture", "--root", str(self.root)])
        self.assertEqual(captured["mode"], "authenticated")
        self.assertNotIn("AKEY", buf.getvalue())
        self.assertNotIn("SKEY", buf.getvalue())
        self.assertIn("::warning title=Internet Archive::a warning", buf.getvalue())
        with mock.patch.dict(os.environ, {"IA_ACCESS_KEY": "", "IA_SECRET_KEY": ""}), \
                mock.patch.object(cli, "run", fake_run), redirect_stdout(io.StringIO()):
            cli.main(["capture", "--root", str(self.root)])
        self.assertEqual(captured["mode"], "anonymous")


class WorkflowFiles(unittest.TestCase):
    # 8: the pinned checkout's comment names v7.0.1 in both workflows
    def test_checkout_pin_comment(self):
        for wf in ("capture.yml", "tests.yml"):
            text = (ROOT / ".github/workflows" / wf).read_text()
            self.assertIn("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1\n", text)
            self.assertNotIn("v6.1.0", text)

    def test_secrets_only_passed_as_env(self):
        text = (ROOT / ".github/workflows/capture.yml").read_text()
        self.assertIn("IA_ACCESS_KEY: ${{ secrets.IA_ACCESS_KEY }}", text)
        self.assertIn("IA_SECRET_KEY: ${{ secrets.IA_SECRET_KEY }}", text)
        self.assertEqual(text.count("secrets.IA_"), 2)


if __name__ == "__main__":
    unittest.main()


class CredentialRedirects(CaptureCase):
    """The Archive keys travel only to the Archive's own hosts, even when a
    server redirects somewhere else."""

    access_key = "AKEY-redirect-test"
    secret_key = "SKEY-redirect-test"

    def setUp(self):
        super().setUp()
        self.evil = FakeSite({"*": (200, b'{"status": "pending"}', {})})
        self.evil.routes = {"/*": (200, b'{"status": "pending"}', {})}

    def tearDown(self):
        self.evil.close()
        super().tearDown()

    def assert_no_keys_reached(self, site):
        self.assertTrue(site.requests, "the redirect was not followed")
        for r in site.requests:
            for k, v in r.headers.items():
                self.assertNotEqual(k.lower(), "authorization")
                self.assertNotIn("AKEY", v)
                self.assertNotIn("SKEY", v)

    def test_redirect_from_save_address_to_other_host_drops_keys(self):
        self.ia.routes["/save"] = (302, b"", {"Location": self.evil.url + "/collect"})
        fetcher = self.fetcher()
        client = self.client(fetcher)
        res = client.save(self.base)
        self.assertEqual(res["outcome"], "error")  # no job id from the other host
        posts = [r for r in self.ia.requests if r.method == "POST"]
        self.assertEqual([r.headers.get("Authorization") for r in posts],
                         [f"LOW {self.access_key}:{self.secret_key}"])  # the Archive got the keys
        self.assert_no_keys_reached(self.evil)  # the other host did not
        self.assertEqual(fetcher.redirects.dropped, [self.evil.url])

    def test_redirect_from_status_address_to_other_host_drops_keys(self):
        self.ia.routes["/save/status/*"] = (302, b"", {"Location": self.evil.url + "/status"})
        fetcher = self.fetcher()
        client = self.client(fetcher, poll_timeout=5)
        res = client.save(self.base)
        self.assertEqual(res["outcome"], "ambiguous")  # the other host only says "pending"
        self.assert_no_keys_reached(self.evil)
        self.assertIn(self.evil.url, fetcher.redirects.dropped)
        # The save request itself (to the Archive) did carry the keys.
        self.assertEqual(self.ia.auth_seen[0], f"LOW {self.access_key}:{self.secret_key}")

    def test_full_capture_with_redirecting_archive_never_leaks(self):
        self.ia.routes["/save/status/*"] = (302, b"", {"Location": self.evil.url + "/status"})
        out = self.capture(poll_timeout=5)
        self.assertEqual(out.exit_code, EXIT_OK)
        self.assert_no_keys_reached(self.evil)
        for f in (self.root / "captures").rglob("*"):
            if f.is_file():
                self.assertNotIn(b"KEY-redirect-test", f.read_bytes(), f)

    def test_redirect_within_the_archive_keeps_keys(self):
        self.ia.routes["/save/status/*"] = (
            302, b"", {"Location": self.ia.url + "/internal/status/x"})
        self.ia.routes["/internal/status/*"] = lambda req: (
            self.ia.auth_seen.append(req.headers.get("Authorization", "")) or
            (200, b'{"status": "success", "timestamp": "20261109000000"}', {}))
        res = self.client(self.fetcher()).save(self.base)
        self.assertEqual(res["outcome"], "snapshot")
        self.assertTrue(all(a.startswith("LOW ") for a in self.ia.auth_seen))

    def test_keys_never_sent_to_a_host_that_is_not_allowed(self):
        from verifier.net import CaptureError, Fetcher
        f = Fetcher(min_interval=0)  # production allow-list: web.archive.org, archive.org
        with self.assertRaises(CaptureError):
            f.get(self.evil.url + "/x", headers={"Authorization": "LOW a:b"})
        self.assertEqual(self.evil.paths(), ["/robots.txt"])  # only robots.txt, no keys


class RedirectHandlerUnit(unittest.TestCase):
    def redirect(self, src, dst, allowed=frozenset({"https://web.archive.org", "https://archive.org"})):
        import email.message
        import urllib.request
        from verifier.net import CredentialSafeRedirectHandler
        h = CredentialSafeRedirectHandler(allowed)
        req = urllib.request.Request(src, headers={"Authorization": "LOW a:b"})
        return h.redirect_request(req, None, 302, "Found", email.message.Message(), dst)

    def test_rules(self):
        keep = [("https://web.archive.org/save", "https://web.archive.org/save/status/1"),
                ("https://web.archive.org/save", "https://archive.org/x")]
        drop = [("https://web.archive.org/save", "https://evil.example/x"),
                ("https://web.archive.org/save", "http://web.archive.org/x"),  # https -> http
                ("https://web.archive.org/save", "https://web.archive.org:8443/x"),  # other port
                ("https://web.archive.org/save", "https://web.archive.org.evil.example/x"),
                ("https://web.archive.org/save", "https://user@evil.example/x")]
        for src, dst in keep:
            with self.subTest(dst=dst):
                self.assertTrue(self.redirect(src, dst).has_header("Authorization"))
        for src, dst in drop:
            with self.subTest(dst=dst):
                self.assertFalse(self.redirect(src, dst).has_header("Authorization"))
