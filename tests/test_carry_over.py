"""scripts/carry_over_records.sh, run in a throwaway git repository with a local 'remote'.
All files here are invented for the test."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CarryOver(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        t = Path(self.tmp.name)
        self.remote, self.repo = t / "remote.git", t / "repo"
        subprocess.run(["git", "init", "-q", "--bare", str(self.remote)], check=True)
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.repo)], check=True)
        self.write("records/github/a/MANIFEST.json", '{"attempts": [1]}')
        self.write("captures/x.txt", "x")
        self.commit("main")
        self.git("remote", "add", "origin", str(self.remote))
        self.git("push", "-q", "origin", "main")

    def tearDown(self):
        self.tmp.cleanup()

    def git(self, *a):
        return subprocess.run(["git", *a], cwd=self.repo, check=True, capture_output=True, text=True).stdout

    def write(self, rel, text):
        p = self.repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)

    def commit(self, msg):
        self.git("add", "-A")
        self.git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", msg)

    def review_run(self):
        """A review run: new records on review/weekly, pushed, not merged."""
        self.git("switch", "-q", "-c", "review/weekly")
        self.write("records/github/a/MANIFEST.json", '{"attempts": [1, 2]}')
        self.write("records/github/b/MANIFEST.json", '{"attempts": [1]}')
        self.commit("review")
        self.git("push", "-q", "--force", "origin", "review/weekly")
        self.git("switch", "-q", "main")

    def run_script(self):
        env = {**os.environ, "REVIEW_BRANCH": "review/weekly", "PUSH_REMOTE": "origin"}
        r = subprocess.run(["bash", str(ROOT / "scripts/carry_over_records.sh")], cwd=self.repo, env=env,
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def test_no_review_branch(self):
        self.assertIn("nothing to carry over", self.run_script())
        self.assertEqual(self.git("status", "--porcelain"), "")

    def test_unmerged_records_are_carried_over(self):
        self.review_run()
        # main moved on meanwhile, but only outside records/ (a daily capture)
        self.write("captures/y.txt", "y")
        self.commit("capture")
        out = self.run_script()
        self.assertIn("Carried over 2 record file(s)", out)
        self.assertEqual((self.repo / "records/github/a/MANIFEST.json").read_text(), '{"attempts": [1, 2]}')
        self.assertTrue((self.repo / "records/github/b/MANIFEST.json").exists())
        changed = {l[3:] for l in self.git("status", "--porcelain", "-uall").splitlines()}
        self.assertEqual(changed, {"records/github/a/MANIFEST.json", "records/github/b/MANIFEST.json"})

    def test_not_carried_when_main_records_changed(self):
        self.review_run()
        self.write("records/github/c/MANIFEST.json", '{"attempts": [1]}')
        self.commit("other records on main")
        self.assertIn("not carried over", self.run_script())
        self.assertEqual(self.git("status", "--porcelain"), "")

    def test_merged_branch_is_left_alone(self):
        self.review_run()
        self.git("-c", "user.name=t", "-c", "user.email=t@t", "merge", "-q", "--no-ff", "-m", "merge",
                 "review/weekly")
        self.assertIn("already merged", self.run_script())
        self.assertEqual(self.git("status", "--porcelain"), "")

    def test_only_records_are_taken(self):
        self.git("switch", "-q", "-c", "review/weekly")
        self.write("records/github/b/MANIFEST.json", '{"attempts": [1]}')
        self.write("data/summary.json", "{}")
        self.write("cards/X/card.html", "<p>")
        self.commit("review")
        self.git("push", "-q", "--force", "origin", "review/weekly")
        self.git("switch", "-q", "main")
        self.run_script()
        self.assertFalse((self.repo / "data/summary.json").exists())
        self.assertFalse((self.repo / "cards/X/card.html").exists())
        self.assertTrue((self.repo / "records/github/b/MANIFEST.json").exists())

    def test_workflow_runs_it_before_the_lookups(self):
        wf = (ROOT / ".github/workflows/verify.yml").read_text()
        self.assertLess(wf.index("bash scripts/carry_over_records.sh"), wf.index("python3 -m verifier records"))
        self.assertLess(wf.index("bash scripts/carry_over_records.sh"), wf.index("python3 -m verifier cards"))


if __name__ == "__main__":
    unittest.main()
