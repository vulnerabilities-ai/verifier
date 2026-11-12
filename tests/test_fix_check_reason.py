"""fix_check_reason: why a fix was not checked, read only from the card's own links.

The card links below are hand-written for the unit tests (each test says which case it is);
the wolfSSL and Wireshark cards are real captured copies in tests/fixtures/."""

import unittest
from pathlib import Path

from test_phase3 import Phase3Case

from verifier.build import build
from verifier.build.phase3 import FIX_CHECK_REASONS, fix_check_reason, link_type, unchecked_link_note
from verifier.records import fix_targets
from verifier.r2 import outside_links, parse_card
from verifier.report import weekly_report
from verifier.wording import find

ROOT = Path(__file__).resolve().parents[1]
REAL = ROOT / "tests/fixtures/fix-link-cards"  # real captured cards (see its README)
WITHHELD = ROOT / "tests/fixtures/withheld-cards"


def real(fid: str):
    f = parse_card(((REAL if (REAL / f"{fid}.html").exists() else WITHHELD) / f"{fid}.html").read_bytes())
    return {"card_facts": f}, {"fix_links": f["links"]["fix"], "advisory_links": f["links"]["advisory"]}


def card(links, fix=(), advisory=()):
    """A stored card reading with these outside links, and these fix / advisory section links."""
    return ({"card_facts": {"outside_links": sorted(links), "links": {"fix": list(fix), "advisory": list(advisory)}}},
            {"fix_links": list(fix), "advisory_links": list(advisory)})


def code(v, inp, fix_merged="not_checked"):
    r = fix_check_reason(v, inp, fix_merged)
    return r[0] if r else None


class Reasons(unittest.TestCase):
    def test_each_reason(self):
        self.assertEqual(code(*card([])), "no_outside_links")
        self.assertEqual(code(*card(["https://nvd.nist.gov/vuln/detail/CVE-2026-1"])), "only_nvd_links")
        self.assertEqual(code(*card(["https://nvd.nist.gov/vuln/detail/CVE-2026-1",
                                     "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"])),
                         "github_not_commit_or_pull")
        self.assertEqual(code(*card(["https://github.com/owner/repo"])), "github_not_commit_or_pull")
        self.assertEqual(code(*card(["https://gitlab.com/o/r/-/commit/abc"], fix=["https://gitlab.com/o/r/-/commit/abc"])),
                         "fix_not_on_github")
        self.assertEqual(code(*card(["https://example.org/news"])), "other_links")
        # a GitHub release tag or repository advisory in the fix section is on GitHub, but not a commit or pull
        tag = "https://github.com/libjxl/libjxl/releases/tag/v0.12.0"
        self.assertEqual(code(*card([tag], fix=[tag])), "github_not_commit_or_pull")
        nvd = "https://nvd.nist.gov/vuln/detail/CVE-2026-7474"
        self.assertEqual(code(*card([nvd], fix=[nvd])), "only_nvd_links")
        gh = "https://github.com/o/r/commit/0123456789abcdef0123456789abcdef01234567"
        self.assertEqual(code(*card([gh], fix=[gh])), "not_looked_up_yet")
        self.assertEqual(code({"card_facts": None}, {"fix_links": [], "advisory_links": []}), "no_card")
        self.assertEqual(code({"card_facts": {"links": {}}}, {"fix_links": [], "advisory_links": []}),
                         "links_not_recorded")

    def test_only_for_not_checked(self):
        for value in ("yes", "no", "not_applicable", "rate_limited", "github_refused_token", "lookup_unreadable"):
            self.assertIsNone(fix_check_reason(*card([]), value))

    def test_never_infers_a_fix_from_advisories_or_nvd(self):
        # NVD or advisory pages that themselves reference a commit are not read as the fix
        v, inp = card(["https://nvd.nist.gov/vuln/detail/CVE-2026-1", "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"],
                      advisory=["https://github.com/advisories/GHSA-aaaa-bbbb-cccc"])
        self.assertEqual(code(v, inp), "github_not_commit_or_pull")

    def test_plain_texts(self):
        self.assertEqual(FIX_CHECK_REASONS["github_not_commit_or_pull"],
                         "the card's links are not GitHub commits or pull requests (it links GitHub, but not to a "
                         "commit or pull request)")
        self.assertTrue(FIX_CHECK_REASONS["no_outside_links"].startswith(
            "the card links no fix commit or pull request"))
        self.assertEqual(find(" ".join(FIX_CHECK_REASONS.values())), [])  # wording guard

    def test_outside_links_leave_the_programs_site(self):
        self.assertEqual(outside_links(["https://red.anthropic.com/x", "https://www.anthropic.com/y",
                                        "https://anthropic.com/z", "https://nvd.nist.gov/a",
                                        "https://notanthropic.com/b", "https://nvd.nist.gov/a"]),
                         ["https://notanthropic.com/b", "https://nvd.nist.gov/a"])

    def test_real_cards(self):
        for name in ("wolfssl-card", "wireshark-card"):
            facts = parse_card((ROOT / "tests/fixtures" / name / "card.html").read_bytes())
            self.assertIsInstance(facts["outside_links"], list)
            for u in facts["outside_links"]:
                self.assertNotIn("anthropic.com/", u.split("?")[0].split("#")[0][:40])
            for u in facts["links"]["fix"]:
                self.assertIn(u, facts["outside_links"])


class RealCards(unittest.TestCase):
    """Frozen copies of real cards (tests/fixtures/fix-link-cards/, withheld-cards/)."""

    ADVISORY_COMMIT = {
        "ANT-2026-19SGCVZZ": "https://github.com/alembic/alembic/commit/3f1745ae657b1ce79d39dc7a4bbc03441d2ebcd1",
        "ANT-2026-8DRZW7VM": "https://github.com/Cisco-Talos/clamav/commit/a0b1531c6368347a79c15fb69d508171c55cc8cf",
        "ANT-2026-B4Z27MGE": "https://github.com/gpac/gpac/commit/5db36afe0f20a02ea2344d42521e687820096cf4",
        "ANT-2026-D7FC4YDQ": "https://github.com/alanxz/rabbitmq-c/commit/4777d0b5c58cb02966a04a85832436bd66ed5d1f",
        "ANT-2026-VVPEMVDE": "https://github.com/Cisco-Talos/clamav/commit/ca39e3843b47f298c3315996df30cf937c20c4ee",
        "ANT-2026-Z477W54M": "https://github.com/Cisco-Talos/clamav/commit/9532b0687a8d6b66bb32c1d0b51ff0430750457b",
    }

    def test_advisory_commit_is_its_own_reason_and_never_the_fix(self):
        for fid, commit in self.ADVISORY_COMMIT.items():
            v, inp = real(fid)
            self.assertEqual(inp["fix_links"], [], fid)
            self.assertIn(commit, inp["advisory_links"], fid)
            self.assertEqual(fix_check_reason(v, inp, "not_checked")[1],
                             "the card has no separate fix link; its advisory link is a GitHub commit, which is "
                             "not used as the fix link", fid)
            t = fix_targets(inp["fix_links"], inp["advisory_links"])
            self.assertEqual((t["commit"], t["pull"], t["not_on_github"]), (None, None, []), fid)  # not looked up

    def test_commit_only_in_the_card_text(self):
        # K8YY7WWS has no fix or advisory section; its analysis text links an earlier wolfSSL commit
        v, inp = real("ANT-2026-K8YY7WWS")
        self.assertEqual((inp["fix_links"], inp["advisory_links"]), ([], []))
        self.assertIn("https://github.com/wolfSSL/wolfssl/commit/e5ab7fa7457d82294bafcfb6c103a9e79b4aa213",
                      v["card_facts"]["outside_links"])
        self.assertEqual(code(v, inp), "commit_in_text_only")

    def test_other_real_reasons(self):
        self.assertEqual(code(*real("ANT-2026-1ZNMP148")), "github_not_commit_or_pull")
        self.assertEqual(code(*real("ANT-2026-3CJT2BP4")), "github_not_commit_or_pull")  # release tag
        self.assertEqual(code(*real("ANT-2026-9VJ9JJXQ")), "github_not_commit_or_pull")  # repository advisory
        self.assertEqual(code(*real("ANT-2026-09SNWQBT")), "no_outside_links")
        self.assertEqual(code(*real("ANT-2026-0HC68EK6")), "only_nvd_links")
        self.assertEqual(code(*real("ANT-2026-CN7KX43N")), "only_nvd_links")  # its fix link is an NVD page
        self.assertEqual(code(*real("ANT-2026-5WVCAVEA")), "other_links")
        for fid in ("ANT-2026-1ZNMP148", "ANT-2026-3CJT2BP4", "ANT-2026-9VJ9JJXQ"):
            from verifier.records import GH_COMMIT, GH_PULL
            self.assertFalse(any(GH_COMMIT.match(u) or GH_PULL.match(u)
                                 for u in real(fid)[0]["card_facts"]["outside_links"]), fid)

    def test_unchecked_link_notes_name_the_real_link_type(self):
        expected = {
            "ANT-2026-3CJT2BP4": "The card's advisory link is a GitHub release tag, not a commit or pull request; it "
                                 "was not checked as the fix: https://github.com/libjxl/libjxl/releases/tag/v0.12.0.",
            "ANT-2026-9VJ9JJXQ": "The card's advisory link is a GitHub repository advisory, not a commit or pull "
                                 "request; it was not checked as the fix: "
                                 "https://github.com/junrar/junrar/security/advisories/GHSA-j273-m5qq-6825.",
            "ANT-2026-CN7KX43N": "The card's fix link is an NVD page, not a commit or pull request; it was not "
                                 "checked as the fix: https://nvd.nist.gov/vuln/detail/CVE-2026-7474.",
        }
        for fid, note in expected.items():
            _, inp = real(fid)
            t = fix_targets(inp["fix_links"], inp["advisory_links"])
            self.assertEqual(unchecked_link_note(t["not_on_github"][0], inp["fix_links"]), note)
            self.assertNotIn("not on GitHub", note)
            self.assertEqual(find(note), [])

    def test_link_types(self):
        self.assertEqual(link_type("https://github.com/kjur/jsrsasign/releases/tag/11.1.2"), "GitHub release tag")
        self.assertEqual(link_type("https://github.com/o/r/security/advisories/GHSA-aaaa-bbbb-cccc"),
                         "GitHub repository advisory")
        self.assertEqual(link_type("https://github.com/advisories/GHSA-aaaa-bbbb-cccc"), "GitHub advisory")
        self.assertEqual(link_type("https://nvd.nist.gov/vuln/detail/CVE-2026-1"), "NVD page")
        self.assertEqual(link_type("https://gitlab.com/o/r/-/commit/abc"), "other")
        self.assertIn("a link of another kind", unchecked_link_note("https://gitlab.com/o/r/-/commit/abc",
                                                                     ["https://gitlab.com/o/r/-/commit/abc"]))

    def test_frozen_copies_match_their_manifests(self):
        import hashlib
        readme = (REAL / "README.md").read_text()
        for f in REAL.glob("*.html"):
            self.assertIn(hashlib.sha256(f.read_bytes()).hexdigest(), readme, f.name)


class InPublishedFiles(Phase3Case):
    def test_column_summary_and_report(self):
        r = build(self.root)  # no lookups made here
        ver = r["tables"]["verification"]
        texts = set(FIX_CHECK_REASONS.values())
        n = 0
        for v in ver:
            if v["fix_merged"] == "not_checked":
                n += 1
                self.assertIn(v["fix_check_reason"], texts, v["finding_id"])
            else:
                self.assertIsNone(v["fix_check_reason"], v["finding_id"])
        s = r["summary"]["fix_check_reasons"]
        self.assertEqual(sum(s.values()), n)
        self.assertGreater(n, 0)
        text = weekly_report(self.root, "2026-01-01")
        self.assertIn("- Fixes not checked, by reason (read from the card): ", text)
        for reason, count in s.items():
            self.assertIn(f"{count}: {reason}", text)
        self.assertEqual(find(text), [])

    def test_note_and_link_type_in_published_rows(self):
        from unittest import mock
        from verifier.build import phase3

        def release_tag(self_, *a):
            return {"status": "not_checked", "fix_merged": "not_checked",
                    "reason": "the card links no GitHub commit or pull request as the fix",
                    "address": "https://github.com/libjxl/libjxl/releases/tag/v0.12.0"}
        with mock.patch.object(phase3.RecordReader, "fix_merged", release_tag):
            r = build(self.root)
        rows = r["tables"]["verification"]  # the mocked lookup answers for every finding
        self.assertTrue(rows)
        for v in rows:
            self.assertEqual(v["fix_link_type_not_checked"], "GitHub release tag")
            self.assertIn("is a GitHub release tag, not a commit or pull request; it was not checked as the fix",
                          v["notes"])
            self.assertNotIn("not on GitHub", v["notes"] or "")
        self.assertEqual(r["summary"]["fix_links_not_checked_by_type"], {"GitHub release tag": len(rows)})
        text = weekly_report(self.root, "2026-01-01")
        self.assertIn("by kind (not checked as the fix): GitHub release tag", text)


if __name__ == "__main__":
    unittest.main()
