"""fix_check_reason: why a fix was not checked, read only from the card's own links.

The card links below are hand-written for the unit tests (each test says which case it is);
the wolfSSL and Wireshark cards are real captured copies in tests/fixtures/."""

import unittest
from pathlib import Path

from test_phase3 import Phase3Case

from verifier.build import build
from verifier.build.phase3 import FIX_CHECK_REASONS, fix_check_reason
from verifier.r2 import outside_links, parse_card
from verifier.report import weekly_report
from verifier.wording import find

ROOT = Path(__file__).resolve().parents[1]


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


if __name__ == "__main__":
    unittest.main()
