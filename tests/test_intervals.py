"""Interval comparisons (rule R5): within the reference, above it, and dated before the
earlier-named event, kept apart.

INVENTED TEST DATES: every date in the unit tests below (class Counts and class Labels) is
invented for these tests and comes from no finding card. The class OnTheFrozenArchive uses the
frozen archive (real captured files and real finding cards, see tests/helpers.py)."""

import unittest

from test_phase3 import Phase3Case

from verifier.build import build
from verifier.build.phase3 import DATED_BEFORE_TEXT, INTERVAL_NOTE, days, interval_comparison
from verifier.report import interval_section, weekly_report
from verifier.wording import WordingError, check_text, find

# INVENTED TEST DATES (report, patch), with the signed day count each gives
INVENTED = {
    "negative":       ("2026-05-14", "2026-04-07"),  # patch dated before report: -37
    "zero":           ("2026-03-01", "2026-03-01"),  # 0
    "at_limit_90":    ("2026-01-01", "2026-04-01"),  # exactly 90
    "one_above_90":   ("2026-01-01", "2026-04-02"),  # 91
    "missing_patch":  ("2026-02-01", None),           # one date missing
}


def invented_days(name):
    return days(*INVENTED[name])


class Counts(unittest.TestCase):
    def test_signed_day_counts_are_kept(self):
        self.assertEqual([invented_days(n) for n in INVENTED], [-37, 0, 90, 91, None])

    def test_negative_zero_limit_above_and_missing(self):
        c = interval_comparison([invented_days(n) for n in INVENTED], 90)
        self.assertEqual(c, {"reference_days": 90, "with_dates": 4,
                             "within": 3,  # kept for compatibility: -37, 0 and 90
                             "above": 1, "within_from_zero": 2, "dated_before_earlier_named_event": 1})
        self.assertEqual(c["within_from_zero"] + c["above"] + c["dated_before_earlier_named_event"], c["with_dates"])

    def test_each_case_alone(self):
        def one(name, ref=90):
            return interval_comparison([invented_days(name)], ref)
        self.assertEqual(one("negative")["dated_before_earlier_named_event"], 1)
        self.assertEqual((one("negative")["within_from_zero"], one("negative")["above"]), (0, 0))
        self.assertEqual(one("zero")["within_from_zero"], 1)
        self.assertEqual(one("at_limit_90")["within_from_zero"], 1)  # up to and including the reference
        self.assertEqual(one("one_above_90")["above"], 1)
        self.assertEqual(one("missing_patch"), {"reference_days": 90, "with_dates": 0, "within": 0, "above": 0,
                                                "within_from_zero": 0, "dated_before_earlier_named_event": 0})

    def test_at_the_45_day_limit(self):
        # INVENTED: patch 2026-06-01, reveal 2026-07-16 (exactly 45 days), and one day more
        c = interval_comparison([days("2026-06-01", "2026-07-16"), days("2026-06-01", "2026-07-17")], 45)
        self.assertEqual((c["within_from_zero"], c["above"]), (1, 1))

    def test_no_reference_counts_only_dated_before(self):
        c = interval_comparison([-35, 0, 12, None], None)
        self.assertEqual(c, {"reference_days": None, "with_dates": 3, "dated_before_earlier_named_event": 1})

    def test_sums_always_hold(self):
        import random
        rnd = random.Random(7)
        for _ in range(200):
            vals = [rnd.choice([None, rnd.randint(-120, 200)]) for _ in range(rnd.randint(0, 30))]
            for ref in (45, 90, 135):
                c = interval_comparison(vals, ref)
                self.assertEqual(c["within_from_zero"] + c["above"] + c["dated_before_earlier_named_event"],
                                 c["with_dates"])
                self.assertEqual(c["within"], c["within_from_zero"] + c["dated_before_earlier_named_event"])


def invented_summary():
    """A summary built from INVENTED interval values only."""
    return {"interval_comparisons": {
        "days_report_to_patch": interval_comparison([-37, 0, 90, 91, None], 90),
        "days_patch_to_reveal": interval_comparison([-29, 45, 46], 45),
        "days_report_to_reveal": interval_comparison([0, 135, 136], 135),
        "days_report_to_merge": interval_comparison([-35, 0, 12], None)},
        "policy_source": None}


class Labels(unittest.TestCase):
    def test_report_lines(self):
        text = "\n".join(interval_section(invented_summary()))
        self.assertIn("- report to patch: 4 findings with both dates; 2 within 90 days, 1 above 90 days, "
                      "1 dated before the earlier-named event.", text)
        self.assertIn("- patch to reveal: 3 findings with both dates; 1 within 45 days, 1 above 45 days, "
                      "1 dated before the earlier-named event.", text)
        self.assertIn("- report to fix merge: 3 findings with both dates; 1 dated before the earlier-named event.",
                      text)
        self.assertIn("- Observed intervals, not compliance determinations.", text)
        self.assertEqual((DATED_BEFORE_TEXT, INTERVAL_NOTE), ("dated before the earlier-named event",
                                                              "Observed intervals, not compliance determinations."))

    def test_guard_earlier_named_passes(self):
        text = "\n".join(interval_section(invented_summary()))
        self.assertEqual(find(text, intervals=True), [])
        check_text("3 dated before the earlier-named event.", "test", intervals=True)

    def test_guard_early_and_error_fail_in_the_interval_section(self):
        for bad in ("2 revealed early.", "1 date error.", "The patch is late.", "4 overdue."):
            with self.assertRaises(WordingError, msg=bad):
                check_text("- report to patch: " + bad, "test", intervals=True)

    def test_early_and_error_are_limited_to_the_interval_section(self):
        self.assertEqual(find("an error page was stored"), [])  # elsewhere: not banned
        self.assertEqual(len(find("an error page was stored", intervals=True)), 1)

    def test_no_reason_is_given(self):
        text = "\n".join(interval_section(invented_summary())).lower()
        for word in ("because", "reason", "typo", "mistake", "wrong", "incorrect"):
            self.assertNotIn(word, text)


class OnTheFrozenArchive(Phase3Case):
    """Real captured files and real cards (frozen copies)."""

    def test_summary_fields_and_report(self):
        r = build(self.root)
        ic = r["summary"]["interval_comparisons"]
        for k in ("days_report_to_patch", "days_patch_to_reveal", "days_report_to_reveal"):
            c = ic[k]
            self.assertEqual(c["within_from_zero"] + c["above"] + c["dated_before_earlier_named_event"],
                             c["with_dates"], k)
            self.assertEqual(c["within"], c["within_from_zero"] + c["dated_before_earlier_named_event"], k)
        self.assertIn("dated_before_earlier_named_event", ic["days_report_to_merge"])
        self.assertNotIn("within", ic["days_report_to_merge"])
        # per-finding signed day counts unchanged (wolfSSL: 90, 53, 143)
        w = next(v for v in r["tables"]["verification"] if v["finding_id"] == "ANT-2026-87DJGDRB")
        self.assertEqual((w["days_report_to_patch"], w["days_patch_to_reveal"], w["days_report_to_reveal"]),
                         (90, 53, 143))
        text = weekly_report(self.root, "2026-01-01")
        self.assertIn("dated before the earlier-named event.", text)
        self.assertIn("Observed intervals, not compliance determinations.", text)
        self.assertEqual(find(text), [])

    def test_schema_documents_the_new_fields(self):
        from verifier.build.schema import SUMMARY_FIELDS
        doc = next(d for name, _, d in SUMMARY_FIELDS if name == "interval_comparisons")
        for s in ("within_from_zero", "dated_before_earlier_named_event", "dated before the earlier-named event",
                  "kept for compatibility", "Observed intervals, not compliance determinations"):
            self.assertIn(s, doc)
        self.assertEqual(find(doc, intervals=True), [])


if __name__ == "__main__":
    unittest.main()
