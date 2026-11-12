# Data contract additions, phase 3

These additions apply on top of R-B (file 02), R-E (file 02) and `docs/data-contract-additions-phase2.md`. Where they differ, this file wins. The general rules are unchanged:
- every file comes in two forms, CSV and JSON, in the contract shape (summary is JSON only);
- empty values are `null` in JSON and empty in CSV, and are never shown as 0 or "none";
- lists are JSON arrays (JSON text in CSV);
- column names are program-neutral, and the program's own field names appear only as `source_field` in `data/schema/`.

All files below are real, built by the pipeline. They change only through a reviewed pull request.

## 1. A new hash-check state: `preimage_withheld`

`hash_check` (in `commitments` and `verification`) can now be:

| Value | Meaning | Page guidance |
| --- | --- | --- |
| `match` | The preimage hashes to the ledger hash. | "Commitment matches". |
| `mismatch` | It does not. Recorded as a fact. | Neutral wording. Never "error" or "failure". |
| `preimage_withheld` (new) | The program's own finding card says the preimage is withheld. `withheld_statement` holds the card's sentence, verbatim. | Show the quote, attributed: "The program's finding card states: '...'". Never call it a mismatch or an error. |
| `unavailable` | The card or its preimage could not be fetched or read. The reason is in the card's `verification.json` and the review. | "Could not be checked". |
| `not_checked` | No card checked yet. | A dash. |
| `not_applicable` | The commitment is not revealed (commitments only). | Hide. |

Today: 232 `match`, 5 `preimage_withheld`, 0 others.

## 2. verification (one row per revealed finding)

This file has the R-B columns, with neutral names (`finding_id`, `severity_model`). Additions:

| Field | Meaning | Example |
| --- | --- | --- |
| `withheld_statement` | Only for `preimage_withheld`: the card's sentence, verbatim. It is a quotation of the program. | "The preimage for this commitment is withheld: ..." |
| `ids_exist` | `verified`, `not_found` (in neither the GitHub Advisory Database nor NVD, both read), `not_applicable` (no IDs), `rate_limited`, `github_refused_token`, `lookup_unreadable` or `not_checked`. (R-B had only `verified` and `not_checked`.) | `verified` |
| `ids_exist_detail` | Per ID and source: `exists`, `not_found`, or the lookup status. | `{"CVE-2026-12340": {"github": "exists", "nvd": "exists"}}` |
| `nvd_published` | Date NVD published the record. | `2026-06-25` |
| `fix_merged` | `yes`, `no`, `not_checked` (not on GitHub, or not looked up yet), `not_applicable`, `rate_limited`, `github_refused_token` or `lookup_unreadable`. (R-B had `yes`, `no`, `not_checked` and `not_applicable`.) | `yes` |
| `fix_merge_base` | The branch the fix's pull request was merged into. | `master` |
| `cvss_github_v31_score`, `cvss_github_v40_score` | The GitHub advisory's CVSS 3.1 and 4.0 scores. **Empty when GitHub has none, never 0.0.** | `7.5`, `6.3` |
| `cvss_github_entries` | Every CVSS entry in the GitHub advisory with a vector string (field, version, score, vector). | |
| `cvss_nvd_primary_v31_score`, `severity_nvd_primary_v31` | NIST's own CVSS 3.1 score and severity in the NVD record (type Primary, source `nvd@nist.gov`). | `7.5`, `HIGH` |
| `cvss_nvd_primary_v40_score`, `severity_nvd_primary_v40` | NIST's own CVSS 4.0 score and severity. | (empty for wolfSSL) |
| `cvss_nvd_cna_v31_score`, `severity_nvd_cna_v31`, `cvss_nvd_cna_v31_source` | The reporting authority's CVSS 3.1 score, severity and identifier as shown in the NVD record (type Secondary). Filled only when exactly one such entry exists; if several, empty (all are in `cvss_nvd_entries`). | `3.1`, `LOW`, `cve@gitlab.com` (Wireshark) |
| `cvss_nvd_cna_v40_score`, `severity_nvd_cna_v40`, `cvss_nvd_cna_v40_source` | The same for CVSS 4.0. | `6.3`, `MEDIUM`, `facts@wolfssl.com` (wolfSSL) |
| `cvss_nvd_entries` | Every CVSS entry in the NVD record, any version (including 3.0 or 2.0 if present), each with score, severity, source and type. | |
| `cwe_github`, `cwe_nvd` | CWE IDs from each source (lists). | `["CWE-125"]` |
| `advisory_review_status` | GitHub's `reviewed` or `unreviewed`. | `unreviewed` |
| `advisory_packages` | Packages the GitHub advisory names, as `ecosystem:name`. | |
| `lookup_status` | `ok` (every lookup read), `no_identifiers` (the finding has no CVE or GHSA ID, so there was nothing to look up; not the same as `ok`), `rate_limited` (resumes next run), `github_refused_token` (GitHub answered HTTP 403 "Resource not accessible by integration" for the built-in token; not a rate limit; the exact message is in `notes`), `lookup_unreadable` (reason in `notes`), `network_error` or `not_checked`. | `ok` |
| `label_hash_check`, `label_ids_exist`, `label_fix_merged`, `label_dates`, `label_intervals`, `label_severity` | The verification label for each metric, from METHODOLOGY. | `Independently verified` |
| `notes` | Plain notes: differences between the ledger and public records (recorded, not judged), lookup reasons, card notes. | |

**Notes on the existing columns:**
- **`severity_github`** is the API's value. GitHub's website shows `medium` as "Moderate", so the page may show it that way, attributed to GitHub.
- **Severities from different sources are never merged into one.**
- **`days_report_to_patch`, `days_patch_to_reveal`, `days_report_to_reveal` and `days_report_to_merge`** are descriptive. **Never label a row "overdue", "late" or "in violation"**, and never colour a row by them. The comparison with the policy references is published only as counts, in `summary.interval_comparisons`.
- **`checked`** means "fully checked". It is `yes` only when all three hold:
  - the hash check is conclusive (`match`, `mismatch` or `preimage_withheld`);
  - the identifiers are confirmed in public records, or there are none (`ids_exist` is `verified` or `not_applicable`);
  - the fix's merge status was determined (`fix_merged` is `yes` or `no`).

  A finding whose fix was not checked is never fully checked. This drives "N of 237 fully checked", which is 0 of 237 until the first real lookups.

### CVSS columns: old names and new names

The first version of this file had one CVSS score per source. It is replaced by one column per CVSS version, because a single column hid the other version: wolfSSL has both 4.0 (6.3, medium) and 3.1 (7.5; NVD says HIGH).

| Old column (removed) | New columns |
| --- | --- |
| `cvss_github_score` + `cvss_github_version` | `cvss_github_v31_score`, `cvss_github_v40_score` (the version is in the name), plus `cvss_github_entries` |
| `cvss_nvd_score` + `cvss_nvd_version` | NIST's own: `cvss_nvd_primary_v31_score`, `cvss_nvd_primary_v40_score`. Reporting authority's: `cvss_nvd_cna_v31_score`, `cvss_nvd_cna_v40_score`, with `cvss_nvd_cna_v31_source` and `cvss_nvd_cna_v40_source`. Plus `cvss_nvd_entries` |
| `severity_nvd` | `severity_nvd_primary_v31`, `severity_nvd_primary_v40`, `severity_nvd_cna_v31`, `severity_nvd_cna_v40` |
| `cvss_nvd_v31_score`, `cvss_nvd_v40_score`, `severity_nvd_v31`, `severity_nvd_v40`, `cvss_nvd_v31_source`, `cvss_nvd_v40_source` (only in the first draft of this change, never merged) | replaced by the primary and cna columns above, so that no entry is chosen over another |
| `severity_github` | unchanged: GitHub's own stated severity |
| severity file `source` = `nvd` | `nvd_primary_v31`, `nvd_primary_v40`, `nvd_cna_v31`, `nvd_cna_v40` |

**Page guidance:**
- Show each version and source separately. Never pick one score as "the" score, and never average.
- An empty value means the source has no score for that version. Show a dash, never 0.0.
- Label NVD scores by who gave them: "NIST (NVD)" for the primary columns, and the reporting authority named in the `_source` column for the cna columns. Show them side by side, never as one score.

## 3. severity (new file)

There is one row per month of reveal, source and severity: the R7 count matrix.

| Field | Meaning | Example |
| --- | --- | --- |
| `program` | As everywhere. | `anthropic-cvd` |
| `month` | Month of the card's reveal date. | `2026-08` |
| `source` | `model`, `firm`, `maintainer`, `github` (GitHub's stated severity), `nvd_primary_v31` or `nvd_primary_v40` (NIST's own CVSS entry in NVD), `nvd_cna_v31` or `nvd_cna_v40` (the reporting authority's entry in NVD). | `maintainer` |
| `severity` | That source's own rating, lower-cased. `not_available` when the source has none. | `low` |
| `count` | Revealed findings. | `12` |

**Page guidance:** show the sources side by side, and never add them together.

## 4. summary (JSON only, one row)

This file has the R-B fields. Additions and clarifications:

| Field | Meaning | Today |
| --- | --- | --- |
| `revision` | The program's revision. | `40` |
| `revealed` | Ledger entries in the revealed tier (our count). | `237` |
| `program_revealed_count` | The revealed count in the program's own data file. **Both are shown as found; neither is "correct".** | `235` |
| `withdrawn`, `withdrawal_reasons` | Aliases of the by-status view, as the contract's names. | `419` |
| `withdrawn_by_flag`, `withdrawal_reasons_by_flag` | The flag view. | `415` |
| `withdrawn_by_status`, `withdrawal_reasons_by_status` | The status view (`none` when an entry has no reason). | `419` |
| `merged`, `merged_with_target` | Status merged, and how many name a target. | `1654`, `2` |
| `hash_preimage_withheld`, `hash_unavailable`, `hash_not_checked` | Counts of those states. | `5`, `0`, `0` |
| `reported_total`, `patched_lab_count`, `fixed_itemized` | The numerators and denominators of the shares below. | `5087`, `629`, `217` |
| `revealed_share_of_reported_pct` | revealed ÷ reported_total × 100. This is "findings with a record we can check". | `4.66` |
| `itemized_share_of_reported_pct` | **An exact alias of `revealed_share_of_reported_pct`** (the contract's name). | `4.66` |
| `fixed_itemized_share_of_patched_claimed_pct` | fixed_itemized ÷ patched_lab_count × 100. | `34.5` |
| `fixed_itemized_share_of_reported_pct` | fixed_itemized ÷ reported_total × 100. | `4.27` |
| `checked_n`, `checked_of` | Fully checked findings, and all revealed findings. Fully checked means: hash check conclusive (match, mismatch or preimage_withheld), identifiers confirmed or none, and fix_merged `yes` or `no`. | `0`, `237` |
| `cvss_scores_present` | For each CVSS column, how many findings have a score. Absent scores are empty, never 0.0. | |
| `fix_merged`, `ids_exist`, `lookups` | Counts of verification rows per value. `lookups` counts `no_identifiers` separately from `ok`. | |
| `interval_comparisons` | For each interval, the reference in days, the rows with both dates, and counts `within` (at or under) and `above` the reference. | |
| `policy_source` | Our dated copy of the policy page the references come from. | |

**More on `interval_comparisons`:**
- **The references:** 90 for report to patch, 45 for patch to reveal (both from the policy), and 135 for report to reveal (from the program's April post).
- **Descriptive only.** Use "within" and "above". Never "overdue", "late" or "violation".

## 5. programs (CSV + JSON; R-E file 02)

- **Columns:** as in R-E: `program`, `name`, `operator`, `status`, `per_finding_record`, `publishes_summary`, `as_of`.
- **Today:** Jon's seven rows.
- **How it is kept:** by hand in `data/programs-manual.csv`. The build fills in only anthropic-cvd's `status` ("Dashboard last updated YYYY-MM-DD (revision N)") and `as_of` from the latest snapshot, so they never go stale.
- **Not published:** `programs-manual.csv` is the hand-kept source. Pages read `programs.json`.

## 6. Where the website gets the files

- **The citation address.** GitHub Pages mirrors `data/` from main after each reviewed merge. The address is `https://vulnerabilities-ai.github.io/verifier/data/...`.
- **The website's own copy.** **The website must not fetch from Pages while it runs.** Each reviewed website export bundles its own copy from `site-data.zip`, which holds:
  - the published files under `data/` (the website's data-files folder);
  - `MANIFEST.sha256.json`, with each file's SHA-256 and the source commit.
- **Where to find the zip:** on the Pages site (`site-data.zip`), and attached to each Publish run.
- **NVD notice.** Pages showing NVD-derived values must carry: *This product uses data from the NVD API but is not endorsed or certified by the NVD.*
