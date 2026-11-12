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
| `ids_exist` | `verified` (every ID has an entry in the GitHub global advisory database, NVD, or the repository's own advisory), `not_found` (in neither the GitHub Advisory Database nor NVD, both read), `not_applicable` (no IDs), `rate_limited`, `github_refused_token`, `no_repository_known`, `lookup_unreadable` or `not_checked`. (R-B had only `verified` and `not_checked`.) | `verified` |
| `ids_exist_detail` | Per ID and source (`github` = the global database, `nvd`, `repository_advisory`): `exists`, `not_found`, `not_in_global_database` (GitHub's global advisory database has no entry for this ID), `no_repository_known`, or the lookup status. | `{"GHSA-85fq-fc5f-7j7g": {"github": "not_in_global_database", "repository_advisory": "exists"}}` |
| `nvd_published` | Date NVD published the record. | `2026-06-25` |
| `fix_merged` | `yes`, `no`, `not_checked` (not on GitHub, or not looked up yet), `not_applicable`, `rate_limited`, `github_refused_token` or `lookup_unreadable`. (R-B had `yes`, `no`, `not_checked` and `not_applicable`.) | `yes` |
| `fix_check_reason` | **New.** Only when `fix_merged` is `not_checked`: why, in plain words, read from the finding card's own links. Empty otherwise. The values are listed in section 8. | `the card's links are not GitHub commits or pull requests (it links GitHub, but not to a commit or pull request)` |
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
| `repo_advisory_repository`, `repo_advisory_published`, `repo_advisory_severity`, `repo_advisory_cve_id`, `repo_advisory_cwes`, `repo_advisory_cvss_v31_score`, `repo_advisory_cvss_v40_score`, `repo_advisory_state`, `repo_advisory_read_with` | For a GHSA ID that GitHub's global advisory database has no entry for: the repository's own security advisory (repository taken from the card's links). **A separate source.** Never merge it with the GitHub global-database columns. CVSS is empty when absent, never 0.0. `read_with` is `token` or `no token`. | `jetty/jetty.project`, `2026-09-16`, `high`, `CVE-2026-19204`, `["CWE-770","CWE-789"]`, (empty), `8.7`, `published`, `token` |
| `lookup_status` | `ok` (every lookup read), `no_identifiers` (the finding has no CVE or GHSA ID, so there was nothing to look up; not the same as `ok`), `rate_limited` (resumes next run), `no_repository_known` (a GHSA ID has no global entry and the card links no repository), `github_refused_token` (GitHub answered HTTP 403 "Resource not accessible by integration" for the built-in token; not a rate limit; the exact message is in `notes`), `lookup_unreadable` (reason in `notes`), `network_error` or `not_checked`. | `ok` |
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
| `ghsa_ids` | GHSA IDs on revealed findings: `total`; per global-database status (`exists`, `not_in_global_database`, ...); and, for those looked up there, per repository-advisory status (`exists`, `not_found`, `no_repository_known`, ...). | |
| `cvss_scores_present` | For each CVSS column, how many findings have a score. Absent scores are empty, never 0.0. | |
| `fix_merged`, `ids_exist`, `lookups` | Counts of verification rows per value. `lookups` counts `no_identifiers` separately from `ok`. | |
| `fix_check_reasons` | **New.** For findings whose `fix_merged` is `not_checked`: how many have each `fix_check_reason` (the plain reason text is the key). | `{"the card links no fix commit or pull request (the card has no outside links)": 28}` |
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

## 7. GHSA IDs with no entry in GitHub's global advisory database

When GitHub refuses the workflow's token for a global advisory, the same request without the token tells whether the database has the ID. A 404 there gives `not_in_global_database`, which pages should show as the plain statement: **"GitHub's global advisory database has no entry for this ID."**

Such an ID can still exist as the repository's own security advisory. It is then confirmed through the `repo_advisory_*` columns, which are a separate source.

**Page guidance:**
- Show the repository advisory under its own heading, for example "Repository advisory (owner/repo)".
- Never fill the GitHub global-database fields from it.
- `no_repository_known` means the card links no GitHub repository, so the repository advisory could not be looked up. Show it as "could not be checked".

## 8. Why a fix was not checked (`fix_check_reason`)

When `fix_merged` is `not_checked`, `fix_check_reason` gives the reason, read only from the links printed on the finding card. "Outside links" means every web link on the card that leaves the program's own site (anthropic.com).

| Reason (exact text) | When |
|---|---|
| the card links no fix commit or pull request (the card has no outside links) | The card has no outside links at all. |
| the card links no fix commit or pull request (its only outside links are NVD records) | Every outside link is an NVD record. |
| the card's links are not GitHub commits or pull requests (it links GitHub, but not to a commit or pull request) | The card links GitHub (for example a release tag, a repository advisory, a global advisory or the repository itself), but no commit or pull request. This applies even when the link is in the card's fix section. |
| the card's fix link is not on GitHub | The card links nothing on GitHub, and its fix section links another host (for example GitLab). These are not looked up. |
| the card's links are not GitHub commits or pull requests | The card has outside links, none on GitHub and not only NVD, and no fix link elsewhere. |
| the card links a GitHub fix, which has not been looked up yet | A GitHub commit or pull request is linked but no lookup has been made yet. |
| no copy of the finding card is available | No card could be fetched. |
| the card's links were not recorded when it was read | The card's stored reading has no list of links (not expected after a rebuild). |

**We never infer a fix commit from a GitHub advisory or an NVD reference.** A reference there is not shown as the fix. That may be added later as a separate, labelled column.

**Page guidance:** show the reason next to "Fix merged: not checked", and show `summary.fix_check_reasons` as a small table of counts.

