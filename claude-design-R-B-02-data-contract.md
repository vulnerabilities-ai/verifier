# Claude Design Handoff R-B, 02 data contract

The sample files in file 03 follow this contract. The pipeline will write real files with the same names and fields. If you need a field that is not here, tell chat before building around it.

## General rules

- Every file comes in two forms with the same content: JSON for the pages, CSV for downloads. File names: snapshots, commitments, verification, gaps, events and summary. The summary file is JSON only.
- JSON files share one shape: schema_version, generated_utc, source, sample_data (true in the sample files only), and rows (a list). The summary file has one row.
- Dates are ISO (2026-10-02). Times are UTC with a Z (2026-10-30T19:15:25Z).
- A field with no value is null in JSON and empty in CSV. Lists (such as CVE IDs) are JSON arrays, and are JSON text inside a CSV cell.
- Never show a null as "0" or "none". Show a dash, or hide the element, as the page rules say.
- Counts shown on pages must come from these files, so the static HTML and the data always agree.

## snapshots (one row per capture of Anthropic's dashboard)

| Field | Meaning |
| --- | --- |
| capture_utc | When we captured the dashboard |
| source_sha256 | SHA-256 of the captured dashboard page |
| as_of_utc, revision | The "last updated" time and revision number Anthropic shows |
| candidates | Findings its models flagged before triage |
| reviewed_by_firms, confirmed_valid, true_positive_pct | Triage figures as Anthropic reports them |
| reported_after_triage, reported_without_review, reported_total | Reported to maintainers, split by whether a firm reviewed them first |
| acknowledged | Acknowledged by a maintainer |
| patched_lab_count | Patched, by Anthropic's count |
| advisories, cves, ghsas | Identifiers assigned, as Anthropic counts them |
| projects_reported | Projects with reported findings |
| ledger_entries, revealed_entries | Commitments in its ledger, and how many are in the revealed tier |
| severity_agreement_n, severity_exact_agreement_pct, severity_within_one_band_pct | Anthropic's comparison of Claude's severity with the external firms' |
| anthropic_fix_rate_pct, anthropic_revealed_count | The "fix rate" Anthropic lists in its data file (fixed findings as a share of revealed findings) and the revealed count that rate is based on. They let the Ledger's "Reading the numbers" note trace to our data |
| label | Always Lab-reported |
| note | Free text, for example "First capture" |

The sample has one row. Anthropic keeps two earlier snapshots (2026-05-22 and 2026-08-26), and the pipeline will add them when it backfills.

## commitments (one row per hash commitment)

| Field | Meaning |
| --- | --- |
| hash, hash_short | The SHA-3-512 commitment hash, and its first 12 characters |
| committed_at | The commitment date, from Anthropic's records |
| first_seen_by_us, first_seen_basis | Our earliest capture containing the hash, and how to read it. In the sample, every row is the first capture, because our archive began then |
| tier | How far the finding has progressed: discovered, sent, acknowledged_by_maintainer or revealed |
| status | Anthropic's status: disclosed, fixed, withdrawn, merged or null |
| withdrawn, withdrawn_reason, merged_into | Withdrawal flag and reason (mistake, duplicate, false_positive, out_of_scope, rejected_not_sec), and the finding a merged commitment was folded into |
| claude_severity | Claude's own severity rating at the time |
| revealed | True once the disclosure window has closed and details are public |
| ant_id, project, bug_class, cve_ids, ghsa_ids | Present only when revealed. Null or empty otherwise |
| fixed_in_response | Anthropic's flag that the finding was fixed (revealed rows only) |
| patched_at, revealed_at | Dates from Anthropic's ledger (revealed rows only) |
| card_url | The finding card on Anthropic's dashboard (revealed rows only) |
| hash_check | match, mismatch, not_checked (revealed, not yet checked) or not_applicable (not revealed) |
| fix_merged | yes, no, not_checked or not_applicable |

6,597 rows in the sample. Rows are sorted newest commitment first. Project, bug class and IDs are never shown for rows that are not revealed.

## verification (one row per revealed finding)

| Field | Meaning |
| --- | --- |
| ant_id, hash, project, bug_class | Identity of the finding |
| hash_check, hash_checked_at | Result of recomputing the hash, and when |
| cve_ids, ghsa_ids, ids_exist | Identifiers, and whether we confirmed the records exist (verified or not_checked) |
| advisory_published | Date the public advisory was published |
| fix_merged, fix_merged_at, fix_url | Whether the fix merged into the project's main branch, when, and a link |
| report_date, patch_released_date, reveal_date, discovered_or_logged_date | Dates from Anthropic's finding card |
| days_report_to_patch, days_patch_to_reveal, days_report_to_reveal, days_report_to_merge | Differences between those dates |
| severity_claude, severity_firm, severity_maintainer, severity_github, severity_nvd | Each source's own rating, never merged into one |
| checked, method | Whether the row has been fully checked, and how |

237 rows in the sample. Only one is fully checked (a manual check on 2026-10-30), so the other 236 show not_checked and nulls. That is the state the pages must handle: "1 of 237".

## gaps (one row per capture)

| Field | Meaning |
| --- | --- |
| patched_claimed, patched_itemized | Anthropic's patched figure, and findings its ledger lists as fixed |
| cves_claimed, cves_itemized | CVE records claimed, and unique CVE IDs on ledger entries |
| ghsas_claimed, ghsas_itemized | Same for GitHub Security Advisories |
| reported_claimed, revealed_itemized | Reported to maintainers, and entries in the revealed tier |
| reported_flagged_in_ledger, revealed_payload_count, withdrawn_flag, withdrawn_status | Counts as Anthropic's own files record them. They can differ slightly from the headline or from each other, and we publish them as found without reconciling them |
| label | Independently verified (our count from Anthropic's published files) |

## events (one row per change between captures)

Fields: capture_utc, event_type (new_commitment, revealed, withdrawn, merged, status_change, headline_change), hash_or_ant_id, old_value, new_value. The sample file is empty because it is the first capture. Pages do not mention events until the file has rows.

## summary (one row, used for tiles and counts)

Fields: capture_utc, as_of_utc, commitments_total, by_tier, revealed, projects_with_revealed_findings, withdrawn, withdrawal_reasons, merged, earliest_commitment, latest_commitment, checked_n, checked_of, hash_matches, hash_mismatches, fixed_itemized, itemized_share_of_reported_pct, archive_began.

## What the real files will change

- More rows in snapshots, and events rows after the second capture.
- first_seen_by_us will differ by commitment, and commitments first captured later show their true first-seen dates.
- Many more verification rows will be fully checked, which makes the intervals section appear (at 10 or more checked rows) and fills the check columns.
- No field names or meanings change.

## Field names at cut-over (approved November 5, 2026)

Published columns become program-neutral when the real pipeline data replaces the sample data, in the cut-over handoff. Until then the pages read the names above. Anthropic's own field names stay as they are in raw captures, cards and preimages, because the committed bytes must never change. Only the published columns are renamed.

| Today | At cut-over |
| --- | --- |
| ant_id | finding_id |
| hash_or_ant_id (events) | hash_or_finding_id |
| claude_severity | model_severity |
| severity_claude (verification) | severity_model |
| anthropic_fix_rate_pct (snapshots) | program_fix_rate_pct |
| anthropic_revealed_count (snapshots) | program_revealed_count |

The finding IDs themselves (ANT-2026-...) are unchanged, and the program column says whose scheme they belong to. Every published file except programs carries the program column (R-E file 02).
