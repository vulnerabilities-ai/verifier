# Methodology

Pinned definitions for this repository. They are copied from the build spec (`docs/pipeline-build-spec-v1.md`) and the data contract (`docs/design-handoff/`). If a definition changes, the change is dated here and logged in CORRECTIONS.md.

## What the pipeline never does

- Label a commitment or finding "overdue", "late" or "in violation". It reports intervals against the policy defaults and nothing more.
- State or imply intent, competence or motive.
- Use an Anthropic model to make a determination about Anthropic data. Hashes, counts and lookups run as deterministic code with tests.
- Publish a derived result about a specific finding without it passing through the weekly review pull request.
- Modify or delete a raw capture.

## R1. Capture (built in phase 1)

- **Source.** The base address is `https://red.anthropic.com/2026/cvd/`. Each run captures the dashboard page, `data/payload.json`, `data/ledger.json`, `about/index.html` and `archive/index.html`.
- **Conduct.**
  - The pipeline identifies itself with the User-Agent `vulnerabilities.ai-verifier/1.0 (+https://github.com/vulnerabilities-ai/verifier; verifier@vulnerabilities.ai)`.
  - It waits at least one second between requests to the same host.
  - It reads robots.txt for every host it touches before fetching anything: red.anthropic.com, www.anthropic.com (the monthly policy copy) and web.archive.org (Save Page Now). If any robots.txt disallows a path the run needs, the run stops before fetching and opens an issue for Jon to decide. A missing robots.txt (HTTP 404) means everything is allowed. A robots.txt that cannot be read (a server error) stops the run.
- **What is recorded.** The bytes are stored exactly as served. For each file, MANIFEST.json records:
  - the requested and final address and the HTTP status;
  - the ETag, Last-Modified and Content-Type, plus all response headers;
  - the size and the SHA-256;
  - the actual UTC fetch time. The scheduled cron time is never assumed, because scheduled runs can start late.
- **All or nothing.** The five files are fetched and validated before anything is written. A non-200 status, an empty file, invalid JSON or a page that is not HTML fails the run loudly, and nothing is stored except a log row.
- **Store only when changed.** If a file's bytes are identical (same SHA-256) to a copy already in the archive, the file is not saved again, and `stored_at` points to the existing copy. If a file changes more than once in one UTC day, later copies get a time suffix such as `payload.T142301Z.json`.
- **Internet Archive.** See the section below. An Archive problem never fails the run when the capture itself succeeded.
- **Capture log.** `captures/capture-log.csv` gets one row per run, whatever the outcome. Statuses:
  - `ok` (capture stored and an Archive receipt for every file asked about);
  - `archive-pending` (capture stored; at least one Archive receipt is still missing, so the run is green with a warning);
  - `ok-archive-failed` (used only by runs on November 8 and 9, 2026, before this rule changed);
  - `ok-with-errors` (the main capture is kept, but the backfill or policy copy failed);
  - `failed`;
  - `stopped-robots`;
  - `failed-test` and `passed-test`, for deliberate test runs with a different address. Test runs store nothing except the log row and never contact the Internet Archive.
- **Integrity.** `python -m verifier audit` checks that every stored file matches the SHA-256 in its manifest, and that every raw file is listed in a manifest. It runs on every pull request.

### Internet Archive receipts

The receipts are an outside check on our own fetch times. Our own archive does not depend on them.

- **What is saved.** Each run asks Save Page Now to save the dashboard page, `data/ledger.json` and `data/payload.json`, the files that hold the commitment hashes. Requests are at least 20 seconds apart. The pipeline uses authenticated Save Page Now when the repository secrets `IA_ACCESS_KEY` and `IA_SECRET_KEY` exist, and anonymous mode otherwise. The mode is recorded. The keys are never written or printed.
- **Retries.** Requests that fail are retried in rounds after 1, 3 and 10 minutes, within a 30-minute budget. HTTP 429 is recorded as "Archive busy". Every attempt is recorded with its time and outcome.
- **Availability check.** After any failed or ambiguous request, the pipeline asks the Archive's availability API (`archive.org/wayback/available`) whether a snapshot dated at or after our fetch exists, and records the answer. This matters because a request can fail on our side while the Archive still makes the capture. On November 8, 2026, a snapshot was created two seconds after a request that returned an error.
- **Raw-copy check.** For every receipt, the pipeline fetches the Archive's raw copy (the `id_` form of the snapshot address, which serves the bytes as captured) and compares its SHA-256 with ours. It records `match`, `mismatch` or `unavailable`, plus the Archive's hash. A mismatch is recorded as a fact, not judged. For example, the Archive may have captured a different version of the page.
- **Reused snapshots.** Save Page Now often returns an existing recent snapshot instead of making a new one. This happened on October 30, 2026 and in the November 8 and 9 runs. The pipeline records the timestamp exactly as returned. When it is earlier than our fetch, the receipt is marked `reused_existing_snapshot` with a negative `seconds_after_our_fetch`. A reused snapshot shows what the Archive held at its own timestamp. It is not a copy of our fetch, and the raw-copy check shows whether the bytes are the same.
- **Receipt window.** A snapshot found through the availability API counts as a receipt for our fetch only if it is dated no more than 24 hours after our fetch.
- **Late receipts.** Each run looks back 7 days for earlier runs still waiting for a receipt and asks the availability API again. It also retries raw-copy checks that were unavailable. Anything found is appended to that day's MANIFEST.json under `appended_notes`, with the date it was found. What was already written is never changed.
- **When it alerts.** An Archive problem alone never fails a run. An issue opens only if the capture itself failed, or if there has been no Archive receipt at all for 3 consecutive capture days. Late receipts count.

### Backfill of Anthropic's own archive

On the first run, the pipeline copies Anthropic's three dated snapshots (`snapshots/2026-05-22-1027`, `2026-08-26-1155`, `2026-10-02-1947`) under `captures/anthropic-archive/<label>/`. For each one it copies the index page, every `.json` file the page links to inside the same snapshot folder, and `data/payload.json` and `data/ledger.json` if present. Each manifest records Anthropic's snapshot label (`anthropic_snapshot_label`) and our own fetch time (`our_fetch_utc`) as separate fields.

**These are copies of Anthropic's own archive.** Our fetch time is when we copied them. It is not evidence of when we first saw anything, and these files are excluded from first-seen.

### Disclosure policy page

Once a month, the pipeline saves a dated copy of `https://www.anthropic.com/coordinated-vulnerability-disclosure` under `captures/policy/YYYY-MM/`, because the policy can change (rule R5).

## First seen by us

**Definition.** The UTC fetch time of the earliest daily capture (`captures/YYYY/MM/DD/`) whose stored files contain a hash, taken from that capture's manifest. Captures are daily, so the resolution is about a day.

**What counts as evidence, strongest first:**

1. **Our capture.** The raw bytes, their SHA-256 and the fetch time in the manifest, all committed to this public repository. The git commit date is an independent, though not tamper-proof, timestamp.
2. **A matching Internet Archive receipt.** A snapshot dated at or after our fetch, and within 24 hours of it, whose raw copy has the same SHA-256 as our file. This is an outside, third-party record that those exact bytes were public by the snapshot's time.
3. **A non-matching or reused receipt.** This shows only what the Archive held at its own timestamp. It supports the first-seen time only if the hash in question also appears in the Archive's copy. That check belongs to later phases, and is never assumed.

**What never counts:**
- the backfill copies under `captures/anthropic-archive/`;
- Anthropic's own dates (for example `committed_at`), which are Lab-reported;
- the cron time a run was scheduled for.

Our archive begins with Jon's manual capture on October 30, 2026, whose exact fetch time and headers were not recorded.

## Verification labels

- **Lab-reported:** only the lab says it, and we record it.
- **Corroborated:** a second public source agrees. This is not independent confirmation.
- **Independently verified:** we checked it ourselves against primary public records.

| Metric | Definition | Label |
| --- | --- | --- |
| Candidates | Anthropic's count of model-flagged items before triage | Lab-reported |
| Disclosed | Findings Anthropic says it sent to maintainers | Lab-reported, corroborated where a public advisory exists |
| Patched, lab count | Anthropic's "to our knowledge" figure | Lab-reported |
| Commitment recorded | The hash is present in the published ledger | Independently verified, with our first-seen time |
| Commitment matches | SHA-3-512 of the published preimage equals the ledger hash | Independently verified |
| Public ID exists | A CVE or GHSA record with that ID exists | Independently verified |
| Fix merged | The fix commit or pull request is merged into the default branch (R4) | Independently verified |
| Report, patch and reveal dates | Dates on Anthropic's finding card | Lab-reported |
| Intervals | Differences between those dates, and to the merge date | Lab-reported dates, merge date independently verified |
| Severity by source | Each source's own rating, never merged | Each source's own |
| Itemized share | Itemized divided by claimed, computed from published files | Independently verified computation |

## Published column names

Published data uses program-neutral names (approved by Jon on November 5, 2026), and every published file except `programs` starts with a `program` column (`anthropic-cvd` for this program). Anthropic's own field names stay unchanged in raw captures, cards and preimages, because the committed bytes must never change.

| Anthropic's source field | Published column |
| --- | --- |
| ant_id | finding_id |
| hash_or_ant_id (events) | hash_or_finding_id |
| claude_severity | model_severity |
| severity_claude (verification) | severity_model |
| anthropic_fix_rate_pct (snapshots) | program_fix_rate_pct |
| anthropic_revealed_count (snapshots) | program_revealed_count |

### Snapshot row (from payload.json)

| Published column | Source in payload.json |
| --- | --- |
| candidates | headline.analyzed |
| reviewed_by_firms | headline.triaged |
| confirmed_valid | headline.verified |
| true_positive_pct | headline.tpr_pct |
| reported_after_triage | headline.confirmed_reported |
| reported_without_review | headline.reported_without_review |
| reported_total | headline.disclosed |
| acknowledged | headline.acknowledged |
| patched_lab_count | headline.fixed_in_response |
| advisories, cves, ghsas | headline.advisories, headline.cves, headline.ghsas |
| projects_reported | project_count |
| ledger_entries | number of entries in ledger |
| revealed_entries | ledger entries whose reveal_tier is revealed |
| severity_agreement_n, severity_exact_agreement_pct, severity_within_one_band_pct | severity_matrix.n_vendor, exact_pct_vendor, within_one_pct_vendor |
| program_fix_rate_pct | fix_rate_pct (fixed of revealed, not of all disclosed; never published without that denominator) |
| program_revealed_count | revealed.count |

The `as_of_utc` field is shortened to whole seconds, as the data contract requires. The exact value stays in the raw capture.

## Known quirks (recorded, not fixed)

These were found in the October 30, 2026 capture of the October 2 snapshot (revision 35). Each becomes a test.

- **Revealed count.** 237 ledger entries are in the revealed tier, but the payload's revealed count is 235.
- **Disclosed.** 6,154 ledger entries are flagged disclosed, against a headline of 6,157.
- **Withdrawals are three valid views, and none is an error.** The phase 2 data records all three:
  - by the withdrawn flag: 243 entries (duplicate 83);
  - by status: 246 entries, which are the flagged 243 plus 3 with reason `report_withdrawn` and no flag;
  - counting the reason field across all entries, including the 2 with status `merged`: duplicate shows 85.
- **Fix rate.** `fix_rate_pct` (92.8) is 218 fixed of 235 revealed. It is not a fix rate for all disclosed findings.
- **Break in the time series.** Date conventions changed at the August 26, 2026 update (Pacific to UTC), and the card label "Reported to tracker" became "Discovered or logged". The time series is marked as broken at that point.
