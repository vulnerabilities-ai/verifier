# Pipeline Build Spec for Claude Code (v1)

## Purpose and how to use this document

This document tells Claude Code what to build: a small, public GitHub repository that captures Anthropic's coordinated vulnerability disclosure dashboard, verifies what can be verified, and publishes open data for vulnerabilities.ai. It follows the [Verifier Model adoption plan](https://claude.ai/artifact/WjHZcGeKhS2X4UutzugCBr), which holds the reasoning. Every definition here is meant to be copied into the repository's methodology file.

**Goals**

1. An independent, dated archive: raw copies of what Anthropic published, and when we first saw it. This is the only independent proof that a commitment hash existed before its reveal.
2. Verification of what can be verified: commitment hashes against their preimages, public CVE and GHSA records, fix merges, and the intervals between report, patch and reveal.
3. Open data under CC BY 4.0 with pinned definitions, where every number is labeled Lab-reported, Corroborated or Independently verified.
4. A human decision before anything critical is published.

**Who does what.** Claude Code writes, tests and explains the code. Jon is not a developer, so Claude Code explains every step in plain language, does the work itself wherever it can, and never assumes terminal skill. Jon makes the decisions listed in section 10 and merges the weekly review pull request.

**Out of scope for v1.** Website pages (Claude Design builds them from this repository's data), the 14 hashes in Anthropic's April red-team post (an add-on for later), programs other than Anthropic's, and detecting which release first shipped a fix (phase 4).

## Your one-time setup

These steps are for you, Jon, and take about 30 minutes in total. Menu names change, so if a screen looks different from what is written here, send a screenshot and ask.

1. **Create the GitHub organization, if you haven't yet.** Sign in to github.com with your own personal GitHub account (create one first if you don't have one). Use the role-based email only as the organization's contact email, never as a shared login, because GitHub accounts belong to one person. Click your profile picture (top right), choose Your organizations, then New organization. Pick the Free plan, choose a name (a placeholder is fine, and it can be renamed once the publishing entity is named), and make yourself the owner. Confirm two-factor authentication is on.
2. **Open Claude Code.** Use the desktop app or the web version at claude.ai/code, whichever you prefer. Start a new project and say: "Build the pipeline in the attached spec." Attach this document, exported as Markdown, or paste it in.
3. **Connect GitHub when it asks.** Approve the connection, and give access to the new organization only, not your personal repositories.
4. **Let Claude Code create the repository.** It must be public. Public repositories get free automation minutes, and a public repository is the point: anyone can check the archive. Ask Claude Code to explain anything you don't follow.
5. **Run the first capture by hand.** On the repository page, click the Actions tab, click the workflow named Capture in the left list, then the Run workflow button, then the green Run workflow button again. When it finishes with a green check, open the captures folder and confirm today's files are there.
6. **Merge the weekly review.** Each week a pull request appears under the Pull requests tab. Open the newest one and read the summary at the top. If it looks right, click the green Merge pull request button, then Confirm merge. If anything looks wrong, don't merge. Write "hold" in a comment and ask me or Claude Code.
7. **Keys, only when needed.** When you choose the cross-check model, Claude Code will explain how to create an API key and where to paste it (the repository's Settings, then Secrets and variables, then Actions). Never paste a key into a chat or a file.
8. **Failure emails.** If a daily capture fails, GitHub normally emails the repository owners and the pipeline opens an issue. Forward the email to me.

## What the pipeline does

Ten capabilities, from raw capture to published data. Everything that touches a specific finding ends in the review pull request.

| Capability | Input | Output | When |
| --- | --- | --- | --- |
| Capture | The dashboard page and its data files | Raw files exactly as served, SHA-256, UTC fetch time, response headers, Internet Archive receipt | Daily |
| Parse | Captured files | Headline time series and a ledger snapshot | Each capture |
| Diff | Today's ledger against the previous one | Events: new commitments, newly revealed, withdrawn, merged, status changes | Each capture |
| First-seen log | Every commitment hash | The first capture in which each hash appeared | Each capture |
| Card verification | Newly revealed finding cards | Hash match result, timeline, severity by source, fix link, advisory links | Weekly and on new reveals |
| Public-record reconciliation | CVE and GHSA IDs, fix links | Whether each ID exists, its dates, severity and CWE, and whether the fix merged | Weekly |
| Interval metrics | Card timelines | Days from report to patch, patch to reveal and report to reveal, against the policy defaults | Weekly |
| Gap metrics | Headline numbers against the ledger | Claimed versus itemized counts | Each capture |
| Review pull request | All derived outputs | A pull request with a plain-language report and flagged items | Weekly |
| Publish | Merged data | CSV and JSON files, README, schema, license | On merge |

**The pipeline must never**

- Label a commitment or finding "overdue", "late" or "in violation". It reports intervals against the policy defaults and nothing more.
- State or imply intent, competence or motive.
- Use an Anthropic model to make a determination about Anthropic data. Hashes, counts and lookups run as deterministic code.
- Publish a derived result about a specific finding without it passing through the review pull request.
- Modify or delete a raw capture.

## Repository layout and schedules

The repository is public, and raw captures are never edited. Names are placeholders until the publishing entity is named.

```text
cvd-verifier/
  README.md                  what this is, how to cite it, the license
  METHODOLOGY.md             pinned definitions (copied from section 6)
  CONFLICTS.md               funding, tools used, relationships
  CORRECTIONS.md             dated corrections log
  captures/
    YYYY/MM/DD/              raw files exactly as served, never edited
      dashboard.html  payload.json  ledger.json  about.html  archive.html
      MANIFEST.json          URL, status, headers, UTC fetch time, SHA-256, archive receipt
    capture-log.csv          one row per run
  cards/
    ANT-2026-XXXXXXXX/       one folder per revealed finding
      card.html              raw copy of the finding card
      preimage.json          extracted preimage bytes
      verification.json      hash result, timeline, severities, links, reconciliation
  data/                      published open data, versioned
    snapshots.csv  commitments.csv  verification.csv  events.csv  gaps.csv
    schema/                  column definitions
  reports/
    YYYY-MM-DD-weekly.md     the review report, opened as a pull request
  src/  tests/               pipeline code and tests, including golden fixtures
  .github/workflows/         capture.yml  verify.yml
```

| Workflow | Schedule | What it does | Where it writes |
| --- | --- | --- | --- |
| capture | Daily at an odd minute such as 06:23 UTC, and on demand | Fetch, hash, save to the Internet Archive, append to the capture log, commit | Directly to main, and only under captures/ |
| verify | Weekly on Monday, and on demand | Rebuild data/ from the captures, fetch and verify new cards, reconcile with public records, write the report | A branch, then a pull request to main |

**Keeping the schedule alive.** GitHub disables scheduled workflows in a public repository after 60 days with no repository activity. Claude Code must confirm whether the pipeline's own commits count as activity, and if they may not, add a monthly activity step. Because a disabled schedule cannot alert anyone, the README shows the date of the last capture, and Jon checks the Actions tab once a month (two minutes).

**Run behavior.** Scheduled runs can start late, so the manifest records the actual fetch time and the pipeline never assumes the cron time. Runs must not overlap. Workflow permissions are the minimum needed: write access to contents and pull requests, and to issues for failure alerts.

## Verification rules

These rules are exact so that anyone can reproduce a result. Each result is recorded with the inputs it used and the time it ran.

**R1. Capture.** The base address is red.anthropic.com/2026/cvd/. Capture the dashboard page, data/payload.json, data/ledger.json, about/index.html and archive/index.html. Identify the pipeline with a clear User-Agent that names the project and a role-based contact address, keep to one request per second, and read robots.txt first. If it disallows any path, stop and ask Jon. Store the bytes exactly as served, then record the HTTP status, ETag, Last-Modified, final address, UTC fetch time and SHA-256. Ask the Internet Archive's Save Page Now to save the dashboard address and record the snapshot address it returns. The Archive may reuse a recent snapshot instead of making a new one (this happened on October 30), so record the returned timestamp as it is. Fail loudly on errors or empty files.

**R2. Commitment hash.** For each ledger entry whose reveal tier is revealed, fetch red.anthropic.com/2026/cvd/findings/ followed by the ANT ID and save the raw page. Extract the preimage from the download link's data address (percent-decoded UTF-8), and fall back to the visible preimage text, re-serialized canonically. Canonical form means sorted keys, no whitespace between tokens, UTF-8, and non-ASCII characters left unescaped (escaping them changes the hash). Compute the SHA-3-512 digest and compare it with the ledger hash and with the provenance hash printed on the card. Record raw-bytes match, canonical-rebuild match and the outcome: match, mismatch or unavailable.

**R3. Public identifiers.** For every CVE and GHSA ID on a card or ledger entry, query GitHub's advisory API and NVD. Record whether the ID exists, its published and updated dates, severity, CVSS version and score, CWE, review status, references and credits. Compare with the ledger's project and bug class, and record differences without judging them. Use the workflow's built-in GitHub token, and ask Jon for a free NVD key if rate limits require one (confirm current limits). Cache every response with its fetch time.

**R4. Fix merged.** From the card's upstream fix commit and the advisory's pull request link, ask GitHub whether the commit exists, and whether the pull request is merged, with its merge date and base branch. Fix merged means the fix commit or its pull request is merged into the project's default branch, dated by its merge time. If the project is not on GitHub, record "not checked" with the address.

**R5. Intervals.** From each card's timeline (Discovered or logged, Sent to maintainer, Maintainer acknowledged, Patch released, Publicly revealed), compute days from report to patch, patch to reveal, report to reveal, and report to fix merged. Compare each with the policy defaults of 90 days and 45 days, and with the 135-day reference from the April post, as counts within or above each. These are descriptive only. Keep a dated copy of Anthropic's disclosure policy page under captures/ and recapture it monthly, since the policy can change.

**R6. Gap metrics.** Every capture, compute claimed against itemized counts: patched (the headline figure against ledger entries flagged fixed in response), CVEs and GHSAs (headline against unique IDs on ledger entries), disclosed (headline against ledger entries flagged disclosed), revealed (payload count against ledger entries in the revealed tier), and withdrawn (the flag against the status). Write the numbers to gaps.csv with no commentary.

**R7. Severity by source.** For each revealed finding, record Claude's, the firm's and the maintainer's severity, plus NVD's and GitHub's, as separate columns. Produce a monthly count matrix.

**R8. Manifest checksum.** Anthropic publishes a manifest checksum without a documented method, and the first attempt could not reproduce it. Retry monthly with any method Anthropic documents, and record the result as a note, never as a finding.

## Data files and definitions

Published files live in data/, versioned and licensed CC BY 4.0, each with a schema file that defines every column. A sixth file, summary.json (JSON only), holds one row of derived counts for the Ledger and Commitments pages: commitments by tier, revealed, withdrawn and their reasons, checked so far, fixed itemized, and the itemized share of reported. The exact columns of every file are defined in the data contract in Design handoff R-B (file 02), and where it differs from the table below, the contract wins.

**Program-neutral column names (approved by Jon, November 5).** Published data uses neutral names so other programs can be added later, and every published file except the programs file has a program column (value anthropic-cvd for this program). Anthropic's own field names stay exactly as they are in raw captures, cards and preimages, because the committed bytes must never change: the preimage contains ant\_id and claude\_severity, and the hash covers them. The pipeline maps source fields to published columns when it builds data/:

| Anthropic's source field | Published column |
| --- | --- |
| ant\_id | finding\_id |
| hash\_or\_ant\_id (events) | hash\_or\_finding\_id |
| claude\_severity | model\_severity |
| severity\_claude (verification) | severity\_model |
| anthropic\_fix\_rate\_pct (snapshots) | program\_fix\_rate\_pct |
| anthropic\_revealed\_count (snapshots) | program\_revealed\_count |

The finding IDs themselves (for example ANT-2026-87DJGDRB) are unchanged. A programs file (programs.csv and programs.json) lists each tracked program, and is maintained by hand. Its columns are defined in Design handoff R-E (file 02), and the schema files must document every renamed column and its source field.

| File | One row per | Key columns |
| --- | --- | --- |
| snapshots.csv | Capture | Capture time (UTC), source file SHA-256, Anthropic's as-of time and revision, candidates, reviewed by firms, confirmed valid, reported after triage, reported without review, disclosed, acknowledged, patched (lab count), advisories, CVEs, GHSAs, projects, ledger entries, revealed entries |
| commitments.csv | Commitment hash | Hash, first seen by us (UTC), committed date, latest tier and status, withdrawn flag and reason, merged-into, Claude severity, and ANT ID, project and bug class once revealed |
| verification.csv | Revealed finding | ANT ID, hash result, CVE and GHSA IDs, whether each exists, advisory and NVD dates, fix merged and its date and links, report, patch and reveal dates, the four intervals, severity from each source, a label per metric, notes |
| events.csv | Change | Capture time, event type (new commitment, revealed, withdrawn, merged, status change, headline change), hash or ANT ID, old value, new value |
| gaps.csv | Capture | Claimed and itemized counts for patched, CVEs, GHSAs, disclosed, revealed and withdrawn, with no commentary |

**First seen by us** is the UTC time of the earliest capture that contains a hash. Captures are daily, so the resolution is about a day, and the Internet Archive receipts give an outside check.

**Verification labels.** Lab-reported means only Anthropic says it, and we record it. Corroborated means a second public source agrees, which is not independent confirmation. Independently verified means we checked it ourselves against primary public records.

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

## Known quirks and golden fixtures

These are facts found in the October 30 capture of the October 2 snapshot (revision 35). Each one becomes a test, so that a change in Anthropic's data shows up as a failing check instead of a silent error.

**Quirks to encode**

1. The ledger appears twice. payload.json carries full timestamps and an is\_fixed field, while ledger.json carries dates only, empty strings for missing values and a revealed field. The sets of hashes are identical.
2. Counts differ in ways the pipeline must record, not fix: 237 entries are in the revealed tier but the payload's revealed count is 235; 6,154 entries are flagged disclosed against a headline of 6,157; 243 entries carry the withdrawn flag but 246 have the withdrawn status.
3. The passed-triage and vendor-confirmed flags are true for only 232 entries, because they are filled in only for revealed findings.
4. The payload's fix\_rate\_pct of 92.8 is 218 fixed of 235 revealed. It is not a fix rate for all disclosed findings (516 of 6,157, or 8.4%, by the lab's count). Never publish it without that denominator.
5. Identifiers are many-to-many: one advisory can list several ANT IDs (a FreeRDP advisory lists three), and one finding can carry both a CVE and a GHSA. Count unique IDs.
6. Eighteen revealed findings (sixteen flagged fixed in response) show a patch date earlier than the discovery date. The card's label is "Discovered or logged". Record it without judgment.
7. Anthropic's manifest checksum was not reproducible (R8).
8. Dates changed convention at the August 26 update (Pacific to UTC), and the card label "Reported to tracker" became "Discovered or logged". Mark the break in the time series.
9. Preimages contain non-ASCII characters (an arrow in reproduction steps), and the committed bytes leave them unescaped.
10. Anthropic keeps three dated snapshots at snapshots/2026-05-22-1027, snapshots/2026-08-26-1155 and snapshots/2026-10-02-1947. Capture all three on the first run as a backfill, under captures/anthropic-archive/.

**Golden fixtures (Jon's manual capture, October 30)**

| File | SHA-256 |
| --- | --- |
| Dashboard page | 07570f8dffddefd8a8ee27a5870aa90331eff2cdad13a64a1f35a71d57f93b64 |
| about page | c022329f17815b0eb09e3773dea3e603b2c2d65da55c763eeb0a19178221a5f5 |
| archive page | 94135f2f080cc6fa79f343eb6b29b80828192aa1b5d119ef59c81835d8c8d3c8 |
| ledger.json | c366fc69afa1dcaac3c0a89da46867a78faaa682dd3be375fee32ccf03099ba4 |
| payload.json | 22b45c8fe1695b940609be0282a5e07e9522516c540ead8891af9ed402da38d3 |

**Expected parse of the snapshot.** Candidates 29,439; confirmed valid 5,674; reported after triage 1,333; reported without review 4,824; disclosed 6,157; acknowledged 5,103; patched 516; advisories 584 (219 CVEs and 365 GHSAs); projects 591; 6,597 ledger entries (acknowledged 4,868, sent 1,054, discovered 438, revealed 237); statuses disclosed 5,936, fixed 218, withdrawn 246, merged 2, none 195; withdrawal reasons mistake 137, duplicate 83, false positive 11, out of scope 7, rejected as not a security issue 5; earliest commitment February 15, 2026.

**Expected result for ANT-2026-87DJGDRB (wolfSSL).** Ledger hash f35e4f410ec58dab28431670e173e03fd1e5105f8afefc79c7edd5117d684d3aa377d218762d2f1ab70c6262e31227885bacaf2062958b077e305e5aebc6c37d, and R2 returns a match. IDs are CVE-2026-12340 and GHSA-q349-x427-xg3w. The timeline is March 24 (discovered or logged), March 27 (sent and acknowledged), June 25 (patch released) and August 17 (revealed), so the intervals are 90, 53 and 143 days. The fix pull request (wolfSSL #10641, commit 6bfb53f0) merged on June 10. Severities are Claude high, firm high, maintainer low, and GitHub's unreviewed advisory shows Moderate, CVSS 6.3, CWE-125, published June 25.

## Guardrails, conduct and security

**Conduct toward the source**

- Identify the pipeline, keep to one request per second, honor robots.txt, and cache. Fetch cards only for newly revealed IDs, and re-check known cards monthly for changes.
- Touch only public pages. Never try to get around an access control.
- If Anthropic's pages change format, fail with a clear message and open an issue. Never guess.
- Published data files carry metadata only (IDs, dates, severities, links). They do not republish report text, crash traces or diffs. Raw card copies sit in the archive and are not featured.

**Editorial guardrails in the report generator**

- Use the wording "The dashboard states X. Public records show Y." Never infer intent, competence or motive.
- Flag every difference from a lab's figure as needs-human-review, with its evidence bundle and as-of dates and links.
- The pipeline never contacts anyone. Jon decides on right of reply.
- Corrections go in CORRECTIONS.md, dated. Published data is never changed silently, and git history keeps every version.

**Conflict controls**

- Claude Code, an Anthropic model, writes this code. Every determination comes from deterministic code with tests. Model-written text is limited to drafting plain-language summaries in the report, and is marked as such.
- An optional cross-check module sends a non-Anthropic model the evidence bundle only, with no browsing, and logs the model name and version. The checker may not come from the party whose program is being checked (no Gemini on Google programs, no Grok on xAI's). It stays off until Jon chooses a provider.
- CONFLICTS.md lists every tool used, including Claude Code and the cross-check model, and every relationship, from the day it begins.

**Security**

- No secrets in the repository or in logs. Use Actions secrets only.
- Pin every third-party action to a full commit hash, keep dependencies minimal and locked, and turn on dependency alerts.
- Give each workflow the minimum permissions. Never run untrusted code with write access.
- Require two-factor authentication for every organization member.
- Block force pushes and deletions on main, so the archive's history cannot be rewritten (confirm this is available on the free plan for a public repository).
- Use a role-based contact address, and keep personal data out of the repository.

## Build phases and acceptance tests

Build in this order. Each phase ends only when its acceptance tests pass, and Claude Code explains what it did to Jon in plain language at the end of each phase.

| Phase | What gets built | Acceptance tests |
| --- | --- | --- |
| 1. Capture (week 1) | capture.yml, the manifest, Internet Archive receipts, the capture log, the backfill of Anthropic's three archived snapshots, the README with the last-capture date, the golden fixtures, and the headline parser | A manual run succeeds. A second run the same day adds a log row and no duplicate files. The manifest hashes match the files. The fixtures parse to the expected numbers. A deliberately broken address opens an issue instead of a silent failure |
| 2. Ledger and cards (weeks 2 to 3) | The ledger diff and events, the first-seen log, card fetching and R2, verification.json, and the first versions of snapshots, commitments, events and gaps | The fixtures reproduce every expected number in section 7. R2 returns a match for ANT-2026-87DJGDRB. All 237 revealed cards are fetched and the outcomes are tallied and reported. A test proves non-ASCII characters are not escaped. A test covers each known quirk |
| 3. Reconciliation and review (weeks 3 to 5) | R3, R4, R5 and R7, the weekly review pull request and report, publishing of data/ (the method is for Jon to choose in section 10), and the cross-check module, off by default | ANT-2026-87DJGDRB matches its expected result. One full review pull request is generated. A wording test fails the build if the report contains "overdue", "late", "violation" or any statement of intent |
| 4. Later | Detecting which release first shipped a fix, the April post's 14 hashes, other programs with checkable numbers, JSON feeds for the website, the cross-check provider | Specified when each is chosen |

**Done for v1** means the archive has run daily for 14 days without a gap, verification.csv has been published once through a merged pull request, and METHODOLOGY.md, CONFLICTS.md and CORRECTIONS.md exist.

## Decisions for Jon, and appendix

Claude Code should ask Jon for these when it reaches them, in plain language, and never guess.

- [ ] The organization and repository name (a placeholder until the publishing entity is named). I recommend a program-neutral name so other programs can be added later
- [ ] A role-based contact address for the User-Agent, the repository and failure emails
- [ ] The cross-check model, Gemini or Grok (the module stays off until chosen)
- [ ] How the website reads the data: GitHub Pages serving the data files (I believe other sites can read them, to be confirmed), or a script that copies the files into the site export before each deploy
- [ ] The code license (the data is CC BY 4.0), for example MIT or Apache 2.0
- [ ] A free NVD API key, only if rate limits require it

**Appendix: fields found in the captured data**

- Ledger entry (ledger.json and payload.json): ant\_id, bug\_class, claude\_severity, committed\_at, corrected\_cve\_ids, corrected\_ghsa\_ids, corrected\_patched\_at, cve\_ids, discovered\_on, ghsa\_ids, hash, is\_fixed\_in\_response (is\_fixed in the payload copy), maintainer\_severity, merged\_into, passed\_triage, patched, patched\_at, project, reveal\_tier, revealed (ledger.json only), revealed\_at, status, superseded\_by, vendor\_confirmed, vendor\_severity, vendor\_severity\_sealed, was\_disclosed, withdrawn, withdrawn\_at, withdrawn\_reason.
- payload.json top level: analysis\_until, as\_of, by\_bug\_class, by\_ecosystem, by\_project, cve\_records, filter\_spec, first\_disclosure\_at, fix\_rate\_pct, fp\_rate, funnel, ghsa\_records, headline, ledger, manifest\_sha3, median\_days\_to\_ack, median\_days\_to\_patch, patch\_acceptance, project\_count, revealed, revision, severity\_matrix, severity\_pairs, target\_depth, tier\_partition, total\_acknowledged, total\_cves, total\_disclosed, total\_fixed, total\_fixed\_in\_response, total\_ghsas, total\_revealed, total\_sent, total\_verified.
- headline: acknowledged, advisories, advisories\_published, analyzed, confirmed\_reported, cves, disclosed, fixed\_in\_response, ghsas, reported\_without\_review, severity\_basis\_definitions, severity\_cube.
- Preimage (version 1): ant\_id, bug\_class, claude\_severity, commit\_sha, created\_at, description, discovered\_at, location, poc\_sha256, preimage\_version, project, reproduction, technical\_details, title, vendor\_severity.
- Finding card, at red.anthropic.com/2026/cvd/findings/ followed by the ANT ID: report, firm analysis (verdict and severity), upstream fix (diff and commit link), advisory link, timeline, and provenance (hash, committed and revealed times, preimage link and visible text).
