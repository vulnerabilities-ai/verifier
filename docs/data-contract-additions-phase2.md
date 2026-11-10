# Data contract additions, phase 2

These additions apply on top of the data contract in Design handoff R-B (file 02) and the additions in R-E (file 02). Where they differ, this file wins. Everything in R-B and R-E that is not mentioned here is unchanged.

The real files are built by the pipeline from the archive. They live in `data/` in the repository, with the same names in two forms: CSV for downloads, and JSON for the pages.

## General rules (unchanged, repeated for convenience)

- **JSON shape.** Every JSON file has `schema_version`, `generated_utc`, `source`, `sample_data` and `rows`. `sample_data` is `false` in the real files.
- **Row layout.** In the real files each row sits on its own line. This is ordinary JSON, and any JSON reader loads it.
- **Dates and times.** Dates are ISO (`2026-10-02`). Times are UTC with a Z (`2026-11-08T23:16:47Z`).
- **Empty values.** A field with no value is `null` in JSON and empty in CSV. Never show it as "0" or "none". Show a dash, or hide the element.
- **Lists.** Lists (such as CVE IDs) are JSON arrays, and JSON text inside a CSV cell.
- **The program column.** Every file starts with `program`. Today it is always `anthropic-cvd`.
- **Program-neutral names.** Every column name is program-neutral, including the new ones below. The program's own field names appear only in the schema files' `source_field`, as attribution.

## 1. snapshots: three new columns

**What a row is now.** One row per snapshot, rather than one per daily capture run. A snapshot is either:
- each distinct version of the program's data file that our own daily captures saw, or
- each copy we made of the program's own archived snapshots.

Today there are 5 rows: revisions 1, 32 and 35 (copies of the program's archive), plus revisions 35 and 40 from our own captures.

| Field | Meaning | Example | Page guidance |
| --- | --- | --- | --- |
| `source_kind` | `our_capture` (our own daily capture) or `program_archive_backfill` (our copy of the program's own archived snapshot) | `program_archive_backfill` | Label backfill rows clearly, for example "from the program's own archive". Never present a backfill row as something we observed when it was current. |
| `program_snapshot_label` | For backfill rows, the program's own name for the snapshot. Empty for our own captures. | `2026-08-26-1155` | Show it as the program's label, not as a date we captured. |
| `first_seen_by_us` | For our own captures, when our first capture containing this snapshot fetched its data file. Empty for backfill rows. | `2026-11-08T23:16:46Z` | Show "First seen by us" only when it has a value. For the revision 35 row it is `2026-10-30T23:59:59Z` (see section 2). |

**Other changes on this file:**
- **`capture_utc`** on a backfill row is when we copied the program's archived snapshot, not when the program published it. On the revision 35 row from our captures it is the end-of-day bound `2026-10-30T23:59:59Z`.
- **The note column** marks the August 26, 2026 break in date conventions on the revision 32 row (dates changed from Pacific time to UTC, and the card label "Reported to tracker" became "Discovered or logged"). The page should show a visible break in any chart that crosses it.
- **Column order:** the three new columns sit after `program_revealed_count` and before `label` and `note`.

## 2. commitments: how first-seen is filled

No new columns. Two existing columns now carry real values.

- **`first_seen_by_us`** is the fetch time of `ledger.json` in our earliest daily capture that contains the hash. Copies of the program's own archive never count.
  - The 752 hashes first seen in revision 40 show their November 8, 2026 time.
  - The 6,597 hashes in Jon's manual capture of October 30, 2026 show `2026-10-30T23:59:59Z`. This is the latest possible time that day, because the time of day was not recorded. No earlier time is ever used.
- **`first_seen_basis`** explains the value in plain words. It also gives the earliest independent evidence available when the data was built:
  - the GitHub commit time of the capture that first contained the hash;
  - the Internet Archive snapshot of `ledger.json`, when one exists. If our check of the Archive's raw copy says `mismatch` or `unavailable`, the text says the byte comparison is unresolved.
- **Text for the October 30 hashes.** It begins with exactly this sentence:
  > manual capture by Jon on 2026-10-30; time not recorded and not independently timestamped; the value is the latest possible time that day. The earliest independent evidence is the repository's first commit on 2026-11-08.

**Page guidance:** show `first_seen_basis` next to the first-seen value (a tooltip or footnote is fine). Never shorten it to a bare date.

**Other values:**
- **`hash_check`** can now also be `unavailable`. That means the card or its preimage could not be read, so the hash could not be checked. Show it as "could not be checked", not as a failure. Today: 1 `match`, 236 `not_checked`.
- **`merged_into`** is shown only when it names a revealed finding. Otherwise it is empty. Today only 2 of 1,654 merged entries name a target.

## 3. events: a `field` column and two new event types

**What it covers.** Events are only changes between snapshots in our own daily captures. Copies of the program's archive produce no events. Every event is dated by our capture time (`capture_utc`), never by the program's dates.

| Field | Meaning | Example |
| --- | --- | --- |
| `field` (new) | The published name of the field that changed. Empty for `new_commitment` and `removed_commitment`. | `status` |

**Event types** (the full list; two are new):

| `event_type` | When |
| --- | --- |
| `new_commitment` | A hash appears. `new_value` holds its tier. |
| `removed_commitment` (new) | A hash that was in the previous snapshot is gone. `old_value` holds its tier. None so far. |
| `revealed` | `tier` changes to `revealed`. |
| `withdrawn` | `status` changes to `withdrawn`. |
| `merged` | `status` changes to `merged`. |
| `status_change` | Any other change of `status`. |
| `headline_change` | A headline number changes. `field` is the snapshots column name (for example `candidates`), and `hash_or_finding_id` is empty. |
| `field_change` (new) | Any other field of a ledger entry changes. |

**Field names used in `field`.** Published names are used: `tier`, `status`, `withdrawn`, `withdrawn_reason`, `withdrawn_at`, `model_severity`, `firm_severity`, `firm_severity_sealed`, `firm_confirmed`, `maintainer_severity`, `discovered_on`, `was_disclosed`, `fixed_in_response`, `patched`, `patched_at`, `revealed`, `revealed_at`, `committed_at`, `passed_triage`, `corrected_patched_at`. For revealed findings only, the list also includes `finding_id`, `project`, `bug_class`, `cve_ids`, `ghsa_ids`, `merged_into` and `superseded_by`.

**Values.**
- Changes to project, bug class or IDs of entries that are not revealed are never listed.
- `old_value` and `new_value` are text: `true` or `false` for flags, JSON text for lists, and empty for none.

**Today: one change observed**, from revision 35 to revision 40, first captured 2026-11-08:
- 752 `new_commitment`;
- 1,652 `merged`;
- 219 `withdrawn`;
- 1 `status_change`;
- 20 `headline_change`;
- 9,268 `field_change`.

**Page guidance:** the events page appears once the file has rows (it now has). Group by `event_type`. Present counts as changes the program made to its records, without commentary.

## 4. gaps: new columns, and a new label

| Field | Meaning | Example |
| --- | --- | --- |
| `capture_utc` | As in snapshots (the row's key; R-B listed it implicitly). | `2026-11-08T23:16:45Z` |
| `revision` | The program's revision number. | `40` |
| `source_kind` | As in snapshots. | `our_capture` |
| `program_snapshot_label` | As in snapshots. | `2026-08-26-1155` |
| `merged_status` | Ledger entries with status `merged`. | `1654` |
| `merged_with_target` | Merged entries that name the finding they were merged into. | `2` |

**Other changes on this file:**
- **`withdrawn_flag`** is empty for snapshots whose ledger has no withdrawn field (revision 1).
- **`label`** now reads: "Independently verified (our count from the program's published files)".
- **`cves_itemized` and `ghsas_itemized`** count unique IDs across `cve_ids` and `corrected_cve_ids` (and the GHSA equivalents).

## 5. withdrawals: a new file

There is one row per snapshot, view and reason. There are three views of withdrawals in the same ledger. They give different totals because the program's flag, status and reason fields do not always move together. **None of the three is an error, and the page must not present any of them as one.**

| Field | Meaning | Example |
| --- | --- | --- |
| `program` | As everywhere. | `anthropic-cvd` |
| `capture_utc` | As in snapshots. | `2026-11-08T23:16:45Z` |
| `revision` | As in snapshots. | `40` |
| `source_kind` | As in snapshots. | `our_capture` |
| `program_snapshot_label` | As in snapshots. | (empty) |
| `view` | `by_flag` (entries with the withdrawn flag), `by_status` (entries with status `withdrawn`) or `by_reason_all_entries` (every entry with a withdrawal reason, including merged entries). | `by_status` |
| `reason` | The program's withdrawal reason. Empty when an entry in the view has none. | `duplicate` |
| `count` | Number of ledger entries. | `44` |

The total for a view is the sum of its rows.

**Today, revision 35:**
- by flag: 243 (duplicate 83);
- by status: 246 (the flagged 243, plus 3 `report_withdrawn`);
- by reason across all entries: duplicate 85, which includes the 2 merged entries.

**Today, revision 40:**
- by flag: 415 (duplicate 44);
- by status: 419 (the flagged 415, plus 3 `report_withdrawn` and 1 with no reason);
- by reason across all entries: duplicate 1,698, which includes the 1,654 merged entries.

**Page guidance:** show the three totals side by side with one plain sentence on what each view counts.

## 6. The `data/schema/` folder

There is one file per published file (`data/schema/snapshots.json`, `commitments.json`, `events.json`, `gaps.json`, `withdrawals.json`). Each has this shape:

```json
{
  "schema_version": 1,
  "file": "commitments",
  "formats": ["csv", "json"],
  "rows": "One row per commitment hash, newest commitment first.",
  "columns": [
    {"name": "model_severity", "type": "string", "meaning": "...", "source_field": "claude_severity", "label": "Lab-reported"}
  ]
}
```

- **`type`** is one of `string`, `integer`, `number`, `boolean`, `date`, `time` or `list`.
- **`source_field`** names the program's own field the value comes from (attribution). This is the only place the program's own names appear.
- **`label`** is the verification label from METHODOLOGY.md, where one applies.
- **For pages:** the schema files can drive column headers and tooltips. The column order in each schema file matches the CSV header.

## 7. Still to come (phase 3)

`summary.json`, `verification.csv` and `verification.json`, and `programs.csv` and `programs.json` are not produced yet. Pages that read them should keep using the sample files until phase 3 publishes the real ones.
