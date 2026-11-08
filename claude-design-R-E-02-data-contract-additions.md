# Claude Design handoff R-E, 02 data contract additions

These additions apply on top of the data contract in R-B file 02. Where they differ, this file wins. The sample data in file 03 follows them.

## The program column

Every row in snapshots, commitments, verification, gaps, events and summary now starts with a program column holding the program's ID. In the sample data every row is anthropic-cvd, because it is the only program with records. The IDs are: anthropic-cvd, project-glasswing, openai-daybreak, project-quiltworks, gold-eagle, akrites and athena. The program column is also the first column in each CSV.

Pages that show one program's data filter by this column. Today only the Anthropic panel has rows to show.

## programs (new file, one row per program)

CSV and JSON, in the same JSON shape as the other files.

| Field | Meaning |
| --- | --- |
| program | The program's ID, as above, and the anchor it uses on the Ledger |
| name | The program's own name, as shown in headings and the comparison table |
| operator | The organization that runs it |
| status | A short, dated statement of where the program stands |
| per_finding_record | "yes, for revealed findings" or "none found" (none found means we found no per-finding record published, and the Ledger says so as a factual statement) |
| publishes_summary | One line on what the program publishes |
| as_of | The date of the most recent source behind the status |

Seven rows in the sample. A new program is added by adding a row here, a panel to the Ledger, and rows in the other files once it publishes records that can be checked.

## Notes

- The Data page lists seven files now (snapshots, commitments, verification, gaps, events, summary and programs). The summary file is JSON only, so the downloads total 13.
- programs.json is read by the Ledger's comparison table, the selector and the Data page's Programs covered table. The panels' copy and sources stay in the HTML.
- Nothing else in the contract changes. The first-seen note, the checked-so-far counts and the empty events file behave as before.
