# Conflicts, tools and relationships

Listed from the day each begins. Most recent changes at the top of each section.

## Tools used

| Tool | Maker | Used for | Since |
| --- | --- | --- | --- |
| Claude Code | Anthropic | Writing, testing and explaining this repository's code and documents | 2026-11-08 |
| GitHub and GitHub Actions | GitHub (Microsoft) | Hosting, scheduled capture, issues | 2026-11-08 |
| Internet Archive, Save Page Now | Internet Archive | Independent third-party snapshots of the dashboard | 2026-11-08 |
| Cross-check model | Not chosen | Off until Jon chooses a provider. The checker may not come from the party whose program is being checked | — |

## The Anthropic conflict, and how it is controlled

The first program this repository checks is Anthropic's, and the code is written with Claude Code, an Anthropic model. The controls:

- Every determination (hashes, counts, lookups, intervals) comes from deterministic code with tests. No language model is called by the pipeline.
- Model-written text is limited to drafting plain-language summaries in the weekly report, and it is marked as such.
- Anyone can rerun the code and the tests against the archived raw files and get the same results.

## Funding

None to date.

## Relationships

None to date.
