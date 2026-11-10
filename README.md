# verifier

Open data and independent archive for checking claims by AI vulnerability-discovery programs.

![Last capture](https://img.shields.io/badge/dynamic/json?url=https%3A%2F%2Fraw.githubusercontent.com%2Fvulnerabilities-ai%2Fverifier%2Fmain%2Fcaptures%2Flatest.json&query=%24.last_capture_date&label=last%20capture&color=blue)

**Last capture:** the badge above reads [`captures/latest.json`](captures/latest.json). Every run, successful or not, is listed in [`captures/capture-log.csv`](captures/capture-log.csv). If the date above is more than two days old, the daily capture has stopped: check the Actions tab.

## What this is

The first program tracked is Anthropic's coordinated vulnerability disclosure dashboard at `red.anthropic.com/2026/cvd/` (program ID `anthropic-cvd`). This repository:

1. **Archives it daily.** It keeps raw copies of what was published, exactly as served, with the UTC time we fetched each file, its SHA-256 fingerprint, the response headers and an Internet Archive receipt. This is an independent, dated record of when each commitment hash was first visible.
2. **Verifies what can be verified.** Commitment hashes are checked against their revealed preimages, and identifiers, fixes and dates against public records. (Phases 2 and 3; not built yet.)
3. **Publishes open data** under `data/` with pinned definitions. Every number is labelled *Lab-reported*, *Corroborated* or *Independently verified*. See [METHODOLOGY.md](METHODOLOGY.md).

Raw captures are never edited or deleted. Git history keeps every version. Corrections are logged in [CORRECTIONS.md](CORRECTIONS.md). Tools, funding and relationships are listed in [CONFLICTS.md](CONFLICTS.md).

## Layout

```text
captures/YYYY/MM/DD/         raw files from our daily capture, plus MANIFEST.json
captures/anthropic-archive/  copies of Anthropic's own dated snapshots (not first-seen evidence)
captures/policy/YYYY-MM/     monthly copy of Anthropic's disclosure policy page
captures/archive-raw/        Internet Archive raw copies that differed from ours (kept for diagnosis)
captures/capture-log.csv     one row per run
cards/<ID>/                  revealed finding cards, preimages and each card's verification.json (rule R2)
records/                     public-record responses (GitHub Advisory Database, NVD, GitHub), as received
reports/                     weekly review reports
data/                        published open data (CC BY 4.0): snapshots, commitments, events, gaps, withdrawals,
                             verification, severity, summary, programs
data/schema/                 the meaning and source of every published column
docs/                        the build spec and the data contract
src/verifier/  tests/        pipeline code and tests
```

To save space, a file whose bytes are identical to a copy already in the archive is not stored again. The day's `MANIFEST.json` still records the fetch, and its `stored_at` field points to the identical copy. The matching SHA-256 proves the two are the same.

## Getting the data

- **Public mirror and citation address:** after each reviewed merge, `data/` is published at `https://vulnerabilities-ai.github.io/verifier/data/` (for example `.../data/commitments.json`). It comes with `site-data.zip` and its SHA-256 manifest.
- **For a website:** bundle a reviewed copy from `site-data.zip`, rather than fetching from the mirror while the site runs.
- **Column meanings:** `data/schema/`.
- **NVD:** this product uses data from the NVD API but is not endorsed or certified by the NVD.

## Check it yourself

Using Python 3.10 or newer, with nothing to install:

```bash
PYTHONPATH=src python3 -m verifier audit
```

This confirms that every stored file matches the SHA-256 in its manifest.

```bash
PYTHONPATH=src:tests python3 -m unittest discover -s tests
```

This runs the tests, including the golden fixtures from the October 30, 2026 capture.

## How to cite

> vulnerabilities.ai verifier, archive of Anthropic's coordinated vulnerability disclosure dashboard, https://github.com/vulnerabilities-ai/verifier, accessed YYYY-MM-DD, commit `<hash>`.

Citing a commit hash pins the exact version of the data you used.

## Licenses

- **Data** (`data/`): [CC BY 4.0](data/LICENSE).
- **Code**: [MIT](LICENSE).
- **Raw captures** (`captures/`, `cards/`) are copies of third-party pages, kept as evidence. Their content belongs to its publishers and is not relicensed here.

Contact: verifier@vulnerabilities.ai
