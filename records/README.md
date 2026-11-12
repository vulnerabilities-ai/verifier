# records/

Public-record responses used for rules R3 (identifiers) and R4 (fix merged), kept exactly as received. Each lookup has a folder with a `MANIFEST.json`, which lists every attempt (time, address, HTTP status, SHA-256, and outcome: fetched, rate_limited or network_error) and the stored `response.json`. Files are never edited. A changed response is stored as a new, time-suffixed copy.

These records are kept as evidence for the checks. They are not republished as a feature. The published tables in `data/` carry only the derived facts (exists or not, dates, severity, CVSS, CWE, merge status and time, links).

**Terms: to be confirmed.** Jon will have counsel confirm the terms below before the records or anything derived from them is relied on. The links point to each source's own published terms. The short descriptions are a plain summary, not legal advice.

## Where each kind of record comes from

### GitHub Advisory Database

- **Folders:** `github/advisories/` and `github/advisories-by-cve/`.
- **Source:** the GitHub REST API, global security advisories endpoint (`https://api.github.com/advisories`). We use the workflow's built-in token, within GitHub's published rate limits.
- **Terms GitHub publishes:**
  - GitHub Terms of Service: https://docs.github.com/en/site-policy/github-terms/github-terms-of-service
  - REST API rate limits and usage: https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api
  - The advisory database's own licence, as GitHub states it in its public repository: https://github.com/github/advisory-database (see its LICENSE file).

### Requests without the token, and repository advisories

- **Folders:**
  - `github/advisories-unauthenticated/`: the global-advisory request made without the token, for IDs where GitHub refused the token. A 404 there means GitHub's global advisory database has no entry for the ID.
  - `github/repos/<owner>/<repository>/security-advisories/<ID>/`: the repository's own security advisory, with the token.
  - `.../unauthenticated/`: the same repository advisory request without the token, made only if the token was refused there.
- **Source:** the GitHub REST API (api.github.com only). Requests without the token are made one per 70 seconds, and stop at the first rate-limit answer.

### National Vulnerability Database (NVD), NIST

- **Folders:** `nvd/cves/`.
- **Source:** the NVD CVE API 2.0 (`https://services.nvd.nist.gov/rest/json/cves/2.0`). We use it without an API key, at one request every 8 seconds. On HTTP 429 (NVD limits by address, and GitHub's runner addresses are shared) we wait 35 seconds and retry up to 3 times, then record `rate_limited` and resume it first on the next run. A key would be used only after Jon approves one.
- **Terms NVD publishes:** https://nvd.nist.gov/developers/terms-of-use. NVD asks products that use its API to carry this notice, which we repeat: *This product uses data from the NVD API but is not endorsed or certified by the NVD.*

### GitHub commits, pull requests and repositories

- **Folders:** `github/repos/<owner>/<repository>/`.
- **Source:** the GitHub REST API, for the public repositories that hold each fix: repository (default branch), commit, pull request, compare, and the pull requests for a commit.
- **What we keep:** facts about whether and when a fix was merged. The code and text in those repositories belong to their owners, under their own licences.
- **Terms:** GitHub Terms of Service (link above). The rate limits are as above.

### Diagnostics

- **Folders:** `diagnostic/`.
- **What they are:** raw responses from the `diagnose_403` diagnostic. These are global-advisory requests made without a token, and repository advisory requests (`/repos/{owner}/{repo}/security-advisories/{ghsa_id}`) made with the built-in token. They come from api.github.com only, and are kept as evidence for the diagnostic report. They are not used in the published tables.

## How the lookups behave

- **robots.txt.** The two APIs above are exempt from the robots.txt check (Jon's decision of 2026-11-10), because their robots.txt files are written for web crawlers. We follow their published API rules instead. Every other host the pipeline touches keeps the robots.txt check.
- **Rate limits.** When GitHub's rate limit runs low, lookups stop cleanly and the rest are recorded as `rate_limited`. The next run starts with those.
- **Token refused.** GitHub sometimes answers HTTP 403 "Resource not accessible by integration" for a global advisory. This is not a rate limit. The response is kept as received, and the lookup is recorded as `github_refused_token` with that exact message.
- **Unusual responses.** A response that cannot be read is kept as received, and the check records `lookup_unreadable` with the reason.
