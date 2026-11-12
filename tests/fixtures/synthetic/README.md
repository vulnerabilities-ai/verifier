# SYNTHETIC test responses

Every file in this folder is **invented for tests**. None was captured from GitHub, NVD or any
other source. File names start with `SYNTHETIC-`, and each file has a `_note` saying so.

Real captured responses are kept elsewhere under `tests/fixtures/` (for example
`tests/fixtures/diagnose-403/` and `tests/fixtures/github-403/`) and are never mixed with these.

| File | Stands in for | Why invented |
|---|---|---|
| `SYNTHETIC-facebook-hermes-repo-advisory-no-token-404.json` | GitHub's answer, without the token, for facebook/hermes's repository advisory GHSA-9qm2-7vmf-h64f: HTTP 404. The body copies the real 404 body GitHub returned for a different request. | The diagnose_403 run did not make this request. |
| `SYNTHETIC-php-src-repo-advisory-no-token-403.json` | GitHub's answer, without the token, for php/php-src's repository advisory GHSA-mh9x-w77w-65xw: HTTP 403 with an invented message. | The diagnose_403 run did not make this request. Used to test an unexpected answer. |

Each file holds `status` (the HTTP status) and `body` (the response body the test server sends).
