"""Fixed settings for the capture pipeline (spec rule R1).

Everything here is public and safe to commit. No secrets belong in this file.
"""

from __future__ import annotations

from . import __version__

PROGRAM = "anthropic-cvd"

CONTACT = "verifier@vulnerabilities.ai"
REPO_URL = "https://github.com/vulnerabilities-ai/verifier"
# The product token is what robots.txt rules are matched against.
UA_TOKEN = "vulnerabilities.ai-verifier"
USER_AGENT = f"{UA_TOKEN}/{__version__} (+{REPO_URL}; {CONTACT})"

BASE_URL = "https://red.anthropic.com/2026/cvd/"

# (stored file name, path relative to BASE_URL, expected kind)
TARGETS: list[tuple[str, str, str]] = [
    ("dashboard.html", "", "html"),
    ("payload.json", "data/payload.json", "json"),
    ("ledger.json", "data/ledger.json", "json"),
    ("about.html", "about/index.html", "html"),
    ("archive.html", "archive/index.html", "html"),
]

# Anthropic's own dated snapshots (spec quirk 10), copied once as a backfill.
ANTHROPIC_SNAPSHOT_LABELS = [
    "2026-05-22-1027",
    "2026-08-26-1155",
    "2026-10-02-1947",
]
# Data files we also try inside each snapshot folder, in addition to any
# .json file the snapshot page links to.
SNAPSHOT_DEFAULT_DATA = ["data/payload.json", "data/ledger.json"]

# Anthropic's disclosure policy page, copied once a month (spec rule R5).
POLICY_URL = "https://www.anthropic.com/coordinated-vulnerability-disclosure"

# Internet Archive.
WAYBACK_BASE = "https://web.archive.org/"
SPN_PREFIX = WAYBACK_BASE + "save/"  # anonymous Save Page Now: GET save/<url>
AVAILABILITY_URL = "https://archive.org/wayback/available"
# Files we ask the Archive to save (they hold the commitment hashes).
ARCHIVE_FILES = ["dashboard.html", "ledger.json", "payload.json"]
ARCHIVE_SPACING_SECONDS = 20  # at least this long between save requests
ARCHIVE_BACKOFF_SECONDS = (60, 180, 600)  # waits before retry rounds 2, 3, 4
ARCHIVE_BUDGET_SECONDS = 30 * 60  # stop retrying after this long
ARCHIVE_POLL_INTERVAL_SECONDS = 10  # authenticated mode: job status polling
ARCHIVE_POLL_TIMEOUT_SECONDS = 180
# A snapshot counts as a receipt for our fetch only if dated no later than this
# after our fetch (or, if the Archive reused an older snapshot, see METHODOLOGY).
ARCHIVE_RECEIPT_WINDOW_SECONDS = 24 * 3600
# Look back this many days for earlier runs still waiting for a receipt.
LATER_RECEIPT_LOOKBACK_DAYS = 7
# Open an issue when this many consecutive capture days have no receipt.
ARCHIVE_STALE_DAYS = 3

# Politeness: at least this many seconds between requests to the same host.
MIN_INTERVAL_SECONDS = 1.0
TIMEOUT_SECONDS = 60
SPN_TIMEOUT_SECONDS = 180

# Public records (rules R3 and R4).
GITHUB_API = "https://api.github.com"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Jon's decision of 2026-11-10: these two documented APIs are exempt from the
# robots.txt check (their robots.txt is written for crawlers). They are used
# under their own published rules instead: GitHub with the workflow's built-in
# token within its rate limits; NVD without a key (none unless Jon approves one).
# Every other host keeps the robots check.
API_ROBOTS_EXEMPT = frozenset({"api.github.com", "services.nvd.nist.gov"})
# NVD limits by address, and GitHub's runner addresses are shared, so the first
# full run met HTTP 429 at 5 requests per 30 s (Jon, 2026-11-12): one request
# every 8 seconds; on a 429, wait 35 seconds and retry up to 3 times, then
# record rate_limited (resumed first on the next run).
NVD_MIN_GAP_SECONDS = 8.0
NVD_RETRY_WAIT_SECONDS = 35.0
NVD_RETRIES = 3
# GitHub's answer when the built-in token may not read a global advisory.
GITHUB_REFUSED_MESSAGE = "Resource not accessible by integration"
# diagnose_403: unauthenticated GitHub requests, at most one per 70 seconds.
DIAG_UNAUTH_GAP_SECONDS = 70.0
DIAG_MAX_IDS = 5
# Weekly run (Jon, 2026-11-12): requests made WITHOUT the token, to confirm that an
# ID has no global-database entry and to retry a repository advisory refused for the
# token. One per 70 seconds, stopping at the first rate-limit answer, resumed across
# runs; at most this long per run, then the rest wait for the next run.
UNAUTH_GAP_SECONDS = 70.0
UNAUTH_BUDGET_SECONDS = 45 * 60
UNAUTH_RECHECK_DAYS = 30
NOT_IN_GLOBAL_DATABASE = "GitHub's global advisory database has no entry for this ID"
GITHUB_STOP_BELOW = 50  # stop GitHub lookups when fewer requests than this remain
SAMPLE_FINDINGS = 5
