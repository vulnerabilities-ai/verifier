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

# Internet Archive "Save Page Now".
SPN_PREFIX = "https://web.archive.org/save/"

# Politeness: at least this many seconds between requests to the same host.
MIN_INTERVAL_SECONDS = 1.0
TIMEOUT_SECONDS = 60
SPN_TIMEOUT_SECONDS = 180
