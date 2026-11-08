"""One complete capture run, as the daily workflow performs it.

Order:
1. Work out every URL this run will touch, on every host.
2. Read robots.txt for each host and stop if anything is disallowed.
3. Fetch and validate the five dashboard files (all or nothing).
4. Ask the Internet Archive to save the dashboard.
5. Store changed files, the day's manifest, latest.json.
6. One-time backfill of Anthropic's snapshots; monthly policy copy.
7. Append one row to captures/capture-log.csv, whatever happened.

Test mode (a deliberately different base address, used to prove that a
failure opens an issue) writes nothing at all except the log row.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin

from . import config
from .capture import (RunInfo, backfill_due, backfill_one, capture_policy, fetch_targets,
                      policy_due, save_page_now, snapshot_folder_url, store_daily,
                      target_urls)
from .net import CaptureError, Fetcher, RobotsDisallowed, utc_now
from .store import Archive

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_ROBOTS = 3


@dataclass
class Outcome:
    status: str
    exit_code: int
    messages: list[str] = field(default_factory=list)
    new_files: int = 0
    unchanged_files: int = 0
    archive_snapshot: str | None = None


def planned_urls(archive: Archive, base_url: str, test_mode: bool, now: str,
                 spn_prefix: str, policy_url: str) -> list[str]:
    urls = [u for _, u, _ in target_urls(base_url)]
    if test_mode:
        return urls
    urls.append(spn_prefix + urljoin(base_url, ""))
    for label in backfill_due(archive):
        folder = snapshot_folder_url(base_url, label)
        urls.append(folder + "index.html")
        urls += [folder + p for p in config.SNAPSHOT_DEFAULT_DATA]
    if policy_due(archive, now):
        urls.append(policy_url)
    return urls


def run(root: Path, *, base_url: str = config.BASE_URL, run: RunInfo | None = None,
        fetcher: Fetcher | None = None, spn_prefix: str = config.SPN_PREFIX,
        policy_url: str = config.POLICY_URL, spn_retry_wait: float = 15.0) -> Outcome:
    archive = Archive(root)
    run = run or RunInfo()
    fetcher = fetcher or Fetcher()
    test_mode = run.mode == "test"
    out = _run(archive, fetcher, base_url, run, test_mode, spn_prefix, policy_url, spn_retry_wait)
    if test_mode:
        out.status = "failed-test" if out.exit_code else "passed-test"
    archive.append_log({
        "run_utc": run.started_utc,
        "finished_utc": utc_now(),
        "run_id": run.run_id,
        "trigger": run.trigger,
        "mode": run.mode,
        "status": out.status,
        "base_url": base_url,
        "new_files": out.new_files,
        "unchanged_files": out.unchanged_files,
        "archive_snapshot": out.archive_snapshot,
        "message": " | ".join(out.messages)[:1000],
    })
    return out


def _run(archive, fetcher, base_url, run, test_mode, spn_prefix, policy_url, spn_retry_wait) -> Outcome:
    # 1-2. robots.txt for every host, before anything else
    try:
        robots = fetcher.check_robots(
            planned_urls(archive, base_url, test_mode, run.started_utc, spn_prefix, policy_url))
    except RobotsDisallowed as e:
        return Outcome("stopped-robots", EXIT_ROBOTS, [str(e)])
    except CaptureError as e:
        return Outcome("failed", EXIT_FAILED, [str(e)])

    # 3. fetch and validate all five files
    try:
        fetched = fetch_targets(fetcher, base_url)
    except RobotsDisallowed as e:
        return Outcome("stopped-robots", EXIT_ROBOTS, [str(e)])
    except CaptureError as e:
        return Outcome("failed", EXIT_FAILED, [str(e)])

    if test_mode:
        return Outcome("passed-test", EXIT_OK,
                       ["Test mode: fetched successfully; nothing stored."])

    out = Outcome("ok", EXIT_OK)

    # 4. Internet Archive
    ia = save_page_now(fetcher, urljoin(base_url, ""), spn_prefix, spn_retry_wait)
    if ia["ok"]:
        out.archive_snapshot = ia["snapshot_url"]
    else:
        out.status, out.exit_code = "ok-archive-failed", EXIT_FAILED
        out.messages.append(f"Internet Archive save failed: {ia.get('error')}")

    # 5. store
    stored = store_daily(archive, fetched, run, base_url, fetcher.robots_summary(), ia)
    out.new_files = sum(1 for f in stored["files"] if f["newly_stored"])
    out.unchanged_files = len(stored["files"]) - out.new_files
    out.messages.insert(0, f"Captured to {stored['manifest']}")

    # 6. backfill and policy
    for label in backfill_due(archive):
        try:
            backfill_one(archive, fetcher, base_url, label)
            out.messages.append(f"Backfilled Anthropic snapshot {label}")
        except RobotsDisallowed as e:
            out.status, out.exit_code = "stopped-robots", EXIT_ROBOTS
            out.messages.append(str(e))
            return out
        except CaptureError as e:
            out.status, out.exit_code = "ok-with-errors", max(out.exit_code, EXIT_FAILED)
            out.messages.append(f"Backfill of {label} failed: {e}")
    if policy_due(archive, run.started_utc):
        try:
            capture_policy(archive, fetcher, policy_url)
            out.messages.append("Saved this month's copy of the disclosure policy page")
        except RobotsDisallowed as e:
            out.status, out.exit_code = "stopped-robots", EXIT_ROBOTS
            out.messages.append(str(e))
        except CaptureError as e:
            out.status, out.exit_code = "ok-with-errors", max(out.exit_code, EXIT_FAILED)
            out.messages.append(f"Policy page copy failed: {e}")
    if out.exit_code == EXIT_FAILED and out.status == "ok":
        out.status = "ok-with-errors"
    return out
