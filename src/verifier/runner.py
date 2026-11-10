"""One complete capture run, as the daily workflow performs it.

Order:
1. Work out every URL this run will touch, on every host.
2. Read robots.txt for each host and stop if anything is disallowed.
3. Fetch and validate the five dashboard files (all or nothing).
4. Store changed files, the day's manifest and latest.json.
5. Internet Archive: save dashboard, ledger.json and payload.json, with
   retries, availability checks and raw-copy comparison. A failure here is a
   warning ("archive-pending"), not a failed run.
6. Look for later receipts for earlier runs (appended, never overwritten).
7. One-time backfill of Anthropic's snapshots; monthly policy copy.
8. Append one row to captures/capture-log.csv, whatever happened.

Test mode (a deliberately different base address, used to prove that a
failure opens an issue) writes nothing at all except the log row.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin

from . import config
from .archive_diag import MismatchDiagnoser
from .archive_org import ArchiveClient
from .capture import (RunInfo, backfill_due, backfill_one, capture_policy, fetch_targets,
                      policy_due, record_archive_result, snapshot_folder_url, store_daily,
                      target_urls)
from .later_receipts import days_without_receipt, find_later_receipts
from .net import CaptureError, Fetcher, RobotsDisallowed, utc_now
from .store import Archive

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_ROBOTS = 3
EXIT_ARCHIVE_STALE = 4  # capture fine, but no Archive receipt for several days


@dataclass
class Outcome:
    status: str
    exit_code: int
    messages: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    new_files: int = 0
    unchanged_files: int = 0
    archive_snapshot: str | None = None
    days_without_receipt: int = 0


def planned_urls(archive: Archive, base_url: str, test_mode: bool, now: str,
                 client: ArchiveClient, policy_url: str) -> list[str]:
    targets = target_urls(base_url)
    urls = [u for _, u, _ in targets]
    if test_mode:
        return urls
    urls += client.planned_urls([u for n, u, _ in targets if n in config.ARCHIVE_FILES])
    for label in backfill_due(archive):
        folder = snapshot_folder_url(base_url, label)
        urls.append(folder + "index.html")
        urls += [folder + p for p in config.SNAPSHOT_DEFAULT_DATA]
    if policy_due(archive, now):
        urls.append(policy_url)
    return urls


def run(root: Path, *, base_url: str = config.BASE_URL, run: RunInfo | None = None,
        fetcher: Fetcher | None = None, client: ArchiveClient | None = None,
        policy_url: str = config.POLICY_URL) -> Outcome:
    archive = Archive(root)
    run = run or RunInfo()
    fetcher = fetcher or Fetcher()
    client = client or ArchiveClient(fetcher)
    test_mode = run.mode == "test"
    if not test_mode and client.on_mismatch is None:
        client.on_mismatch = MismatchDiagnoser(archive)
    out = _run(archive, fetcher, client, base_url, run, test_mode, policy_url)
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
        "message": " | ".join(out.messages + out.warnings)[:1000],
    })
    return out


def _run(archive, fetcher, client, base_url, run, test_mode, policy_url) -> Outcome:
    # 1-2. robots.txt for every host, before anything else
    try:
        fetcher.check_robots(planned_urls(archive, base_url, test_mode, run.started_utc,
                                          client, policy_url))
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

    # 4. store first, so a slow Archive can never cost us the capture
    stored = store_daily(archive, fetched, run, base_url, fetcher.robots_summary())
    out.new_files = sum(1 for f in stored["files"] if f["newly_stored"])
    out.unchanged_files = len(stored["files"]) - out.new_files
    out.messages.append(f"Captured to {stored['manifest']}")

    # 5. Internet Archive (a warning, never a failed run)
    by_name = {f["name"]: f for f in stored["files"]}
    items = [{"name": n, "url": by_name[n]["url"], "our_fetched_utc": by_name[n]["fetched_utc"],
              "our_sha256": by_name[n]["sha256"]} for n in config.ARCHIVE_FILES]
    try:
        ia = client.archive_items(items)
    except RobotsDisallowed as e:
        ia = {"mode": client.mode, "ok": False, "error": str(e), "items": [
            {**i, "status": "pending"} for i in items]}
        out.status, out.exit_code = "stopped-robots", EXIT_ROBOTS
        out.messages.append(str(e))
    record_archive_result(archive, stored["manifest"], stored["run_index"], run.run_id, ia)
    for it in ia["items"]:
        r = it.get("receipt")
        if r and it["name"] == "dashboard.html":
            out.archive_snapshot = r["snapshot_url"]
        if r and r.get("raw_check", {}).get("result") == "mismatch":
            out.warnings.append(f"The Archive's raw copy of {it['name']} differs from ours "
                                "(recorded in the manifest)")
    if not ia.get("ok") and out.exit_code != EXIT_ROBOTS:
        out.status = "archive-pending"
        out.warnings.append("No Internet Archive receipt yet for: "
                            + ", ".join(ia.get("pending", [])) + ". Later runs will look again.")

    # 6. later receipts for earlier runs
    if out.exit_code != EXIT_ROBOTS:
        try:
            notes = find_later_receipts(archive, client, run.started_utc[:10], skip_run_id=run.run_id)
            if notes:
                out.messages.append(f"Appended {len(notes)} later Archive note(s) to earlier records")
        except RobotsDisallowed as e:
            out.status, out.exit_code = "stopped-robots", EXIT_ROBOTS
            out.messages.append(str(e))
        except CaptureError as e:
            out.warnings.append(f"Late-receipt check did not complete: {e}")
    out.days_without_receipt = days_without_receipt(archive)

    # 7. backfill and policy
    if out.exit_code != EXIT_ROBOTS:
        _backfill_and_policy(archive, fetcher, base_url, run, policy_url, out)

    # A capture problem outranks an Archive warning.
    if out.exit_code == EXIT_OK and out.days_without_receipt >= config.ARCHIVE_STALE_DAYS:
        out.exit_code = EXIT_ARCHIVE_STALE
        out.warnings.append(f"No Internet Archive receipt for {out.days_without_receipt} "
                            "consecutive capture days.")
    return out


def _backfill_and_policy(archive, fetcher, base_url, run, policy_url, out: Outcome) -> None:
    for label in backfill_due(archive):
        try:
            backfill_one(archive, fetcher, base_url, label)
            out.messages.append(f"Backfilled Anthropic snapshot {label}")
        except RobotsDisallowed as e:
            out.status, out.exit_code = "stopped-robots", EXIT_ROBOTS
            out.messages.append(str(e))
            return
        except CaptureError as e:
            out.status, out.exit_code = "ok-with-errors", EXIT_FAILED
            out.messages.append(f"Backfill of {label} failed: {e}")
    if policy_due(archive, run.started_utc):
        try:
            capture_policy(archive, fetcher, policy_url)
            out.messages.append("Saved this month's copy of the disclosure policy page")
        except RobotsDisallowed as e:
            out.status, out.exit_code = "stopped-robots", EXIT_ROBOTS
            out.messages.append(str(e))
        except CaptureError as e:
            out.status, out.exit_code = "ok-with-errors", EXIT_FAILED
            out.messages.append(f"Policy page copy failed: {e}")
