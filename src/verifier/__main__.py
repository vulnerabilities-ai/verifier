"""Command line: python -m verifier <command>

  capture          run one capture (what the daily workflow does)
  audit            check the archive's integrity
  parse-headline   print the published snapshot row for a payload.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import config
from .archive_org import ArchiveClient
from .audit import audit
from .capture import RunInfo
from .net import Fetcher, sha256_hex
from .parse_headline import parse_headline
from .runner import run


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="verifier")
    sub = ap.add_subparsers(dest="cmd", required=True)

    c = sub.add_parser("capture")
    c.add_argument("--root", default=".")
    c.add_argument("--test-base-url", default="",
                   help="Deliberately use a different base address. Test mode: "
                        "nothing is stored except a log row.")
    c.add_argument("--run-id", default="local")
    c.add_argument("--trigger", default="manual")
    c.add_argument("--summary-file", default="",
                   help="Write a plain-language result here (used for failure issues).")

    a = sub.add_parser("audit")
    a.add_argument("--root", default=".")

    h = sub.add_parser("parse-headline")
    h.add_argument("payload")
    h.add_argument("--dashboard", help="dashboard.html, for source_sha256")
    h.add_argument("--capture-utc")

    args = ap.parse_args(argv)

    if args.cmd == "capture":
        test = bool(args.test_base_url.strip())
        base = args.test_base_url.strip() if test else config.BASE_URL
        info = RunInfo(run_id=args.run_id, trigger=args.trigger, mode="test" if test else "normal")
        fetcher = Fetcher()
        # Keys come only from the environment (GitHub Actions secrets). They are
        # handed to the client and never printed, logged or written to a file.
        client = ArchiveClient(fetcher,
                               access_key=os.environ.get("IA_ACCESS_KEY", "").strip() or None,
                               secret_key=os.environ.get("IA_SECRET_KEY", "").strip() or None)
        out = run(Path(args.root), base_url=base, run=info, fetcher=fetcher, client=client)
        lines = [f"Status: {out.status}", f"Internet Archive mode: {client.mode}"]
        lines += [f"- {m}" for m in out.messages]
        lines += [f"- Warning: {w}" for w in out.warnings]
        text = "\n".join(lines) + "\n"
        print(text)
        if os.environ.get("GITHUB_ACTIONS") == "true":
            for w in out.warnings:
                print(f"::warning title=Internet Archive::{w}")
        if args.summary_file:
            Path(args.summary_file).write_text(text, encoding="utf-8")
        return out.exit_code

    if args.cmd == "audit":
        problems = audit(Path(args.root))
        for p in problems:
            print("PROBLEM:", p)
        print("Archive OK" if not problems else f"{len(problems)} problem(s) found")
        return 1 if problems else 0

    if args.cmd == "parse-headline":
        payload = Path(args.payload).read_bytes()
        sha = sha256_hex(Path(args.dashboard).read_bytes()) if args.dashboard else None
        row = parse_headline(payload, capture_utc=args.capture_utc, source_sha256=sha)
        print(json.dumps(row, indent=2))
        return 0
    return 2


if __name__ == "__main__":
    sys.exit(main())
