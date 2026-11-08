"""Command line: python -m verifier <command>

  capture          run one capture (what the daily workflow does)
  audit            check the archive's integrity
  parse-headline   print the published snapshot row for a payload.json
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import config
from .audit import audit
from .capture import RunInfo
from .net import sha256_hex
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
        out = run(Path(args.root), base_url=base, run=info)
        text = f"Status: {out.status}\n" + "\n".join(f"- {m}" for m in out.messages) + "\n"
        print(text)
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
