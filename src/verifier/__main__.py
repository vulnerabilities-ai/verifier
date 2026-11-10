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

    cd = sub.add_parser("cards", help="fetch new or due finding cards (network)")
    cd.add_argument("--root", default=".")
    cd.add_argument("--summary-file", default="")

    b = sub.add_parser("build", help="rebuild data/ and cards/*/verification.json (no network)")
    b.add_argument("--root", default=".")

    rp = sub.add_parser("review-pr", help="write the review pull request's title and description")
    rp.add_argument("--root", default=".")
    rp.add_argument("--cards-summary", default="")
    for k in ("cards", "build", "tests", "audit"):
        rp.add_argument(f"--{k}", default="success", help=f"outcome of the {k} step")
    rp.add_argument("--date", required=True)
    rp.add_argument("--title-out", required=True)
    rp.add_argument("--body-out", required=True)

    rs = sub.add_parser("review-summary", help="write the plain-language tally for the review PR")
    rs.add_argument("--root", default=".")
    rs.add_argument("--cards-summary", default="")
    rs.add_argument("--out", default="")

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

    if args.cmd == "cards":
        from .build import latest_ledger
        from .build.sources import Sources
        from .cards import fetch_cards
        from .net import RobotsDisallowed
        _, revealed = latest_ledger(Sources(Path(args.root)))
        try:
            tally = fetch_cards(Path(args.root), revealed, Fetcher())
            code = 0
        except RobotsDisallowed as e:
            tally, code = {"stopped": str(e)}, 3
        text = json.dumps(tally, indent=2)
        print(text)
        if args.summary_file:
            Path(args.summary_file).write_text(text, encoding="utf-8")
        return code

    if args.cmd == "build":
        from .build import build
        r = build(Path(args.root))
        print(json.dumps({"generated_utc": r["generated_utc"], "rows": r["rows"], "cards": r["cards"]}, indent=2))
        return 0

    if args.cmd == "review-pr":
        from .review import review_pr
        cards_fetch = (json.loads(Path(args.cards_summary).read_text(encoding="utf-8"))
                       if args.cards_summary and Path(args.cards_summary).exists() else None)
        outcomes = {k: getattr(args, k) for k in ("cards", "build", "tests", "audit")}
        title, body = review_pr(Path(args.root), outcomes, args.date, cards_fetch)
        Path(args.title_out).write_text(title, encoding="utf-8")
        Path(args.body_out).write_text(body, encoding="utf-8")
        print(title)
        print(body)
        return 0

    if args.cmd == "review-summary":
        from .review import review_summary
        cards_fetch = (json.loads(Path(args.cards_summary).read_text(encoding="utf-8"))
                       if args.cards_summary and Path(args.cards_summary).exists() else None)
        text = review_summary(Path(args.root), cards_fetch)
        if args.out:
            Path(args.out).write_text(text, encoding="utf-8")
        print(text)
        return 0

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
