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
    for k in ("cards", "lookups", "build", "report", "tests", "audit"):
        rp.add_argument(f"--{k}", default="success", help=f"outcome of the {k} step")
    rp.add_argument("--report-file", default="")
    rp.add_argument("--sample", default="false")
    rp.add_argument("--date", required=True)
    rp.add_argument("--title-out", required=True)
    rp.add_argument("--body-out", required=True)

    rs = sub.add_parser("review-summary", help="write the plain-language tally for the review PR")
    rs.add_argument("--root", default=".")
    rs.add_argument("--cards-summary", default="")
    rs.add_argument("--out", default="")

    rc = sub.add_parser("records", help="look up public records for rules R3 and R4 (network)")
    rc.add_argument("--root", default=".")
    rc.add_argument("--sample-only", default="false", help="true: only 5 findings (wolfSSL first)")
    rc.add_argument("--summary-file", default="")

    rpt = sub.add_parser("report", help="write the weekly review report from data/")
    rpt.add_argument("--root", default=".")
    rpt.add_argument("--date", required=True, help="the run's date, YYYY-MM-DD")
    rpt.add_argument("--out", required=True)
    rpt.add_argument("--sample", default="false")

    st = sub.add_parser("site", help="build the GitHub Pages site and site-data.zip from data/")
    st.add_argument("--root", default=".")
    st.add_argument("--out", required=True)
    st.add_argument("--commit", default="")

    dg = sub.add_parser("diagnose-403", help="try other ways to read GitHub advisories refused for the token")
    dg.add_argument("--root", default=".")
    dg.add_argument("--ids", required=True, help="'auto' (first 5 refused) or comma-separated GHSA IDs (max 5)")
    dg.add_argument("--date", required=True, help="the run's date, YYYY-MM-DD")
    dg.add_argument("--out", required=True)

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
        outcomes = {k: getattr(args, k) for k in ("cards", "lookups", "build", "report", "tests", "audit")}
        title, body = review_pr(Path(args.root), outcomes, args.date, cards_fetch,
                                report_file=args.report_file or None, sample=args.sample == "true")
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

    if args.cmd == "records":
        from .build import latest_ledger
        from .build.phase3 import finding_inputs
        from .build.sources import Sources
        from .cards import write_verifications
        from .records import RecordFetcher, run_lookups
        root = Path(args.root)
        ledger_rel, revealed = latest_ledger(Sources(root))
        write_verifications(root, revealed, ledger_rel)  # card facts give the fix links
        entries = {e["ant_id"]: e for e in Sources(root).load_json_file(ledger_rel)
                   if e.get("reveal_tier") == "revealed" and e.get("ant_id")} if ledger_rel else {}
        # The workflow's built-in token only (no other secret); sent only to api.github.com.
        rf = RecordFetcher(root, token=os.environ.get("GITHUB_TOKEN") or None)
        tally = run_lookups(root, finding_inputs(root, entries), rf, sample_only=args.sample_only == "true")
        text = json.dumps(tally, indent=2)
        print(text)
        if args.summary_file:
            Path(args.summary_file).write_text(text, encoding="utf-8")
        return 0

    if args.cmd == "report":
        from .report import weekly_report
        text = weekly_report(Path(args.root), args.date, sample=args.sample == "true")
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print(f"Wrote {out}")
        return 0

    if args.cmd == "site":
        from .sitepub import build_site
        man = build_site(Path(args.root), Path(args.out), args.commit or None)
        print(f"Built {args.out}: {len(man['files'])} data files")
        return 0

    if args.cmd == "diagnose-403":
        from .build import latest_ledger
        from .build.phase3 import finding_inputs
        from .build.sources import Sources
        from .diagnose403 import choose_ids, diagnose, report
        root = Path(args.root)
        src = Sources(root)
        ledger_rel, _ = latest_ledger(src)
        entries = {e["ant_id"]: e for e in src.load_json_file(ledger_rel)
                   if e.get("reveal_tier") == "revealed" and e.get("ant_id")} if ledger_rel else {}
        findings = finding_inputs(root, entries)
        for fid, f in findings.items():
            f["project"] = entries[fid].get("project")
        ids = choose_ids(root, args.ids)
        if not ids:
            print("No GHSA IDs to diagnose.")
            return 1
        # The workflow's built-in token only; sent only to api.github.com.
        results = diagnose(root, ids, findings, token=os.environ.get("GITHUB_TOKEN") or None)
        text = report(results, args.date)
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
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
