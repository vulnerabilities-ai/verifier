"""Shared test setup: fake Anthropic site, fake Internet Archive, fake policy
host, and a fake clock so retry waits take no real time."""

import csv
import tempfile
import unittest
from pathlib import Path

from fakeserver import FakeArchive, FakeSite, dashboard_routes, policy_routes, snapshot_routes

from verifier import config
from verifier.archive_org import ArchiveClient
from verifier.capture import RunInfo
from verifier.net import Fetcher
from verifier.runner import run

LABELS = config.ANTHROPIC_SNAPSHOT_LABELS


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps: list[float] = []

    def clock(self):
        return self.now

    def sleep(self, s):
        self.sleeps.append(s)
        self.now += s


def files_under(root: Path) -> list[str]:
    cap = root / "captures"
    if not cap.exists():
        return []
    return sorted(p.relative_to(root).as_posix() for p in cap.rglob("*") if p.is_file())


class CaptureCase(unittest.TestCase):
    access_key = None
    secret_key = None

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        routes = dashboard_routes()
        routes.update(snapshot_routes(LABELS))
        self.site = FakeSite(routes)
        self.base = self.site.url + "/2026/cvd/"
        content = {self.base + p[len("/2026/cvd/"):]: r[1]
                   for p, r in routes.items() if p.startswith("/2026/cvd/")}
        self.ia = FakeArchive(content)
        self.policy = FakeSite(policy_routes())
        self.fake = FakeClock()

    def tearDown(self):
        for s in (self.site, self.ia, self.policy):
            s.close()
        self.tmp.cleanup()

    def client(self, fetcher, **kw):
        args = dict(wayback_base=self.ia.url + "/",
                    availability_url=self.ia.url + "/wayback/available",
                    access_key=self.access_key, secret_key=self.secret_key,
                    poll_interval=1, sleep=self.fake.sleep, clock=self.fake.clock)
        args.update(kw)
        return ArchiveClient(fetcher, **args)

    def fetcher(self):
        # The fake Archive stands in for web.archive.org and archive.org, so it
        # is the only destination allowed to receive the (fake) keys.
        return Fetcher(min_interval=0, credential_destinations=frozenset({self.ia.url}))

    def capture(self, mode="normal", base=None, run_id="r1", **client_kw):
        fetcher = self.fetcher()
        return run(self.root, base_url=base or self.base,
                   run=RunInfo(run_id=run_id, trigger="test", mode=mode),
                   fetcher=fetcher, client=self.client(fetcher, **client_kw),
                   policy_url=self.policy.url + "/coordinated-vulnerability-disclosure")

    def log(self):
        with open(self.root / "captures" / "capture-log.csv", encoding="utf-8") as f:
            return list(csv.DictReader(f))


# ---------------------------------------------------------------------------
# Frozen archive: tests never depend on the live archive's growing state
# (more captures, more cards, more appended notes). They copy a fixed set of
# capture folders and a frozen copy of the wolfSSL card with Jon's manual
# manifest, and build into a temporary folder.
# ---------------------------------------------------------------------------
import shutil  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
FIXTURE_CARD = REPO / "tests" / "fixtures" / "wolfssl-card"
WOLF_ID = "ANT-2026-87DJGDRB"
FROZEN_CAPTURE_DIRS = ["captures/2026/10/30", "captures/2026/11/08", "captures/anthropic-archive"]


def frozen_archive(dst: Path) -> Path:
    for rel in FROZEN_CAPTURE_DIRS:
        shutil.copytree(REPO / rel, dst / rel)
    card_dir = dst / "cards" / WOLF_ID
    card_dir.mkdir(parents=True)
    for f in ("card.html", "preimage.json", "MANIFEST.json"):
        shutil.copy(FIXTURE_CARD / f, card_dir / f)
    return dst
