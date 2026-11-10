"""Build the GitHub Pages site and site-data.zip from data/ (after a merge to main).

- Pages carries data/ as the public mirror and citation address. The website
  itself never fetches from Pages at runtime; each reviewed website export
  bundles its own copy, from site-data.zip.
- site-data.zip holds the published files in the layout of the website's
  data-files folder (SITE_DATA_FOLDER) plus MANIFEST.sha256.json.
- Deterministic: entries sorted, fixed timestamps, so the same data gives the
  same zip.
"""

from __future__ import annotations

import hashlib
import json
import shutil
import zipfile
from pathlib import Path

SITE_DATA_FOLDER = "data"  # folder name inside the zip, as the website's export expects
EXCLUDE = {"programs-manual.csv"}  # the hand-kept source; the site uses programs.csv/json
FIXED_TIME = (1980, 1, 1, 0, 0, 0)


def published_files(root: Path) -> list[Path]:
    data = Path(root) / "data"
    return sorted(p for p in data.rglob("*") if p.is_file() and p.name not in EXCLUDE)


def manifest(root: Path, commit: str | None) -> dict:
    data = Path(root) / "data"
    return {"source_commit": commit, "folder": SITE_DATA_FOLDER,
            "files": {f"{SITE_DATA_FOLDER}/{p.relative_to(data).as_posix()}": hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in published_files(root)}}


def build_site(root: Path, out: Path, commit: str | None = None) -> dict:
    root, out = Path(root), Path(out)
    if out.exists():
        shutil.rmtree(out)
    (out / "data").mkdir(parents=True)
    data = root / "data"
    for p in published_files(root):
        dst = out / "data" / p.relative_to(data)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(p, dst)
    man = manifest(root, commit)
    man_bytes = (json.dumps(man, indent=2, sort_keys=True) + "\n").encode()
    (out / "MANIFEST.sha256.json").write_bytes(man_bytes)
    with zipfile.ZipFile(out / "site-data.zip", "w", zipfile.ZIP_DEFLATED) as z:
        for p in published_files(root):
            info = zipfile.ZipInfo(f"{SITE_DATA_FOLDER}/{p.relative_to(data).as_posix()}", FIXED_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, p.read_bytes())
        info = zipfile.ZipInfo("MANIFEST.sha256.json", FIXED_TIME)
        info.compress_type = zipfile.ZIP_DEFLATED
        z.writestr(info, man_bytes)
    links = "\n".join(f'<li><a href="{k}">{k}</a></li>' for k in sorted(man["files"]))
    (out / "index.html").write_text(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>verifier data</title></head><body>"
        "<h1>vulnerabilities.ai verifier: published data</h1>"
        "<p>Open data under CC BY 4.0, mirrored from the main branch after each reviewed merge. "
        "Cite the repository commit for an exact version. Methodology and source: "
        "<a href=\"https://github.com/vulnerabilities-ai/verifier\">github.com/vulnerabilities-ai/verifier</a>.</p>"
        f"<p>Source commit: <code>{commit or 'unknown'}</code>. "
        "<a href=\"site-data.zip\">site-data.zip</a> (the same files, with <a href=\"MANIFEST.sha256.json\">"
        f"SHA-256 manifest</a>).</p><ul>{links}</ul></body></html>\n", encoding="utf-8")
    return man
