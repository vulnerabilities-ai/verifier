"""Wording guard (spec: editorial guardrails).

Our own text (the weekly report, review pull request text, and published text
fields) must never label anything "overdue", "late" or "in violation", and must
never state or imply intent, competence or motive. The pipeline reports facts:
"The dashboard states X. Public records show Y."

Verbatim quotations of the program's own words are exempt, because they are
the program's words, not ours: in Markdown they are lines starting with ">",
and in published data they are fields marked as quotations (withheld_statement).
"""

from __future__ import annotations

import re

BANNED = [
    (r"\boverdue\b", "overdue"),
    (r"\blate\b", "late"),
    (r"\bviolat\w*", "violation"),
    (r"\bbreach\w*", "breach"),
    (r"\bdeliberate(ly)?\b", "deliberately"),
    (r"\bintentional(ly)?\b", "intentionally"),
    (r"\bknowingly\b", "knowingly"),
    (r"\bin order to hide\b", "in order to hide"),
    (r"\bconceal\w*", "concealed"),
    (r"\bmisle(d|ad\w*)\b", "misled"),
    (r"\bnegligen\w*", "negligent"),
    (r"\bincompeten\w*", "incompetent"),
    (r"\bfailed to\b", "failed to"),
    (r"\brefused to\b", "refused to"),
    (r"\bcover(ed|ing)? up\b", "covered up"),
    (r"\bdishonest\w*", "dishonest"),
]
_PATTERNS = [(re.compile(p, re.I), word) for p, word in BANNED]

QUOTE_FIELDS = frozenset({"withheld_statement"})


class WordingError(Exception):
    pass


def find(text: str) -> list[str]:
    """Banned terms in our own text. Lines starting with '>' are verbatim quotations."""
    hits = []
    for line in (text or "").splitlines():
        if line.lstrip().startswith(">"):
            continue
        for pat, word in _PATTERNS:
            if pat.search(line):
                hits.append(f"'{word}' in: {line.strip()[:160]}")
    return hits


def check_text(text: str, where: str) -> None:
    hits = find(text)
    if hits:
        raise WordingError(f"Wording guard ({where}): " + "; ".join(hits))


def check_rows(rows: list[dict], where: str) -> None:
    """Check every text value in published rows, except fields that are verbatim quotations."""
    hits = []
    for r in rows:
        for k, v in r.items():
            if k in QUOTE_FIELDS or not isinstance(v, str):
                continue
            hits += [f"{k}: {h}" for h in find(v)]
    if hits:
        raise WordingError(f"Wording guard ({where}): " + "; ".join(hits[:20]))
