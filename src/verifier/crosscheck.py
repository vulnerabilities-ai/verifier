"""Optional cross-check by a non-Anthropic model. OFF until Jon chooses a provider.

When enabled, it would send a model ONLY the evidence bundle for an item that
needs human review (no browsing), and log the model's name and version. The
checker may not come from the party whose program is being checked (no Gemini
on Google programs, no Grok on xAI programs, no Claude on Anthropic programs).

Today: no provider is configured, nothing is sent anywhere, no secret is used.
"""

from __future__ import annotations

import json

PROVIDER: str | None = None  # set only after Jon chooses one

# provider -> operator, used to refuse a checker from the checked program's party
PROVIDER_OPERATORS = {"gemini": "Google", "grok": "xAI", "claude": "Anthropic", "gpt": "OpenAI"}


class CrossCheckDisabled(Exception):
    pass


def evidence_bundle(item_text: str, verification_row: dict | None, links: list[str]) -> dict:
    """Everything a checker may see for one item: the statement and its evidence, nothing else."""
    return {"item": item_text, "verification": verification_row or {}, "links": sorted(set(links)),
            "instructions": "Check only whether the evidence supports the statement. No browsing."}


def allowed(provider: str, program_operator: str) -> bool:
    return PROVIDER_OPERATORS.get(provider.lower()) != program_operator


def run(bundle: dict, program_operator: str, provider: str | None = PROVIDER) -> dict:
    if not provider:
        raise CrossCheckDisabled("The cross-check is off: no provider has been chosen.")
    if not allowed(provider, program_operator):
        raise CrossCheckDisabled(f"{provider} may not check a program run by {program_operator}.")
    raise CrossCheckDisabled(f"Provider {provider} is not implemented yet.")


def dumps(bundle: dict) -> str:
    return json.dumps(bundle, indent=2, ensure_ascii=False)
