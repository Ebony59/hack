"""Context-window budgeting for the deployed SIE generation endpoint.

The generation endpoint reserves ``prompt + max_new_tokens`` against a fixed
window, so an over-large ``max_new_tokens`` fails the request before the model
runs. The catalogued ``:h100-256k`` / ``:h200-256k`` deployments are not
available on the current key; raise ``CONTEXT_BUDGET_TOKENS`` only after
confirming a larger deployment actually serves generation.
"""
from __future__ import annotations

CONTEXT_BUDGET_TOKENS = 4096
GENERATION_RESERVE_TOKENS = 1400


def estimated_tokens(text: str) -> int:
    """Rough 4-chars-per-token estimate, deliberately conservative."""
    return len(text) // 4
