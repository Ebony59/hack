"""Token budgeting for the default SIE generation deployments.

SIE advertises an 8192-token sequence window for the default Qwen3.5-4B and
Qwen3.8-27B-FP8 profiles. Their generation output cap is 4096 tokens. Keep
those two limits separate: treating the output cap as the total context window
starves reasoning models before they emit visible output.
"""
from __future__ import annotations

CONTEXT_BUDGET_TOKENS = 8192
GENERATION_RESERVE_TOKENS = 4096


def estimated_tokens(text: str) -> int:
    """Conservative estimate for mixed prose, JSON, and source code.

    The former four-characters-per-token rule undercounted real Qwen prompts
    containing Rust and escaped tool observations by roughly 30–40%.
    """
    return (len(text) * 2 + 4) // 5
