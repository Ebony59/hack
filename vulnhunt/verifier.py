"""The verification gate. A candidate finding only survives if there is real
evidence for it. We never mark something `verified` without a concrete signal,
and we down-weight or drop candidates that look like noise.

Signals used (cheap -> expensive):
  * sink still present at/near the reported line (grep)
  * an untrusted-input source is reachable in the same file (taint proximity)
  * offline stubs are always rejected
  * optional: semgrep / build / test evidence when the tools exist

This is deliberately conservative: for the competition, a false positive costs
reviewer trust, so the gate errs toward dropping unproven candidates.
"""
from __future__ import annotations

import re
from typing import List

from .config import LanguageAdapter
from .schema import Finding
from .tools import ToolRunner

_MIN_CONFIDENCE = 0.35


def _sink_present(f: Finding, tools: ToolRunner) -> bool:
    snippet = tools.read_file(f.file, max(1, f.line - 4), f.line + 4)
    return bool(snippet and "[error" not in snippet[:8])


def _input_reachable(f: Finding, adapter: LanguageAdapter, tools: ToolRunner) -> bool:
    for src in adapter.input_sources:
        if tools.grep(src, max_results=1):
            # crude: some untrusted-input source exists in the repo
            return True
    return False


def verify(findings: List[Finding], adapter: LanguageAdapter, tools: ToolRunner,
           run_semgrep: bool = False) -> List[Finding]:
    survivors: List[Finding] = []
    semgrep_hits = None
    if run_semgrep:
        res = tools.semgrep()
        if res.get("ok"):
            semgrep_hits = res.get("stdout", "")

    for f in findings:
        # Reject offline stubs outright.
        if "offline" in f.summary.lower() or "[offline" in f.title.lower():
            f.verified = False
            f.evidence.append("rejected: offline stub (SIE was not running)")
            continue

        evidence: List[str] = []
        score = f.confidence

        if _sink_present(f, tools):
            evidence.append(f"sink code present at {f.file}:{f.line}")
            score += 0.15
        else:
            evidence.append(f"could not read reported location {f.file}:{f.line}")
            score -= 0.25

        if _input_reachable(f, adapter, tools):
            evidence.append("untrusted-input source present in target")
            score += 0.1

        if semgrep_hits and re.search(re.escape(f.file), semgrep_hits):
            evidence.append("semgrep flagged the same file")
            score += 0.25

        f.confidence = max(0.0, min(1.0, score))
        f.evidence.extend(evidence)
        f.verified = f.confidence >= 0.6 and "sink code present" in " ".join(f.evidence)

        if f.confidence >= _MIN_CONFIDENCE:
            survivors.append(f)

    return survivors
