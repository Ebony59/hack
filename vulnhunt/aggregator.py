"""Dedupe findings that share a root cause and rank by severity then confidence."""
from __future__ import annotations

from typing import Dict, List

from .schema import SEVERITY_ORDER, Finding


def aggregate(findings: List[Finding]) -> List[Finding]:
    best: Dict[tuple, Finding] = {}
    for f in findings:
        k = f.key()
        cur = best.get(k)
        if cur is None or _better(f, cur):
            if cur is not None:
                # keep the stronger, note the merge
                f.evidence.append(f"merged {1 + cur.evidence.count('merged')} duplicate region(s)")
            best[k] = f
    merged = list(best.values())
    merged.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), -f.confidence))
    return merged


def _better(a: Finding, b: Finding) -> bool:
    sa, sb = SEVERITY_ORDER.get(a.severity, 9), SEVERITY_ORDER.get(b.severity, 9)
    if sa != sb:
        return sa < sb
    if a.verified != b.verified:
        return a.verified
    return a.confidence > b.confidence
