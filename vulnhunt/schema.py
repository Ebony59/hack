"""The Finding data model and the JSON schema SIE's `extract`/`generate` fills."""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from typing import List, Optional

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}


@dataclass
class Finding:
    target: str
    title: str
    vuln_class: str
    severity: str                      # Critical | High | Medium | Low
    file: str                          # repo-relative
    line: int
    summary: str
    steps: List[str] = field(default_factory=list)
    poc: str = ""
    suggested_fix: str = ""
    commit: str = ""
    confidence: float = 0.0            # 0..1, harness-assigned
    verified: bool = False
    evidence: List[str] = field(default_factory=list)  # what confirmed/weakened it
    region_id: str = ""                # which retrieved region produced it

    def key(self) -> tuple:
        """Dedup key: same root cause == same file + class + nearby line."""
        return (self.target, self.file, self.vuln_class, self.line // 15)

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)


# JSON schema handed to SIE `extract` (output_schema) or embedded in a generate
# prompt so the model returns a well-formed candidate finding.
FINDING_SCHEMA = {
    "type": "object",
    "properties": {
        "is_vulnerability": {"type": "boolean",
                             "description": "true only if untrusted input can reach the sink exploitably"},
        "title": {"type": "string"},
        "vuln_class": {"type": "string"},
        "severity": {"type": "string", "enum": ["Critical", "High", "Medium", "Low", "Info"]},
        "line": {"type": "integer", "description": "1-based line of the sink"},
        "summary": {"type": "string", "description": "the flaw and why it matters, 2-3 sentences"},
        "data_flow": {"type": "string", "description": "how untrusted input reaches the sink"},
        "steps": {"type": "array", "items": {"type": "string"}},
        "poc": {"type": "string", "description": "payload, request, or failing test"},
        "suggested_fix": {"type": "string"},
        "confidence": {"type": "number", "description": "0..1"},
    },
    "required": ["is_vulnerability", "vuln_class", "severity", "summary"],
}


def finding_from_extract(target: str, file: str, region_id: str, data: dict) -> Optional[Finding]:
    """Build a Finding from a model's structured output, or None if it decided
    there is no vulnerability."""
    if not data or not data.get("is_vulnerability"):
        return None
    return Finding(
        target=target,
        title=data.get("title") or f"{data.get('vuln_class', 'issue')} in {file}",
        vuln_class=data.get("vuln_class", "unknown"),
        severity=data.get("severity", "Low"),
        file=file,
        line=int(data.get("line") or 0),
        summary=data.get("summary", ""),
        steps=list(data.get("steps") or []),
        poc=data.get("poc", ""),
        suggested_fix=data.get("suggested_fix", ""),
        confidence=float(data.get("confidence") or 0.5),
        region_id=region_id,
        evidence=([f"data-flow: {data['data_flow']}"] if data.get("data_flow") else []),
    )
