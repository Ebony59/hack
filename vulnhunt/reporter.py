"""Emit findings as submission-ready markdown + machine-readable JSON."""
from __future__ import annotations

import json
import os
from typing import List

from .schema import Finding


def _finding_md(f: Finding, idx: int) -> str:
    steps = "\n".join(f"  {i + 1}. {s}" for i, s in enumerate(f.steps)) or "  (see PoC)"
    ev = "\n".join(f"  - {e}" for e in f.evidence) or "  - (none)"
    badge = "VERIFIED" if f.verified else "candidate"
    return f"""### {idx}. {f.title}

- **Project:** {f.target}
- **Severity:** {f.severity}  ({badge}, confidence {f.confidence:.2f})
- **Class:** {f.vuln_class}
- **Location:** `{f.file}:{f.line}`{f' (commit {f.commit})' if f.commit else ''}

**Summary:** {f.summary}

**Steps to reproduce:**
{steps}

**Proof of concept:**
```
{f.poc or '(none provided)'}
```

**Suggested fix:** {f.suggested_fix or '(none)'}

**Evidence:**
{ev}
"""


def write_report(findings: List[Finding], out_dir: str, target: str) -> dict:
    os.makedirs(out_dir, exist_ok=True)
    verified = [f for f in findings if f.verified]
    md = [f"# vulnhunt findings — {target}",
          "",
          f"{len(findings)} finding(s) after verification "
          f"({len(verified)} verified). Sorted by severity.",
          ""]
    for i, f in enumerate(findings, 1):
        md.append(_finding_md(f, i))

    md_path = os.path.join(out_dir, f"findings-{target}.md")
    json_path = os.path.join(out_dir, f"findings-{target}.json")
    with open(md_path, "w") as fh:
        fh.write("\n".join(md))
    with open(json_path, "w") as fh:
        json.dump([f.to_dict() for f in findings], fh, indent=2)
    return {"markdown": md_path, "json": json_path,
            "total": len(findings), "verified": len(verified)}
