"""The fan-out step: for each candidate region, launch an SIE-powered
investigator agent. This is where the competition constraint lives -- the
per-region reasoning runs on SIE-served models, not on Claude/Codex sub-agents.
The harness only orchestrates, feeds tools, and collects structured output.

Each agent runs a small ReAct-style loop:
    think -> optionally request a tool (READ/GREP) -> observe -> repeat
    -> emit a structured Finding candidate (SIE `generate` in JSON mode).
Fan-out is a thread pool; concurrency is the number of SIE agents in flight.
"""
from __future__ import annotations

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Optional

from .retriever import Region
from .schema import FINDING_SCHEMA, Finding, finding_from_extract
from .sie_client import SIEClient
from .tools import ToolRunner

_MAX_STEPS = 3

_SYSTEM = """You are a precise security auditor. You are given one region of source \
code from the project '{target}'. Decide whether it contains a REAL, exploitable \
vulnerability reachable from untrusted input (a network request, webhook, file, \
CLI arg, env var, or message). Do not report style issues or theoretical risks.

Region: {location}   Language: {language}
Sink patterns matched here: {sinks}
Suspected classes: {classes}
Project context: {notes}

You may request tools to confirm data flow. To use a tool, output EXACTLY one line:
  TOOL READ <relative/path> <start_line> <end_line>
  TOOL GREP <regex>
After a tool result you may request another tool or finish. When done, output your
verdict as JSON only.

--- CODE ---
{code}
--- END CODE ---
"""

_TOOL_RE = re.compile(r"^TOOL\s+(READ|GREP)\s+(.*)$", re.M)


def _run_agent(region: Region, sie: SIEClient, tools: ToolRunner, notes: str) -> Optional[Finding]:
    c = region.chunk
    prompt = _SYSTEM.format(
        target=c.target, location=c.location(), language=c.language,
        sinks=", ".join(region.sink_hits) or "none",
        classes=", ".join(region.suspected_classes) or "unknown",
        notes=(notes or "").strip()[:400],
        code=c.text[:6000],
    )

    transcript = prompt
    for _ in range(_MAX_STEPS):
        reply = sie.generate(transcript, max_new_tokens=768, temperature=0.0)
        m = _TOOL_RE.search(reply)
        if not m:
            break  # model went straight to a verdict
        kind, arg = m.group(1), m.group(2).strip()
        obs = _dispatch_tool(kind, arg, tools)
        transcript += f"\n{reply.strip()}\nTOOL RESULT:\n{obs[:3000]}\n"

    # Force a structured verdict.
    data = sie.generate_json(transcript, FINDING_SCHEMA, max_new_tokens=768)
    finding = finding_from_extract(c.target, c.file, c.id, data or {})
    if finding and not finding.line:
        finding.line = c.start_line
    return finding


def _dispatch_tool(kind: str, arg: str, tools: ToolRunner) -> str:
    if kind == "READ":
        parts = arg.split()
        path = parts[0]
        start = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 1
        end = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else start + 60
        return tools.read_file(path, start, end)
    if kind == "GREP":
        return "\n".join(tools.grep(arg)) or "[no matches]"
    return "[unknown tool]"


def investigate(regions: List[Region], sie: SIEClient, tools: ToolRunner,
                notes: str = "", concurrency: int = 4) -> List[Finding]:
    """Fan out one SIE investigator per region; collect candidate findings."""
    findings: List[Finding] = []
    if not regions:
        return findings
    with ThreadPoolExecutor(max_workers=max(1, concurrency)) as pool:
        futs = {pool.submit(_run_agent, r, sie, tools, notes): r for r in regions}
        for fut in as_completed(futs):
            r = futs[fut]
            try:
                f = fut.result()
            except Exception as e:      # one agent failing must not sink the run
                print(f"[investigator] {r.chunk.location()} failed: {e}")
                continue
            if f:
                # carry a lexical/taint prior into the finding's confidence
                if r.has_input_source:
                    f.confidence = min(1.0, f.confidence + 0.1)
                findings.append(f)
                print(f"[investigator] candidate: {f.severity:8} {f.vuln_class:20} "
                      f"{f.file}:{f.line}")
    return findings
