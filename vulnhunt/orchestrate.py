"""End-to-end pipeline + CLI.

    conda activate hack
    python -m vulnhunt.orchestrate --target snare
    python -m vulnhunt.orchestrate --target snare --offline        # no SIE needed
    python -m vulnhunt.orchestrate --all --top 15 --concurrency 6

The reasoning engine is SIE. This module only wires the stages together:
index -> retrieve -> fan out SIE investigators -> verify -> aggregate -> report.
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from typing import List

from .aggregator import aggregate
from .config import Target, load_config
from .indexer import index_target
from .investigator import investigate
from .reporter import write_report
from .retriever import retrieve
from .schema import Finding
from .sie_client import SIEClient
from .tools import ToolRunner


def run_target(cfg, target: Target, sie: SIEClient, args) -> List[Finding]:
    repo_path = cfg.abs_path(target)
    if not os.path.isdir(repo_path):
        print(f"[!] target path not found: {repo_path}")
        return []
    adapters = target.adapters()
    print(f"\n=== {target.name}  ({repo_path}) ===")

    t0 = time.time()
    chunks = index_target(repo_path, target, adapters)
    print(f"[index]     {len(chunks)} chunks")

    regions = retrieve(chunks, adapters, sie, top_k=args.top)
    print(f"[retrieve]  {len(regions)} candidate regions")
    for r in regions[:args.top]:
        print(f"            {r.score:6.2f}  {r.chunk.location():40} "
              f"{','.join(r.suspected_classes)}")

    # The verifier/tool-runner uses the first adapter for build/test/lint.
    tools = ToolRunner(repo_path, adapters[0])
    candidates = investigate(regions, sie, tools, notes=target.notes,
                             concurrency=args.concurrency)
    print(f"[investigate] {len(candidates)} candidate finding(s)")

    from .verifier import verify
    survivors = verify(candidates, adapters[0], tools, run_semgrep=args.semgrep)
    print(f"[verify]    {len(survivors)} survived the gate")

    findings = aggregate(survivors)
    report = write_report(findings, args.out, target.name)
    print(f"[report]    {report['total']} finding(s), {report['verified']} verified "
          f"-> {report['markdown']}  ({time.time() - t0:.1f}s)")
    return findings


def main(argv=None):
    ap = argparse.ArgumentParser(description="vulnhunt: SIE-driven vuln discovery")
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--targets-file", default=os.path.join(here, "targets.yaml"))
    ap.add_argument("--repos-root", "--repo-root", dest="repos_root", default=None,
                    help="folder that CONTAINS the target repos (else "
                         "$VULNHUNT_REPOS_ROOT or config.local.yaml)")
    ap.add_argument("--target", help="name of a single target to scan")
    ap.add_argument("--all", action="store_true", help="scan every configured target")
    ap.add_argument("--sie-url", default=None, help="SIE base URL (default $SIE_URL or :8080)")
    ap.add_argument("--offline", action="store_true", help="force offline fallbacks (no SIE)")
    ap.add_argument("--top", type=int, default=12, help="candidate regions per target")
    ap.add_argument("--concurrency", type=int, default=4, help="SIE agents in flight")
    ap.add_argument("--semgrep", action="store_true", help="run semgrep in the verifier")
    ap.add_argument("--out", default=os.path.join(here, "..", "out"))
    args = ap.parse_args(argv)

    cfg = load_config(args.targets_file, repos_root=args.repos_root)
    print(f"[config] {len(cfg.targets)} target(s): "
          + ", ".join(f"{t.name}[{','.join(t.languages) or '?'}]" for t in cfg.targets))
    sie = SIEClient(base_url=args.sie_url, offline=(True if args.offline else None))

    # Legacy scanner compatibility: do not mistake an unreachable SIE service
    # for a clean security scan. The staged CLI is the supported workflow.
    if not args.offline:
        preflight = sie.preflight({"encode", "score", "generate"})
        if not preflight.ok:
            print("[sie] preflight failed; refusing legacy scan.")
            for check in preflight.checks:
                print(f"       {'ok' if check.ok else 'FAIL'} {check.capability}: {check.detail}")
            return 1

    if args.target:
        targets = [cfg.target(args.target)]
    else:
        # No --target: scan every repo in the configured list (that's the point
        # of the repos: list). --all is kept as an explicit synonym.
        targets = cfg.targets
    if not targets:
        print("No targets configured. Add a `repos:` list to config.local.yaml.")
        return 2

    all_findings: List[Finding] = []
    for t in targets:
        all_findings.extend(run_target(cfg, t, sie, args))

    print(f"\n[done] {len(all_findings)} total finding(s) across {len(targets)} target(s). "
          f"Reports in {os.path.abspath(args.out)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
