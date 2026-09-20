"""Tiny end-to-end smoke test -- cheap, ~1-3 SIE calls.

Verifies, in order:
  1. SIE connection (online/offline, auth)
  2. encode  (one short text)
  3. score   (rerank two snippets)
  4. generate (one tiny prompt)  <-- locks the request/response shape
  5. ONE investigator agent on ONE retrieved region of one repo

Each step is isolated: a failure prints a clear message and the rest continue.

    python -m vulnhunt.smoke                       # first configured repo
    python -m vulnhunt.smoke --target snare
    python -m vulnhunt.smoke --offline             # no SIE; exercises plumbing
    python -m vulnhunt.smoke --repos-root /path/to/repos
"""
from __future__ import annotations

import argparse
import os
import sys

from .config import load_config
from .indexer import index_target
from .investigator import investigate
from .retriever import retrieve
from .sie_client import SIEClient
from .tools import ToolRunner


def _ok(label, value=""):
    print(f"  [ok]   {label} {value}")


def _fail(label, err):
    print(f"  [FAIL] {label}: {err}")


def main(argv=None):
    ap = argparse.ArgumentParser(description="vulnhunt smoke test (tiny)")
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--targets-file", default=os.path.join(here, "targets.yaml"))
    ap.add_argument("--repos-root", "--repo-root", dest="repos_root", default=None)
    ap.add_argument("--target", default=None, help="which repo (default: first configured)")
    ap.add_argument("--sie-url", default=None)
    ap.add_argument("--offline", action="store_true")
    args = ap.parse_args(argv)

    failures = []

    print("== 1. SIE connection ==")
    sie = SIEClient(base_url=args.sie_url, offline=(True if args.offline else None))
    print(f"       base={sie.base_url}  generate={sie.generate_url}  "
          f"key={'set' if sie.api_key else 'none'}  offline={sie.offline}")
    print(f"       models: encode={sie.models['encode']}  generate={sie.models['generate']}")

    print("== 2. encode ==")
    try:
        v = sie.encode(["hello, agents"])
        _ok("encode -> dim", len(v[0]))
    except Exception as e:
        _fail("encode", e)
        failures.append("encode")

    print("== 3. score (rerank) ==")
    try:
        s = sie.score("command injection via untrusted input",
                      ["Command::new(user_input).spawn()", "let x = 2 + 2;"])
        _ok("score ->", [round(x, 3) for x in s])
    except Exception as e:
        _fail("score", e)
        failures.append("score")

    print("== 4. generate (tiny) ==")
    try:
        out = sie.generate("Reply with exactly one word: READY", max_new_tokens=8)
        _ok("generate ->", repr((out or "").strip()[:40]))
    except Exception as e:
        _fail("generate", e)
        failures.append("generate")

    print("== 5. one investigator agent on one region ==")
    try:
        cfg = load_config(args.targets_file, repos_root=args.repos_root)
        target = cfg.target(args.target) if args.target else (cfg.targets[0] if cfg.targets else None)
        if not target:
            print("  [skip] no targets configured")
            return 0
        repo = cfg.abs_path(target)
        if not os.path.isdir(repo):
            print(f"  [skip] repo path not found: {repo}")
            return 0
        adapters = target.adapters()
        chunks = index_target(repo, target, adapters)
        regions = retrieve(chunks, adapters, sie, top_k=1)
        print(f"       target={target.name}  chunks={len(chunks)}  region={regions[0].chunk.location() if regions else 'none'}")
        if not regions:
            print("  [skip] no candidate region retrieved")
            return 0
        tools = ToolRunner(repo, adapters[0])
        findings = investigate(regions[:1], sie, tools, notes=target.notes, concurrency=1)
        if findings:
            f = findings[0]
            _ok("agent produced a candidate:", f"{f.severity} {f.vuln_class} @ {f.file}:{f.line}")
        else:
            print("  [ok]   agent ran; no vulnerability claimed for this region")
    except Exception as e:
        _fail("investigator", e)
        failures.append("investigator")

    print("\nSmoke test done.")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
