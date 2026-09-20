"""Deterministic repository inventory: useful evidence, never a security conclusion."""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import re

from .config import EXCLUDE_DIRS, Target
from .models import EvidenceRef, RepositorySnapshot
from .tools import AnalysisTools


ENTRY_PATTERNS = {
    "rust": re.compile(r"(?:fn\s+main\b|Router::|route\(|webhook|TcpListener|Command::new)"),
    "js": re.compile(r"(?:runtime\.onMessage|addEventListener|express\(|fetch\(|chrome\.)"),
    "ts": re.compile(r"(?:runtime\.onMessage|addEventListener|express\(|fetch\(|chrome\.)"),
    "python": re.compile(r"(?:def\s+main\b|app\.route|FastAPI\(|Flask\()"),
}


def build_inventory(target: Target, snapshot: RepositorySnapshot, tools: AnalysisTools) -> dict:
    repo = Path(snapshot.repo_path)
    counts: Counter[str] = Counter()
    files, entry_candidates, docs, tests, generated = [], [], [], [], []
    extension_lang = {ext: adapter.name for adapter in target.adapters() for ext in adapter.extensions}
    for path in sorted(repo.rglob("*")):
        if not path.is_file() or any(part in EXCLUDE_DIRS or part.startswith(".") for part in path.parts):
            continue
        rel = path.relative_to(repo).as_posix()
        files.append(rel)
        language = extension_lang.get(path.suffix)
        if language:
            counts[language] += 1
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                text = ""
            if ENTRY_PATTERNS.get(language, re.compile("$^")).search(text):
                entry_candidates.append(rel)
        lowered = rel.lower()
        if any(term in lowered for term in ("readme", "security", "contributing", "architecture", "docs/")):
            docs.append(rel)
        if any(term in lowered for term in ("test", "spec", "fixture")):
            tests.append(rel)
        if any(term in lowered for term in ("generated", "vendor", "third_party", "target/")):
            generated.append(rel)
    hints = {"input_sources": [x for adapter in target.adapters() for x in adapter.input_sources],
             "sinks": [sink.name for adapter in target.adapters() for sink in adapter.sink_patterns]}
    return {"schema_version": 1, "target_id": target.name, "commit": snapshot.commit,
            "files": files, "language_counts": dict(counts), "manifests": snapshot.manifests,
            "instructions": snapshot.instructions, "entry_point_candidates": entry_candidates,
            "documentation": docs, "test_paths": tests, "generated_or_vendor_paths": generated,
            "lexical_hints": hints, "limitations": ["Candidates are convention-based inventory hints, not conclusions."]}
