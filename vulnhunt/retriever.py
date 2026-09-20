"""Rank chunks by how likely they are to hold a vulnerability.

Two signals, combined:
  1. Lexical: sink-pattern matches (weighted by severity) + presence of an
     untrusted-input source in the same region (taint proximity).
  2. Semantic (when SIE is up): embed a per-class security query and the chunks,
     rank by similarity, then rerank the top lexical candidates with SIE `score`
     for precision.

Output is a shortlist of candidate regions to fan out over.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional

from .config import LanguageAdapter
from .indexer import Chunk
from .sie_client import SIEClient

_SEV_WEIGHT = {"Critical": 4.0, "High": 3.0, "Medium": 2.0, "Low": 1.0, "Info": 0.5}


@dataclass
class Region:
    """A candidate region handed to an investigator agent."""
    chunk: Chunk
    lexical_score: float
    semantic_score: float
    sink_hits: List[str]        # names of sink patterns matched
    suspected_classes: List[str]
    has_input_source: bool

    @property
    def score(self) -> float:
        # Lexical dominates (it's precise about *where* a sink is); semantic
        # breaks ties and surfaces regions lexical misses. Taint proximity is a
        # strong multiplier -- a sink reachable from input is what we want.
        base = self.lexical_score + 1.5 * self.semantic_score
        return base * (1.6 if self.has_input_source else 1.0)


def _compile(adapters: List[LanguageAdapter]):
    sinks = []
    sources = []
    for a in adapters:
        for sp in a.sink_patterns:
            sinks.append((sp, re.compile(sp.regex, re.I)))
        for src in a.input_sources:
            sources.append(re.compile(src, re.I))
    return sinks, sources


def _lexical(chunk: Chunk, sinks, sources):
    hits, classes, score = [], set(), 0.0
    for sp, rx in sinks:
        n = len(rx.findall(chunk.text))
        if n:
            hits.append(sp.name)
            classes.add(sp.vuln_class)
            score += _SEV_WEIGHT.get(sp.severity_hint, 1.0) * min(n, 3)
    has_input = any(rx.search(chunk.text) for rx in sources)
    return score, hits, sorted(classes), has_input


def retrieve(chunks: List[Chunk], adapters: List[LanguageAdapter], sie: SIEClient,
             top_k: int = 12, semantic_pool: int = 60,
             query: Optional[str] = None) -> List[Region]:
    sinks, sources = _compile(adapters)

    # 1. Lexical pass over every chunk.
    scored: List[Region] = []
    for c in chunks:
        lex, hits, classes, has_input = _lexical(c, sinks, sources)
        if lex <= 0:
            continue
        c.sink_hits = hits
        scored.append(Region(chunk=c, lexical_score=lex, semantic_score=0.0,
                             sink_hits=hits, suspected_classes=classes,
                             has_input_source=has_input))
    scored.sort(key=lambda r: r.lexical_score, reverse=True)

    # 2. Semantic rerank of the lexical shortlist (precision boost when SIE up).
    pool = scored[:semantic_pool]
    if pool and not sie.offline:
        q = query or ("security vulnerability: untrusted external input reaching a "
                      "dangerous sink -- command execution, SQL, path traversal, "
                      "authentication bypass, unsafe deserialization")
        try:
            sem = sie.score(q, [r.chunk.text for r in pool])
            lo, hi = min(sem), max(sem)
            rng = (hi - lo) or 1.0
            for r, s in zip(pool, sem):
                r.semantic_score = (s - lo) / rng
        except Exception as e:      # never let retrieval crash the run
            print(f"[retriever] semantic rerank skipped: {e}")

    ranked = sorted(scored, key=lambda r: r.score, reverse=True)
    return ranked[:top_k]
