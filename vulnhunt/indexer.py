"""Walk a target repo and chunk source files into line-windowed regions with
file/line metadata. Chunks are the unit that gets retrieved and investigated.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Dict, List

from .config import EXCLUDE_DIRS, LanguageAdapter, Target


@dataclass
class Chunk:
    id: str
    target: str
    file: str            # repo-relative path
    start_line: int      # 1-based, inclusive
    end_line: int
    text: str
    language: str
    sink_hits: List[str] = field(default_factory=list)   # filled by retriever
    score: float = 0.0

    def location(self) -> str:
        return f"{self.file}:{self.start_line}-{self.end_line}"


def _iter_source_files(root: str, exts: set) -> List[str]:
    out = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS and not d.startswith(".")]
        for fn in filenames:
            if os.path.splitext(fn)[1] in exts:
                out.append(os.path.join(dirpath, fn))
    return out


def index_target(repo_path: str, target: Target, adapters: List[LanguageAdapter],
                 window: int = 80, overlap: int = 15, max_bytes: int = 400_000) -> List[Chunk]:
    """Return line-windowed chunks across all files matching the target's
    language adapters. `window`/`overlap` are in lines."""
    ext_to_lang: Dict[str, str] = {}
    exts = set()
    for a in adapters:
        for e in a.extensions:
            exts.add(e)
            ext_to_lang[e] = a.name

    chunks: List[Chunk] = []
    for path in _iter_source_files(repo_path, exts):
        try:
            if os.path.getsize(path) > max_bytes:
                continue
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.readlines()
        except OSError:
            continue
        rel = os.path.relpath(path, repo_path)
        lang = ext_to_lang.get(os.path.splitext(path)[1], adapters[0].name)
        step = max(1, window - overlap)
        for start in range(0, max(1, len(lines)), step):
            block = lines[start:start + window]
            if not block:
                break
            text = "".join(block)
            if not text.strip():
                continue
            cid = f"{target.name}:{rel}:{start + 1}"
            chunks.append(Chunk(
                id=cid, target=target.name, file=rel,
                start_line=start + 1, end_line=start + len(block),
                text=text, language=lang,
            ))
            if start + window >= len(lines):
                break
    return chunks
