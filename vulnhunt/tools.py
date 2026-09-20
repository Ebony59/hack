"""Tool-runner: the actions an investigator agent (and the verifier) can take
against a target repo. Everything is sandboxed to the repo path, and shell
availability is detected so a missing tool degrades gracefully instead of
crashing the run.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, List, Optional

from .config import LanguageAdapter
from .ids import content_hash, stable_id
from .models import EvidenceRef


class AnalysisTools:
    """Read-only repository navigation for mapping agents.

    All paths are resolved before use, so a symlink in an untrusted repository
    cannot turn a seemingly relative read into a host-file read.
    """
    def __init__(self, repo_path: str, commit: str):
        self.repo_root = Path(repo_path).resolve()
        self.commit = commit
        self.evidence: dict[str, EvidenceRef] = {}

    def _safe(self, relative: str) -> Path | None:
        candidate = Path(relative)
        if candidate.is_absolute():
            return None
        try:
            resolved = (self.repo_root / candidate).resolve(strict=True)
            resolved.relative_to(self.repo_root)
        except (OSError, RuntimeError, ValueError):
            return None
        return resolved

    def _relative(self, path: Path) -> str:
        return path.relative_to(self.repo_root).as_posix()

    def list_files(self, prefix: str = "", max_results: int = 400) -> list[str]:
        base = self._safe(prefix) if prefix else self.repo_root
        if not base or not base.is_dir():
            return []
        results = []
        for path in sorted(base.rglob("*")):
            if path.is_file():
                try:
                    path.resolve().relative_to(self.repo_root)
                except (OSError, ValueError):
                    continue
                results.append(self._relative(path))
                if len(results) >= max_results:
                    break
        return results

    def read_file(self, path: str, start_line: int = 1, end_line: int | None = None) -> str:
        if start_line < 1 or (end_line is not None and end_line < start_line):
            return "[error: invalid line range]"
        full = self._safe(path)
        if not full or not full.is_file():
            return f"[error: no such permitted file {path}]"
        try:
            lines = full.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        except OSError:
            return f"[error: unable to read {path}]"
        end = min(end_line or len(lines), len(lines))
        return "".join(f"{number:5d}| {line}" for number, line in
                       enumerate(lines[start_line - 1:end], start_line))

    def search(self, pattern: str, paths: list[str] | None = None, max_results: int = 40) -> list[str]:
        try:
            expression = re.compile(pattern)
        except re.error as exc:
            return [f"[error: invalid regex: {exc}]"]
        candidates = paths or self.list_files(max_results=10000)
        results = []
        for rel in candidates:
            full = self._safe(rel)
            if not full or not full.is_file():
                continue
            try:
                for number, line in enumerate(full.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                    if expression.search(line):
                        results.append(f"{rel}:{number}: {line[:500]}")
                        if len(results) >= max_results:
                            return results
            except OSError:
                continue
        return results

    def find_symbol(self, name: str) -> list[str]:
        return self.search(rf"(?:fn|struct|enum|trait|impl|class|def|function|const|let)\s+{re.escape(name)}\b")

    def find_references(self, name: str) -> list[str]:
        return self.search(rf"\b{re.escape(name)}\b")

    def read_manifest(self, path: str) -> str:
        return self.read_file(path, 1, 800)

    def git_show(self, path: str, revision: str | None = None) -> str:
        full = self._safe(path)
        if not full:
            return "[error: path escapes repository]"
        revision = revision or self.commit
        try:
            out = subprocess.run(["git", "show", f"{revision}:{self._relative(full)}"], cwd=self.repo_root,
                                 capture_output=True, text=True, timeout=20, check=False)
            return out.stdout[:20000] if out.returncode == 0 else f"[error: git show failed: {out.stderr[:300]}]"
        except OSError as exc:
            return f"[error: git unavailable: {exc}]"

    def git_log(self, path: str, limit: int = 10) -> str:
        full = self._safe(path)
        if not full:
            return "[error: path escapes repository]"
        try:
            out = subprocess.run(["git", "log", f"-n{min(limit, 50)}", "--format=%H %s", "--", self._relative(full)],
                                 cwd=self.repo_root, capture_output=True, text=True, timeout=20, check=False)
            return out.stdout[:10000] if out.returncode == 0 else f"[error: git log failed]"
        except OSError as exc:
            return f"[error: git unavailable: {exc}]"

    def get_evidence(self, path: str, start_line: int, end_line: int, reason: str,
                     symbol: str | None = None) -> EvidenceRef:
        full = self._safe(path)
        if not full or not full.is_file():
            raise ValueError(f"evidence path is outside repository or missing: {path}")
        if start_line < 1 or end_line < start_line:
            raise ValueError("invalid evidence line range")
        lines = full.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        excerpt = "".join(lines[start_line - 1:end_line])
        if not excerpt:
            raise ValueError("evidence line range is empty")
        relative = self._relative(full)
        digest = content_hash(excerpt)
        evidence = EvidenceRef(id=stable_id("evidence", self.commit,
                                       {"path": relative, "start": start_line, "end": end_line, "hash": digest}),
                           repo_commit=self.commit, path=relative, start_line=start_line, end_line=end_line,
                           symbol=symbol, content_hash=digest, reason=reason, excerpt=excerpt[:12000])
        self.evidence[evidence.id] = evidence
        return evidence

    def dispatch(self, tool: str, arguments: dict[str, Any]) -> Any:
        allowed = {"list_files", "read_file", "search", "find_symbol", "find_references", "read_manifest",
                   "git_show", "git_log", "get_evidence"}
        if tool not in allowed:
            raise ValueError(f"tool not allowed for analysis: {tool}")
        return getattr(self, tool)(**arguments)


class ToolRunner:
    def __init__(self, repo_path: str, adapter: LanguageAdapter, cmd_timeout: int = 300):
        self.repo_path = os.path.realpath(repo_path)
        self.adapter = adapter
        self.cmd_timeout = cmd_timeout

    # ----- availability --------------------------------------------------- #
    @staticmethod
    def have(binary: str) -> bool:
        return shutil.which(binary) is not None

    def _safe(self, rel: str) -> Optional[str]:
        """Resolve a repo-relative path, refusing anything outside the repo."""
        if os.path.isabs(rel):
            return None
        full = os.path.realpath(os.path.join(self.repo_path, rel))
        try:
            if os.path.commonpath([self.repo_path, full]) != self.repo_path:
                return None
        except ValueError:
            return None
        return full

    # ----- read ----------------------------------------------------------- #
    def read_file(self, rel: str, start: int = 1, end: Optional[int] = None) -> str:
        full = self._safe(rel)
        if not full or not os.path.isfile(full):
            return f"[error: no such file {rel}]"
        with open(full, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.readlines()
        end = end or len(lines)
        start = max(1, start)
        picked = lines[start - 1:end]
        return "".join(f"{start + i:5d}| {ln}" for i, ln in enumerate(picked))

    # ----- grep ----------------------------------------------------------- #
    def grep(self, pattern: str, max_results: int = 40) -> List[str]:
        """Ripgrep if present, else a Python fallback. Returns 'file:line: text'."""
        if self.have("rg"):
            try:
                out = subprocess.run(
                    ["rg", "-n", "--no-heading", "-S", "-m", str(max_results), pattern, "."],
                    cwd=self.repo_path, capture_output=True, text=True, timeout=60)
                return [l for l in out.stdout.splitlines() if l][:max_results]
            except (subprocess.SubprocessError, OSError):
                pass
        import re
        rx = re.compile(pattern)
        hits: List[str] = []
        for dp, dns, fns in os.walk(self.repo_path):
            dns[:] = [d for d in dns if d not in {".git", "target", "node_modules"}]
            for fn in fns:
                p = os.path.join(dp, fn)
                try:
                    with open(p, "r", encoding="utf-8", errors="replace") as fh:
                        for i, line in enumerate(fh, 1):
                            if rx.search(line):
                                hits.append(f"{os.path.relpath(p, self.repo_path)}:{i}: {line.strip()}")
                                if len(hits) >= max_results:
                                    return hits
                except OSError:
                    continue
        return hits

    # ----- run commands (build / test / lint / custom) -------------------- #
    def run(self, cmd: List[str], timeout: Optional[int] = None) -> dict:
        if not cmd or not self.have(cmd[0]):
            return {"ok": False, "skipped": True, "reason": f"{cmd[0] if cmd else '?'} not installed",
                    "code": None, "stdout": "", "stderr": ""}
        try:
            p = subprocess.run(cmd, cwd=self.repo_path, capture_output=True, text=True,
                               timeout=timeout or self.cmd_timeout)
            return {"ok": p.returncode == 0, "skipped": False, "code": p.returncode,
                    "stdout": p.stdout[-8000:], "stderr": p.stderr[-8000:]}
        except subprocess.TimeoutExpired:
            return {"ok": False, "skipped": False, "reason": "timeout", "code": None,
                    "stdout": "", "stderr": "timed out"}
        except OSError as e:
            return {"ok": False, "skipped": True, "reason": str(e), "code": None,
                    "stdout": "", "stderr": ""}

    def build(self) -> dict:
        return self.run(self.adapter.build_cmd) if self.adapter.build_cmd else \
            {"ok": False, "skipped": True, "reason": "no build command"}

    def test(self) -> dict:
        return self.run(self.adapter.test_cmd) if self.adapter.test_cmd else \
            {"ok": False, "skipped": True, "reason": "no test command"}

    def lint(self) -> dict:
        return self.run(self.adapter.lint_cmd) if self.adapter.lint_cmd else \
            {"ok": False, "skipped": True, "reason": "no lint command"}

    def semgrep(self, config: str = "auto") -> dict:
        if not self.have("semgrep"):
            return {"ok": False, "skipped": True, "reason": "semgrep not installed"}
        return self.run(["semgrep", "--config", config, "--json", "--quiet", "."], timeout=600)
