"""Tool-runner: the actions an investigator agent (and the verifier) can take
against a target repo. Everything is sandboxed to the repo path, and shell
availability is detected so a missing tool degrades gracefully instead of
crashing the run.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from typing import List, Optional

from .config import LanguageAdapter


class ToolRunner:
    def __init__(self, repo_path: str, adapter: LanguageAdapter, cmd_timeout: int = 300):
        self.repo_path = os.path.abspath(repo_path)
        self.adapter = adapter
        self.cmd_timeout = cmd_timeout

    # ----- availability --------------------------------------------------- #
    @staticmethod
    def have(binary: str) -> bool:
        return shutil.which(binary) is not None

    def _safe(self, rel: str) -> Optional[str]:
        """Resolve a repo-relative path, refusing anything outside the repo."""
        full = os.path.abspath(os.path.join(self.repo_path, rel))
        if not (full == self.repo_path or full.startswith(self.repo_path + os.sep)):
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
