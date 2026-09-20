"""Git-pinned target baseline collection without reading environment secrets."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from .config import Target
from .ids import content_hash, stable_id
from .models import RepositorySnapshot, utc_now


MANIFEST_NAMES = {"Cargo.toml", "package.json", "pyproject.toml", "setup.py", "requirements.txt"}
INSTRUCTION_NAMES = {"AGENTS.md", "CONTRIBUTING.md", "SECURITY.md", "SECURITY.txt"}


def _git(repo: Path, *args: str) -> str | None:
    try:
        out = subprocess.run(["git", *args], cwd=repo, text=True, capture_output=True,
                             timeout=15, check=False)
    except OSError:
        return None
    return out.stdout.strip() if out.returncode == 0 else None


def _tool_version(name: str) -> str:
    binary = shutil.which(name)
    if not binary:
        return "unavailable"
    try:
        out = subprocess.run([binary, "--version"], text=True, capture_output=True,
                             timeout=5, check=False)
        return (out.stdout or out.stderr).splitlines()[0][:200] if out.returncode == 0 else "unavailable"
    except OSError:
        return "unavailable"


def collect_snapshot(target: Target, config_material: str) -> RepositorySnapshot:
    repo = Path(target.path).resolve()
    if not repo.is_dir():
        raise ValueError(f"target repository does not exist: {repo}")
    commit = _git(repo, "rev-parse", "HEAD")
    if not commit:
        raise ValueError(f"target is not a Git repository or has no HEAD: {repo}")
    manifests, package_roots, instructions = [], [], []
    for path in repo.rglob("*"):
        if ".git" in path.parts or not path.is_file():
            continue
        relative = path.relative_to(repo).as_posix()
        if path.name in MANIFEST_NAMES:
            manifests.append(relative)
            package_roots.append(path.parent.relative_to(repo).as_posix() or ".")
        if path.name in INSTRUCTION_NAMES or path.name.lower() in {"readme.md", "architecture.md"}:
            instructions.append(relative)
    harness_root = Path(__file__).resolve().parent.parent
    return RepositorySnapshot(
        target_id=target.name,
        repo_path=str(repo), remote_url=_git(repo, "remote", "get-url", "origin"), commit=commit,
        branch=_git(repo, "branch", "--show-current"), dirty=bool(_git(repo, "status", "--porcelain")),
        languages=target.languages, manifests=sorted(manifests), package_roots=sorted(set(package_roots)),
        instructions=sorted(instructions),
        build_commands=[a.build_cmd for a in target.adapters() if a.build_cmd],
        test_commands=[a.test_cmd for a in target.adapters() if a.test_cmd], created_at=utc_now(),
        harness_commit=_git(harness_root, "rev-parse", "HEAD"), config_hash=content_hash(config_material),
        tool_versions={name: _tool_version(name) for name in ("git", "rg", "cargo", "node", "npm")},
    )


def snapshot_id(snapshot: RepositorySnapshot) -> str:
    return stable_id("snapshot", snapshot.commit, {"target": snapshot.target_id,
                                                      "config": snapshot.config_hash})
