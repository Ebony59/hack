"""Deterministic ground-truth test for the safe fixture.

Everything happens inside a temporary directory: an ordinary internal report is
read successfully, while a ``../`` traversal and a symlink that escapes the root
are both rejected. No real secret or out-of-tree file is touched.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from .app import ReportAccessError, read_report

MARKER = "OUTSIDE-MARKER-8f3a1c"


def test_reads_ordinary_internal_report(tmp_path: Path) -> None:
    root = tmp_path / "reports"
    root.mkdir()
    (root / "weekly.txt").write_text("weekly numbers", encoding="utf-8")

    assert read_report(root, "weekly.txt") == "weekly numbers"


def test_rejects_dotdot_traversal(tmp_path: Path) -> None:
    root = tmp_path / "reports"
    root.mkdir()
    (tmp_path / "outside-secret.txt").write_text(MARKER, encoding="utf-8")

    with pytest.raises(ReportAccessError):
        read_report(root, "../outside-secret.txt")


def test_rejects_symlink_escape(tmp_path: Path) -> None:
    root = tmp_path / "reports"
    root.mkdir()
    (tmp_path / "outside-secret.txt").write_text(MARKER, encoding="utf-8")
    # A symlink INSIDE the root that points OUTSIDE it.
    (root / "escape.txt").symlink_to(tmp_path / "outside-secret.txt")

    with pytest.raises(ReportAccessError):
        read_report(root, "escape.txt")
