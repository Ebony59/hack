"""Deterministic ground-truth test for the vulnerable fixture.

The test demonstrates the known-bad behaviour entirely inside a temporary
directory: it plants a harmless marker file *outside* the reports root and
shows that ``read_report`` can be tricked into reading it via ``../``. No real
secret and no file outside the temporary tree is ever touched.
"""
from __future__ import annotations

from pathlib import Path

from .app import read_report

MARKER = "OUTSIDE-MARKER-8f3a1c"


def test_reads_ordinary_internal_report(tmp_path: Path) -> None:
    root = tmp_path / "reports"
    root.mkdir()
    (root / "weekly.txt").write_text("weekly numbers", encoding="utf-8")

    assert read_report(root, "weekly.txt") == "weekly numbers"


def test_traversal_reads_outside_marker(tmp_path: Path) -> None:
    root = tmp_path / "reports"
    root.mkdir()
    # A harmless marker file that lives OUTSIDE the reports root.
    (tmp_path / "outside-secret.txt").write_text(MARKER, encoding="utf-8")

    # The vulnerability: "../outside-secret.txt" escapes the reports root.
    leaked = read_report(root, "../outside-secret.txt")

    assert leaked == MARKER
