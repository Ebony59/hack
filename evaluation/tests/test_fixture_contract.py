"""Fixture behaviour tests driven from the evaluation package.

Covers required cases:
  1. the vulnerable fixture reads the harmless outside marker through '../'
  2. the safe fixture reads an ordinary internal report
  3. the safe fixture rejects '../' traversal
  4. the safe fixture rejects a symlink pointing outside the root

These import the fixture apps directly (unique subpackage names) so both
`app.py` modules coexist, and use only temporary directories.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from evaluation.fixtures.path_traversal_safe.app import (
    ReportAccessError,
    read_report as read_report_safe,
)
from evaluation.fixtures.path_traversal_vulnerable.app import (
    read_report as read_report_vulnerable,
)

MARKER = "OUTSIDE-MARKER-8f3a1c"


def _make_root(tmp_path: Path) -> Path:
    root = tmp_path / "reports"
    root.mkdir()
    (tmp_path / "outside-secret.txt").write_text(MARKER, encoding="utf-8")
    return root


def test_vulnerable_reads_outside_marker_via_dotdot(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    assert read_report_vulnerable(root, "../outside-secret.txt") == MARKER


def test_safe_reads_internal_report(tmp_path: Path) -> None:
    root = tmp_path / "reports"
    root.mkdir()
    (root / "weekly.txt").write_text("weekly numbers", encoding="utf-8")
    assert read_report_safe(root, "weekly.txt") == "weekly numbers"


def test_safe_rejects_dotdot(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    with pytest.raises(ReportAccessError):
        read_report_safe(root, "../outside-secret.txt")


def test_safe_rejects_symlink_escape(tmp_path: Path) -> None:
    root = _make_root(tmp_path)
    (root / "escape.txt").symlink_to(tmp_path / "outside-secret.txt")
    with pytest.raises(ReportAccessError):
        read_report_safe(root, "escape.txt")


def test_fixtures_share_the_same_interface() -> None:
    import inspect

    sig_safe = inspect.signature(read_report_safe)
    sig_vuln = inspect.signature(read_report_vulnerable)
    assert list(sig_safe.parameters) == list(sig_vuln.parameters) == [
        "reports_root",
        "requested_name",
    ]
