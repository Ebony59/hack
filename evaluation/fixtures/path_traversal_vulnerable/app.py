"""Report reader.

A tiny application that returns the contents of a named report. It models one
workflow:

    a caller supplies a report filename
        -> the app combines it with a reports directory
        -> the app reads and returns the report

Part of the Vulnhunt evaluation fixtures; the behaviour is exercised only inside
a temporary directory by the accompanying test.
"""
from __future__ import annotations

from pathlib import Path


def read_report(reports_root: Path, requested_name: str) -> str:
    """Return the requested UTF-8 report.

    Args:
        reports_root: Directory that is supposed to contain the reports.
        requested_name: Report name supplied by the caller.

    Returns:
        The decoded contents of the file.

    Raises:
        FileNotFoundError: If the joined path does not exist.
    """
    target = Path(reports_root) / requested_name
    return target.read_text(encoding="utf-8")
