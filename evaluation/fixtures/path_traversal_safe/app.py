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


class ReportAccessError(Exception):
    """Raised when a requested report resolves outside the reports root."""


def read_report(reports_root: Path, requested_name: str) -> str:
    """Return the requested UTF-8 report.

    Args:
        reports_root: Directory that is supposed to contain the reports.
        requested_name: Report name supplied by the caller.

    Returns:
        The decoded contents of the file.

    Raises:
        ReportAccessError: If the resolved target is outside ``reports_root``.
        FileNotFoundError: If the resolved target does not exist or is not a
            regular file.
    """
    root = Path(reports_root).resolve(strict=True)
    # ``resolve`` follows symlinks, so the real location of the target is
    # compared against the root.
    target = (root / requested_name).resolve()

    if root != target and root not in target.parents:
        raise ReportAccessError(
            f"requested report {requested_name!r} resolves outside the reports root"
        )

    if not target.is_file():
        raise FileNotFoundError(f"no such report: {requested_name!r}")

    return target.read_text(encoding="utf-8")
