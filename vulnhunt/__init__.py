"""vulnhunt: an autonomous vulnerability-discovery harness.

Pipeline:  index -> retrieve risky regions -> fan out SIE investigator agents
-> extract structured findings -> verify with real tools -> aggregate -> report.

The reasoning engine is Superlinked SIE (self-hosted). This package is only the
orchestration around it: it never reasons about vulnerabilities itself.
"""

__version__ = "0.1.0"
