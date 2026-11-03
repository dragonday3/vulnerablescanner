"""Shared candidate shape for all three Phase 6 misconfiguration check
families (`header_checks.py`, `exposed_service_checks.py`,
`tls_inspector.py`).

A `MisconfigCandidate` is a detection result that hasn't been persisted
yet -- it carries everything `analyzer.py` (Task 4) needs to build a
`Misconfiguration` row, but owns no DB session and knows nothing about
`service_id`. Keeping all three check families return this same shape
lets the analyzer treat them uniformly regardless of which family
produced a given candidate.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MisconfigCandidate:
    check_id: str
    title: str
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"
    description: str
    evidence: dict
