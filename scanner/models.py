"""
Typed data models for scan results.

The core wrapper (`trivy_scanner.py`) returns plain dictionaries so it stays
simple and easy to serialise to JSON. These dataclasses give later sprints
(reporting, dashboard) a typed view of the same data when that is convenient.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import List

SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


@dataclass
class Finding:
    """A single vulnerability found in an image."""
    id: str                 # CVE / advisory identifier, e.g. CVE-2024-1234
    pkg: str                # vulnerable package / library name
    severity: str           # CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
    installed: str          # version currently in the image
    fixed: str = ""         # version that resolves the issue ("" if none)

    @property
    def has_fix(self) -> bool:
        return bool(self.fixed)


@dataclass
class ScanResult:
    """The full result of scanning one image."""
    image: str
    summary: dict = field(default_factory=lambda: {s: 0 for s in SEVERITIES})
    findings: List[Finding] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict) -> "ScanResult":
        """Build a ScanResult from the dict returned by scan_image()."""
        findings = [Finding(**f) for f in data.get("findings", [])]
        return cls(
            image=data.get("image", ""),
            summary=data.get("summary", {s: 0 for s in SEVERITIES}),
            findings=findings,
        )

    @property
    def total(self) -> int:
        return sum(self.summary.values())

    @property
    def blocking(self) -> int:
        """Count of HIGH + CRITICAL findings (used by the CI gate in Sprint 2)."""
        return self.summary.get("HIGH", 0) + self.summary.get("CRITICAL", 0)

    def to_dict(self) -> dict:
        return asdict(self)
