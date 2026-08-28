"""Canonical report data model shared by every output renderer."""
from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class ReportDocument:
    schema_version: str
    report_id: str
    generated_at: str
    period: str
    title: str
    totals: dict[str, Any]
    overall: dict[str, Any]
    images: list[dict[str, Any]]
    source: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
