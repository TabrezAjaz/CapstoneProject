"""Validated, idempotent scan ingestion and historical comparisons."""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from reporters.service import SEVERITIES, ReportError, load_artifacts


def utc_timestamp(value: str) -> str:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError("timezone required")
        return parsed.astimezone(timezone.utc).isoformat(timespec="microseconds")
    except (ValueError, AttributeError) as exc:
        raise ValueError("Timestamp must be ISO 8601 with a timezone") from exc


def finding_keys(artifact: dict[str, Any], severity: str | None = None) -> set[tuple[str, str]]:
    return {(str(item.get("id", "")), str(item.get("pkg", "")))
            for item in artifact["findings"] + artifact.get("suppressed_findings", [])
            if severity is None or item["severity"] == severity}


class HistoryStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as connection:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("""CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY, image TEXT NOT NULL,
                scanned_at TEXT NOT NULL, payload TEXT NOT NULL)""")
            connection.execute("CREATE INDEX IF NOT EXISTS scans_image_time ON scans(image, scanned_at)")

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=15)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def ingest(self, paths: Iterable[str | Path]) -> int:
        artifacts = load_artifacts(paths)
        inserted = 0
        with self.connect() as connection:
            for artifact in artifacts:
                if not isinstance(artifact["scan_id"], str) or not artifact["scan_id"].strip():
                    raise ReportError("scan_id must be a non-empty string")
                if not isinstance(artifact["image"], str) or not artifact["image"].strip():
                    raise ReportError("image must be a non-empty string")
                timestamp = utc_timestamp(artifact["scanned_at"])
                payload = json.dumps(artifact, sort_keys=True)
                existing = connection.execute("SELECT payload FROM scans WHERE scan_id = ?",
                                              (artifact["scan_id"],)).fetchone()
                if existing:
                    if existing["payload"] != payload:
                        raise ReportError("A scan_id cannot be reused with different content")
                    continue
                connection.execute("INSERT INTO scans VALUES (?, ?, ?, ?)",
                                   (artifact["scan_id"], artifact["image"], timestamp, payload))
                inserted += 1
        return inserted

    def detail(self, scan_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT payload FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
        return json.loads(row["payload"]) if row else None

    def snapshot(self, image: str = "", start: str = "", end: str = "",
                 severity: str = "") -> dict[str, Any]:
        if severity and severity not in SEVERITIES:
            raise ValueError("Unknown severity")
        start = utc_timestamp(start) if start else ""
        end = utc_timestamp(end) if end else ""
        if start and end and start > end:
            raise ValueError("Start must be before end")
        with self.connect() as connection:
            images = [row[0] for row in connection.execute("SELECT DISTINCT image FROM scans ORDER BY image")]
            rows = connection.execute(
                "SELECT scanned_at, payload FROM scans WHERE (? = '' OR image = ?) "
                "AND (? = '' OR scanned_at <= ?) ORDER BY scanned_at, scan_id",
                (image, image, end, end)).fetchall()
        previous: dict[str, Any] = {}
        latest: dict[str, Any] = {}
        history = []
        for row in rows:
            artifact = json.loads(row["payload"])
            name = artifact["image"]
            prior = previous.get(name)
            if not start or row["scanned_at"] >= start:
                current_keys = finding_keys(artifact, severity or None)
                prior_keys = finding_keys(prior, severity or None) if prior else set()
                summary = artifact["summary"]
                entry = {
                    "scan_id": artifact["scan_id"], "image": name,
                    "scanned_at": artifact["scanned_at"], "summary": summary,
                    "pending": summary[severity] if severity else sum(summary.values()),
                    "found": len(current_keys - prior_keys),
                    "resolved": len(prior_keys - current_keys),
                    "baseline": prior is None,
                    "blocking": artifact["policy"]["blocking_findings"],
                    "passed": artifact["policy"]["passed"],
                    "suppressed": sum(1 for item in artifact.get("suppressed_findings", [])
                                      if not severity or item["severity"] == severity),
                }
                history.append(entry)
                latest[name] = entry
            previous[name] = artifact
        current = sorted(latest.values(), key=lambda item: (-item["blocking"], item["image"]))
        totals = {key: sum(item[key] for item in current)
                  for key in ("pending", "found", "resolved", "blocking", "suppressed")}
        totals.update({"images": len(current), "blocked_images": sum(not item["passed"] for item in current)})
        summary = {level: sum(item["summary"][level] for item in current) for level in SEVERITIES}
        return {"images": images, "totals": totals, "summary": summary, "latest": current,
                "history": history, "filters": {"image": image, "start": start, "end": end, "severity": severity}}