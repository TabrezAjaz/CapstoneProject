"""Prometheus gauges derived only from persisted, validated scan evidence."""
from datetime import datetime

from prometheus_client import CollectorRegistry, Gauge, generate_latest

from .history import HistoryStore


def render_metrics(store: HistoryStore) -> bytes:
    snapshot = store.snapshot()
    registry = CollectorRegistry()
    findings = Gauge("vulnerability_findings", "Active findings in the latest scan", ["image", "severity"], registry=registry)
    gauges = {key: Gauge(name, description, ["image"], registry=registry)
              for key, name, description in (
                  ("blocking", "vulnerability_blocking_findings", "Findings blocking the policy"),
                  ("found", "vulnerability_new_findings", "New CVE/package pairs since previous scan"),
                  ("resolved", "vulnerability_resolved_findings", "CVE/package pairs absent since previous scan"),
                  ("suppressed", "vulnerability_suppressed_findings", "Approved exception finding count"))}
    blocked = Gauge("vulnerability_policy_blocked", "One when latest scan is policy blocked", ["image"], registry=registry)
    timestamp = Gauge("vulnerability_scan_timestamp_seconds", "UTC timestamp of latest scan", ["image"], registry=registry)
    scans = Gauge("vulnerability_scans_stored", "Number of persisted scan artifacts", registry=registry)
    scans.set(len(snapshot["history"]))
    for entry in snapshot["latest"]:
        name = entry["image"]
        for level, count in entry["summary"].items():
            findings.labels(name, level).set(count)
        for key, metric in gauges.items():
            metric.labels(name).set(entry[key])
        blocked.labels(name).set(not entry["passed"])
        timestamp.labels(name).set(datetime.fromisoformat(entry["scanned_at"].replace("Z", "+00:00")).timestamp())
    return generate_latest(registry)