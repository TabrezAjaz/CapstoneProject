import copy
import json
from pathlib import Path

import pytest
from prometheus_client.parser import text_string_to_metric_families

from dashboard.app import create_app
from dashboard.history import HistoryStore
from dashboard.cli import run as import_history
from reporters.service import ReportError

FIXTURE = Path(__file__).parent / "fixtures" / "normalized-scan-v1.json"


def write_scan(tmp_path, scan_id, timestamp, findings=None):
    artifact = json.loads(FIXTURE.read_text())
    artifact.update(scan_id=scan_id, scanned_at=timestamp)
    if findings is not None:
        artifact["findings"] = findings
        artifact["summary"] = {key: sum(item["severity"] == key for item in findings)
                               for key in artifact["summary"]}
        blocking = artifact["summary"]["HIGH"] + artifact["summary"]["CRITICAL"]
        artifact["policy"].update(blocking_findings=blocking, passed=blocking == 0)
    path = tmp_path / f"{scan_id}.json"
    path.write_text(json.dumps(artifact))
    return path


def test_history_is_persistent_idempotent_and_rejects_reused_id(tmp_path):
    database = tmp_path / "history.sqlite3"
    store = HistoryStore(database)
    assert store.ingest([FIXTURE]) == 1
    assert HistoryStore(database).ingest([FIXTURE]) == 0
    data = json.loads(FIXTURE.read_text())
    data["image"] = "different:1"
    path = tmp_path / "conflict.json"
    path.write_text(json.dumps(data))
    with pytest.raises(ReportError, match="reused"):
        store.ingest([path])
    assert store.snapshot()["totals"]["images"] == 1


def test_equal_counts_can_have_new_and_resolved_vulnerabilities(tmp_path):
    store = HistoryStore(tmp_path / "history.sqlite3")
    data = json.loads(FIXTURE.read_text())
    newer = copy.deepcopy(data["findings"])
    newer[0]["id"] = "CVE-NEW"
    first = write_scan(tmp_path, "first", "2026-10-28T10:00:00Z")
    second = write_scan(tmp_path, "second", "2026-10-29T10:00:00Z", newer)
    store.ingest([second, first])
    snapshot = store.snapshot(start="2026-10-29T00:00:00Z")
    assert snapshot["totals"]["pending"] == 2
    assert snapshot["totals"]["found"] == 1
    assert snapshot["totals"]["resolved"] == 1
    assert snapshot["latest"][0]["baseline"] is False
    assert len(snapshot["history"]) == 1
    assert store.snapshot(severity="HIGH")["totals"]["found"] == 0
    assert store.snapshot(image="' OR 1=1 --")["latest"] == []


def test_import_batch_rolls_back_on_invalid_timestamp(tmp_path):
    store = HistoryStore(tmp_path / "history.sqlite3")
    path = write_scan(tmp_path, "invalid", "not-a-date")
    with pytest.raises(ValueError):
        store.ingest([FIXTURE, path])
    assert store.snapshot()["history"] == []


def test_read_only_api_filters_and_metrics(tmp_path):
    app = create_app(tmp_path / "history.sqlite3")
    app.extensions["history"].ingest([FIXTURE])
    client = app.test_client()
    assert client.get("/healthz").json == {"status": "ok"}
    assert client.get("/api/overview?severity=HIGH").json["totals"]["pending"] == 1
    assert client.get("/api/overview?severity=INVALID").status_code == 400
    assert client.get("/api/overview?start=invalid").status_code == 400
    assert client.get("/api/overview?start=2026-10-29T00:00:00Z&end=2026-10-28T00:00:00Z").status_code == 400
    assert client.get("/api/scans/missing").status_code == 404
    assert client.post("/api/overview").status_code == 405
    response = client.get("/metrics")
    metrics = {sample.name: sample for family in text_string_to_metric_families(response.text)
               for sample in family.samples}
    assert metrics["vulnerability_blocking_findings"].value == 2
    assert metrics["vulnerability_policy_blocked"].value == 1
    assert metrics["vulnerability_scans_stored"].value == 1
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]


def test_suppression_is_not_misreported_as_remediation(tmp_path):
    store = HistoryStore(tmp_path / "history.sqlite3")
    first = write_scan(tmp_path, "before", "2026-10-28T10:00:00Z")
    second = write_scan(tmp_path, "after", "2026-10-29T10:00:00Z", [])
    raw = json.loads(first.read_text())
    approved = json.loads(second.read_text())
    approved["raw_summary"] = raw["summary"]
    approved["suppressed_findings"] = [{**finding, "exception": {
        "id": finding["id"], "reason": "Approved risk", "expires": "2027-01-01"}}
        for finding in raw["findings"]]
    second.write_text(json.dumps(approved))
    store.ingest([first, second])
    totals = store.snapshot()["totals"]
    assert totals["pending"] == 0
    assert totals["suppressed"] == 2
    assert totals["resolved"] == 0


def test_dashboard_page_and_local_assets(tmp_path):
    client = create_app(tmp_path / "history.sqlite3").test_client()
    page = client.get("/")
    assert page.status_code == 200
    assert b"Security overview" in page.data
    for path in ("dashboard.js", "dashboard.css", "vendor/chart.umd.js", "vendor/lucide.min.js"):
        assert client.get("/static/" + path).status_code == 200


def test_ci_metrics_export_and_invalid_artifact_exit_code(tmp_path):
    database = str(tmp_path / "history.sqlite3")
    metrics = tmp_path / "metrics.prom"
    assert import_history([str(FIXTURE), "--database", database, "--metrics-file", str(metrics)]) == 0
    assert b'vulnerability_blocking_findings{image="example/app:1"} 2.0' in metrics.read_bytes()
    assert import_history([str(tmp_path / "missing.json"), "--database", database]) == 2