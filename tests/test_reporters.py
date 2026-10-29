import json
from pathlib import Path

import pytest

from reporters.service import ReportError, build_document, generate_reports, load_artifacts

FIXTURES = Path(__file__).parent / "fixtures"


def test_load_and_aggregate_versioned_artifacts():
    artifacts = load_artifacts([FIXTURES / "normalized-scan-v1.json", FIXTURES / "normalized-clean-v1.json"])
    document = build_document(artifacts, "daily")
    assert document.totals["images"] == 2
    assert document.totals["findings"] == 2
    assert document.totals["blocking_findings"] == 2
    assert document.overall["status"] == "BLOCKED"


def test_rejects_raw_or_inconsistent_artifacts(tmp_path):
    with pytest.raises(ReportError, match="Unsupported"):
        load_artifacts([FIXTURES / "trivy-fail.json"])
    invalid = json.loads((FIXTURES / "normalized-scan-v1.json").read_text())
    invalid["summary"]["HIGH"] = 9
    path = tmp_path / "bad.json"
    path.write_text(json.dumps(invalid))
    with pytest.raises(ReportError, match="does not match"):
        load_artifacts([path])


def test_generates_matching_json_html_and_pdf(tmp_path):
    document = build_document(load_artifacts([FIXTURES / "normalized-scan-v1.json"]))
    manifest_path = generate_reports(document, ["json", "html", "pdf"], tmp_path)
    manifest = json.loads(manifest_path.read_text())
    assert {item["format"] for item in manifest["outputs"]} == {"json", "html", "pdf"}
    pdf = next(tmp_path.glob("*.pdf")).read_bytes()
    html = next(tmp_path.glob("*.html")).read_text()
    report_json = json.loads(next(path for path in tmp_path.glob("*.json") if not path.name.endswith("manifest.json")).read_text())
    assert pdf.startswith(b"%PDF-")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert report_json["report_id"] == document.report_id == manifest["report_id"]


def test_unknown_format_fails(tmp_path):
    document = build_document(load_artifacts([FIXTURES / "normalized-clean-v1.json"]))
    with pytest.raises(ReportError, match="Unsupported report format"):
        generate_reports(document, ["docx"], tmp_path)
