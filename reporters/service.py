"""Strict artifact loading, aggregation, and report rendering."""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from jinja2 import Environment, FileSystemLoader, select_autoescape
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from .models import ReportDocument

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


class ReportError(ValueError):
    """Raised for invalid artifacts, formats, or output failures."""


def _validate_artifact(data: Any, path: Path) -> dict[str, Any]:
    if not isinstance(data, dict) or data.get("schema_version") != "1.0":
        raise ReportError(f"Unsupported scan artifact schema: {path}")
    required = ("scan_id", "scanned_at", "image", "summary", "findings", "policy")
    if any(key not in data for key in required):
        raise ReportError(f"Incomplete scan artifact: {path}")
    summary = data["summary"]
    findings = data["findings"]
    if not isinstance(summary, dict) or not isinstance(findings, list):
        raise ReportError(f"Invalid summary or findings: {path}")
    for severity in SEVERITIES:
        if not isinstance(summary.get(severity), int) or summary[severity] < 0:
            raise ReportError(f"Invalid {severity} count: {path}")
    counted = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        severity = str(finding.get("severity", "UNKNOWN")).upper()
        if severity not in counted:
            raise ReportError(f"Invalid finding severity in {path}")
        counted[severity] += 1
    if counted != {severity: summary[severity] for severity in SEVERITIES}:
        raise ReportError(f"Summary does not match findings: {path}")
    return data


def load_artifacts(paths: Iterable[str | Path]) -> list[dict[str, Any]]:
    """Load only explicitly selected, schema-v1 normalized scan artifacts."""
    artifacts = []
    for value in paths:
        path = Path(value)
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ReportError(f"Cannot load scan artifact {path}: {exc}") from exc
        artifacts.append(_validate_artifact(data, path))
    if not artifacts:
        raise ReportError("At least one scan artifact is required")
    return artifacts


def build_document(artifacts: list[dict[str, Any]], period: str = "run",
                   title: str = "Container Vulnerability Report") -> ReportDocument:
    if period not in {"run", "daily", "weekly"}:
        raise ReportError("period must be run, daily, or weekly")
    totals: dict[str, Any] = {severity: 0 for severity in SEVERITIES}
    totals.update({"images": len(artifacts), "findings": 0, "blocking_findings": 0,
                   "passed_images": 0, "blocked_images": 0})
    highest = "UNKNOWN"
    images = []
    for artifact in artifacts:
        for severity in SEVERITIES:
            totals[severity] += artifact["summary"][severity]
            if artifact["summary"][severity] and RANK[severity] > RANK[highest]:
                highest = severity
        totals["findings"] += len(artifact["findings"])
        totals["blocking_findings"] += artifact["policy"]["blocking_findings"]
        key = "passed_images" if artifact["policy"]["passed"] else "blocked_images"
        totals[key] += 1
        copy = dict(artifact)
        copy["findings"] = sorted(artifact["findings"],
                                  key=lambda item: (-RANK[item["severity"]], str(item.get("id", ""))))
        images.append(copy)
    images.sort(key=lambda item: item["image"])
    source = next((item.get("source", {}) for item in artifacts if item.get("source")), {})
    generated = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    return ReportDocument("1.0", str(uuid.uuid4()), generated, period, title, totals,
                          {"highest_severity": highest,
                           "status": "BLOCKED" if totals["blocked_images"] else "PASSED",
                           "summary": f"{totals['images']} images, {totals['findings']} findings"},
                          images, source)


def _atomic_write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
        os.replace(temporary, path)
    except OSError:
        Path(temporary).unlink(missing_ok=True)
        raise


def _render_html(document: ReportDocument) -> bytes:
    environment = Environment(
        loader=FileSystemLoader(Path(__file__).parent / "templates"),
        autoescape=select_autoescape(("html", "xml", "j2")),
    )
    return environment.get_template("report.html.j2").render(document=document).encode("utf-8")


def _render_pdf(document: ReportDocument) -> bytes:
    from io import BytesIO
    buffer = BytesIO()
    styles = getSampleStyleSheet()
    pdf = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=14 * mm, leftMargin=14 * mm,
                            topMargin=14 * mm, bottomMargin=14 * mm,
                            title=document.title, author="Container Vulnerability Scanner")
    story = [Paragraph(document.title, styles["Title"]),
             Paragraph(f"{document.period.title()} report · {document.generated_at}", styles["Normal"]),
             Spacer(1, 8), Paragraph(f"Status: {document.overall['status']}", styles["Heading2"]),
             Paragraph(document.overall["summary"], styles["Normal"])]
    for image in document.images:
        story.extend([PageBreak(), Paragraph(str(image["image"]), styles["Heading1"]),
                      Paragraph(f"Policy: {'PASSED' if image['policy']['passed'] else 'BLOCKED'} · "
                                f"Blocking findings: {image['policy']['blocking_findings']}", styles["Normal"]),
                      Spacer(1, 8)])
        rows = [["Severity", "CVE", "Package", "Installed", "Fixed"]]
        for finding in image["findings"]:
            rows.append([finding["severity"], str(finding.get("id") or ""),
                         str(finding.get("pkg") or ""), str(finding.get("installed") or ""),
                         str(finding.get("fixed") or "Not fixed")])
        if len(rows) == 1:
            rows.append(["-", "No vulnerabilities detected", "", "", ""])
        table = Table(rows, repeatRows=1, colWidths=[20*mm, 33*mm, 42*mm, 35*mm, 35*mm])
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0b5550")),
                                   ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                                   ("GRID", (0, 0), (-1, -1), .4, colors.grey),
                                   ("FONTSIZE", (0, 0), (-1, -1), 7),
                                   ("VALIGN", (0, 0), (-1, -1), "TOP")]))
        story.append(table)
    pdf.build(story)
    return buffer.getvalue()


def generate_reports(document: ReportDocument, formats: Iterable[str], output_dir: str | Path) -> Path:
    """Write selected report formats and a checksum manifest atomically."""
    directory = Path(output_dir)
    slug = f"vulnerability-{document.period}-{document.report_id[:8]}"
    outputs = []
    for name in dict.fromkeys(value.lower().strip() for value in formats):
        if name == "json":
            content, media = json.dumps(document.to_dict(), indent=2).encode("utf-8"), "application/json"
        elif name == "html":
            content, media = _render_html(document), "text/html"
        elif name == "pdf":
            content, media = _render_pdf(document), "application/pdf"
        else:
            raise ReportError(f"Unsupported report format: {name}")
        path = directory / f"{slug}.{name}"
        try:
            _atomic_write(path, content)
        except OSError as exc:
            raise ReportError(f"Cannot write report {path}: {exc}") from exc
        outputs.append({"format": name, "file": path.name, "media_type": media,
                        "size": len(content), "sha256": hashlib.sha256(content).hexdigest()})
    manifest = directory / f"{slug}.manifest.json"
    _atomic_write(manifest, json.dumps({"schema_version": "1.0", "report_id": document.report_id,
                                        "generated_at": document.generated_at,
                                        "outputs": outputs}, indent=2).encode("utf-8"))
    return manifest
