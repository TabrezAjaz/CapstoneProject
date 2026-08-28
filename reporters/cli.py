"""Command-line report generator for normalized scanner artifacts."""
from __future__ import annotations

import argparse
import os
import sys

from .service import ReportError, build_document, generate_reports, load_artifacts


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description="Generate JSON, HTML, and PDF vulnerability reports")
    value.add_argument("artifacts", nargs="+", help="explicit schema-v1 scan artifact paths")
    value.add_argument("--period", choices=("run", "daily", "weekly"), default="run")
    value.add_argument("--formats", default=os.environ.get("REPORT_FORMATS", "json,html,pdf"))
    value.add_argument("--output-dir", default=os.environ.get("REPORT_OUTPUT_DIR", "reports"))
    value.add_argument("--title", default="Container Vulnerability Report")
    return value


def run(argv=None) -> int:
    args = parser().parse_args(argv)
    try:
        artifacts = load_artifacts(args.artifacts)
        document = build_document(artifacts, args.period, args.title)
        manifest = generate_reports(document, args.formats.split(","), args.output_dir)
        print(manifest)
        return 0
    except ReportError as exc:
        print(f"Report error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"Report generation failed: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(run())
