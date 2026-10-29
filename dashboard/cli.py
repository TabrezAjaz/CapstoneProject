"""Import archived normalized artifacts into durable monitoring history."""
from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path

from reporters.service import ReportError
from .history import HistoryStore
from .metrics import render_metrics


def run(argv=None):
    parser = argparse.ArgumentParser(description="Import normalized scan artifacts; repeated imports are safe")
    parser.add_argument("artifacts", nargs="+")
    parser.add_argument("--database", default="dashboard/data/history.sqlite3")
    parser.add_argument("--metrics-file", help="export current Prometheus gauges as a CI evidence artifact")
    args = parser.parse_args(argv)
    try:
        store = HistoryStore(args.database)
        count = store.ingest(args.artifacts)
        if args.metrics_file:
            destination = Path(args.metrics_file)
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(render_metrics(store))
    except (ReportError, ValueError, OSError, sqlite3.Error) as exc:
        print(f"History ingestion failed: {exc}", file=sys.stderr)
        return 2
    print(f"Imported {count} new scan artifact(s)")
    return 0


if __name__ == "__main__":
    sys.exit(run())