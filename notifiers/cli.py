"""Slack notification CLI for canonical report JSON."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .slack import NotificationError, RANK, send_slack


def run(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Send a vulnerability report summary to Slack")
    parser.add_argument("report", help="canonical JSON report")
    parser.add_argument("--alert-on", default=os.environ.get("NOTIFICATION_ALERT_ON", "HIGH"))
    parser.add_argument("--always", action="store_true", help="send even below threshold")
    args = parser.parse_args(argv)
    try:
        document = json.loads(Path(args.report).read_text(encoding="utf-8"))
        threshold = args.alert_on.upper()
        if threshold not in RANK or threshold == "UNKNOWN":
            raise NotificationError("alert_on must be LOW, MEDIUM, HIGH, or CRITICAL")
        if not args.always and document.get("period") == "run" and RANK[document["overall"]["highest_severity"]] < RANK[threshold]:
            print("Notification skipped: report is below alert threshold")
            return 0
        webhook = os.environ.get("SLACK_WEBHOOK_URL", "")
        if not webhook:
            raise NotificationError("SLACK_WEBHOOK_URL is required")
        result = send_slack(webhook, document)
        print(f"Slack notification delivered in {result['attempts']} attempt(s)")
        return 0
    except (OSError, json.JSONDecodeError, KeyError, NotificationError) as exc:
        print(f"Notification error: {exc}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(run())
