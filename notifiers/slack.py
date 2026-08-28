"""Secure Slack incoming-webhook notifications with bounded retry."""
from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable

RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
COLORS = {"CRITICAL": "#b42318", "HIGH": "#e76f00", "MEDIUM": "#d4a000",
          "LOW": "#1976d2", "UNKNOWN": "#64748b"}


class NotificationError(RuntimeError):
    """Raised when notification configuration or delivery fails."""


def validate_webhook(url: str) -> str:
    parsed = urllib.parse.urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname not in {"hooks.slack.com", "hooks.slack-gov.com"}
            or parsed.username or parsed.password or parsed.fragment or parsed.port not in {None, 443}
            or not parsed.path.startswith("/services/")):
        raise NotificationError("SLACK_WEBHOOK_URL is not a valid Slack HTTPS webhook")
    return url


def _clean(value: Any, limit: int = 180) -> str:
    return str(value or "").replace("@channel", "channel").replace("@here", "here")[:limit]


def build_payload(document: dict[str, Any]) -> dict[str, Any]:
    totals = document["totals"]
    severity = document["overall"]["highest_severity"]
    status = document["overall"]["status"]
    cadence = str(document.get("period", "run")).title()
    text = (f"{cadence} container vulnerability report: {status}. "
            f"{totals['images']} images, {totals['CRITICAL']} critical, {totals['HIGH']} high.")
    fields = []
    for image in document["images"][:10]:
        summary = image["summary"]
        fields.append({"type": "mrkdwn", "text":
                       f"*{_clean(image['image'])}*\nC {summary['CRITICAL']} · H {summary['HIGH']} · "
                       f"M {summary['MEDIUM']} · L {summary['LOW']} · "
                       f"{'PASS' if image['policy']['passed'] else 'BLOCKED'}"})
    return {"text": text, "attachments": [{"color": COLORS[severity], "blocks": [
        {"type": "header", "text": {"type": "plain_text", "text": _clean(text, 150)}},
        {"type": "section", "fields": fields or [{"type": "mrkdwn", "text": "No images."}]},
        {"type": "context", "elements": [{"type": "mrkdwn", "text":
         f"Report ID `{_clean(document['report_id'])}` · Generated {_clean(document['generated_at'])}"}]},
    ]}]}


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def send_slack(webhook_url: str, document: dict[str, Any], *, attempts: int = 3,
               timeout: float = 10, opener=None, sleep: Callable[[float], None] = time.sleep,
               jitter: Callable[[], float] = random.random) -> dict[str, Any]:
    """Deliver a bounded Slack payload without exposing the secret URL."""
    url = validate_webhook(webhook_url)
    body = json.dumps(build_payload(document), separators=(",", ":")).encode("utf-8")
    if len(body) > 45_000:
        raise NotificationError("Slack payload exceeds safe size limit")
    client = opener or urllib.request.build_opener(_NoRedirect)
    last = "delivery failed"
    for attempt in range(1, attempts + 1):
        request = urllib.request.Request(url, body, {"Content-Type": "application/json"}, method="POST")
        try:
            with client.open(request, timeout=timeout) as response:
                if 200 <= response.status < 300:
                    return {"delivered": True, "attempts": attempt, "status": response.status}
                last = f"HTTP {response.status}"
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}"
            retryable = exc.code in {408, 425, 429} or exc.code >= 500
            if not retryable:
                raise NotificationError(last) from exc
            retry_after = exc.headers.get("Retry-After") if exc.headers else None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = type(exc).__name__
            retry_after = None
        if attempt < attempts:
            try:
                delay = min(float(retry_after), 10.0) if retry_after else min(2 ** (attempt - 1) + jitter(), 10)
            except (TypeError, ValueError):
                delay = min(2 ** (attempt - 1) + jitter(), 10)
            sleep(delay)
    raise NotificationError(f"Slack delivery failed after {attempts} attempts ({last})")
