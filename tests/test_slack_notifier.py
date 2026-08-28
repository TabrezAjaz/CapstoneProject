import urllib.error
from pathlib import Path

import pytest

from notifiers.slack import NotificationError, build_payload, send_slack, validate_webhook
from reporters.service import build_document, load_artifacts

FIXTURES = Path(__file__).parent / "fixtures"


class Response:
    status = 200
    def __enter__(self): return self
    def __exit__(self, *args): return False


class Opener:
    def __init__(self, effects): self.effects = iter(effects); self.calls = 0
    def open(self, request, timeout):
        self.calls += 1
        effect = next(self.effects)
        if isinstance(effect, Exception): raise effect
        return effect


def document():
    return build_document(load_artifacts([FIXTURES / "normalized-scan-v1.json"])).to_dict()


@pytest.mark.parametrize("url", ["http://hooks.slack.com/services/a/b/c", "https://example.com/services/a",
                                  "https://user:pass@hooks.slack.com/services/a", "https://hooks.slack.com:444/services/a"])
def test_rejects_unsafe_webhooks(url):
    with pytest.raises(NotificationError): validate_webhook(url)


def test_payload_has_severity_style_and_no_mentions():
    value = document()
    value["images"][0]["image"] = "@channel app"
    payload = build_payload(value)
    assert payload["attachments"][0]["color"] == "#b42318"
    assert "@channel" not in str(payload)


def test_delivery_success():
    opener = Opener([Response()])
    result = send_slack("https://hooks.slack.com/services/a/b/c", document(), opener=opener)
    assert result == {"delivered": True, "attempts": 1, "status": 200}


def test_retries_transient_error_without_leaking_url():
    error = urllib.error.HTTPError("secret", 429, "rate", {"Retry-After": "0"}, None)
    opener = Opener([error, Response()])
    sleeps = []
    result = send_slack("https://hooks.slack.com/services/a/b/c", document(), opener=opener, sleep=sleeps.append)
    assert result["attempts"] == 2 and sleeps == [0.0]


def test_does_not_retry_client_error():
    error = urllib.error.HTTPError("secret", 400, "bad", {}, None)
    with pytest.raises(NotificationError, match="HTTP 400"):
        send_slack("https://hooks.slack.com/services/a/b/c", document(), opener=Opener([error]))
