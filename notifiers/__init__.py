"""Notification providers for vulnerability report summaries."""

from .slack import NotificationError, build_payload, send_slack

__all__ = ["NotificationError", "build_payload", "send_slack"]
