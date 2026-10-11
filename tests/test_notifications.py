"""Tests for notification payloads, formatting, and deduplication."""

from __future__ import annotations

import pytest

from jsmon.diffing import build_diff
from jsmon.notifications import NotificationPayload, Notifier, build_message

OLD = b'var api = "/api/v1/users";\n'
NEW = b'var api = "/api/v2/users";\nvar t = "sk_live_abcdef1234567890";\n'


def _payload():
    diff = build_diff(OLD, NEW)
    return NotificationPayload(
        project_name="Test Project",
        asset_url="https://example.com/static/app.js",
        previous_hash="a" * 64,
        current_hash="b" * 64,
        previous_size=100,
        current_size=140,
        detected_at="2026-01-01T00:00:00+00:00",
        diff=diff,
        dashboard_url="https://dash.example.com/changes/1",
        indicators=diff.indicators,
    )


def test_message_contains_all_required_fields():
    text = build_message(_payload(), diff_url="https://signed.example/x")
    assert "Test Project" in text
    assert "https://example.com/static/app.js" in text
    assert ("a" * 16) in text
    assert ("b" * 16) in text
    assert "100" in text and "140" in text
    assert "+40" in text
    assert "+40.0%" in text
    assert "2026-01-01" in text
    assert "https://dash.example.com/changes/1" in text
    assert "https://signed.example/x" in text
    assert "Diff:" in text
    assert "Review indicators" in text


def test_message_reports_diff_and_indicators():
    text = build_message(_payload())
    assert "+" in text and "lines" in text
    assert "Review indicators" in text


def test_message_handles_baseline_without_previous_size():
    payload = _payload()
    payload.previous_size = None
    payload.previous_hash = None
    text = build_message(payload)
    assert "baseline" in text.lower()
    # No previous size means the message must not claim a bogus delta.
    assert "n/a" not in text
    assert "Size: baseline" in text


def test_notifier_is_disabled_without_channels():
    notifier = Notifier()
    assert notifier.enabled is False


def test_notifier_dedupes_repeat_alerts():
    calls = []

    class Recording(Notifier):
        def __init__(self):
            super().__init__(dashboard_url="https://dash.test")
            self._telegram = True

        def _send_telegram(self, payload, diff_url):
            calls.append(payload.current_hash)

    notifier = Recording()
    notifier.telegram_enabled = True
    payload = _payload()

    notifier.notify(payload, asset_id="asset-1")
    notifier.notify(payload, asset_id="asset-1")
    assert len(calls) == 1, "an unchanged asset must not alert twice"

    notifier.notify(payload, asset_id="asset-1", diff_url="")
    assert len(calls) == 1


def test_notifier_reports_channel_status():
    class Recording(Notifier):
        def __init__(self):
            super().__init__(dashboard_url="https://dash.test")

        def _send_telegram(self, payload, diff_url):
            return None

        def _send_slack(self, payload, diff_url):
            raise RuntimeError("slack is down")

    notifier = Recording()
    notifier.telegram_enabled = True
    notifier.slack_enabled = True

    results = notifier.notify(_payload(), asset_id="asset-1")
    assert results["telegram"] == "sent"
    assert "failed" in results["slack"]


def test_failed_notification_never_raises():
    class Broken(Notifier):
        def _send_telegram(self, payload, diff_url):
            raise RuntimeError("network exploded")

    notifier = Broken()
    notifier.telegram_enabled = True
    # Must not propagate.
    results = notifier.notify(_payload(), asset_id="asset-1")
    assert "failed" in results["telegram"]


def test_format_bytes():
    from jsmon.notifications import _fmt_bytes

    assert _fmt_bytes(None) == "n/a"
    assert _fmt_bytes(512) == "512 B"
    assert _fmt_bytes(2048) == "2.0 KB"
    assert _fmt_bytes(5 * 1024 * 1024) == "5.00 MB"


def test_multipart_encoding_for_telegram_document():
    body, content_type = Notifier._encode_multipart(
        {"chat_id": "1", "caption": "hello"},
        {"document": ("changes.diff", b"a\nb\n", "text/plain")},
    )
    assert "multipart/form-data" in content_type
    assert b'name="document"' in body
    assert b"changes.diff" in body
    assert b"a\nb\n" in body
