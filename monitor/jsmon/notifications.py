"""Notification delivery for detected JavaScript changes.

Channels: Telegram (document + caption) and Slack (file upload), preserving
the original jsmon behaviour but modernised:

* the diff is delivered as a compact text summary plus a dashboard link
  (signed snapshot download) instead of a large HTML attachment
* delivery failures are recorded and never roll back stored results
* per-run deduplication prevents repeat alerts for an unchanged asset
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

from .diffing import DiffResult


class NotificationError(Exception):
    pass


@dataclass
class NotificationPayload:
    project_name: str
    asset_url: str
    previous_hash: Optional[str]
    current_hash: str
    previous_size: Optional[int]
    current_size: int
    detected_at: str
    diff: Optional[DiffResult] = None
    dashboard_url: str = ""
    indicators: list = field(default_factory=list)


def _fmt_bytes(n: Optional[int]) -> str:
    if n is None:
        return "n/a"
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.2f} MB"


def build_message(payload: NotificationPayload, *, diff_url: str = "") -> str:
    """Human-readable notification text (Telegram/Slack safe)."""
    delta = None
    if payload.previous_size is not None:
        delta = payload.current_size - payload.previous_size
        pct = (delta / payload.previous_size * 100) if payload.previous_size else 0.0
        size_line = (
            f"{_fmt_bytes(payload.previous_size)} -> {_fmt_bytes(payload.current_size)} "
            f"({delta:+d} B, {pct:+.1f}%)"
        )
    else:
        size_line = f"baseline {_fmt_bytes(payload.current_size)}"

    lines = [
        f"[JSMon] JavaScript change detected",
        f"Project: {payload.project_name}",
        f"Asset: {payload.asset_url}",
        f"Hash: {(payload.previous_hash or 'baseline')[:16]} -> {payload.current_hash[:16]}",
        f"Size: {size_line}",
        f"Detected: {payload.detected_at}",
    ]

    if payload.diff is not None:
        d = payload.diff
        lines.append(
            f"Diff: +{d.added_lines} / -{d.removed_lines} lines "
            f"({d.old_lines} -> {d.new_lines} total)"
        )

    if payload.indicators:
        high = [i for i in payload.indicators if getattr(i, "severity", "") == "high"]
        cats = sorted({getattr(i, "category", "other") for i in payload.indicators})
        lines.append(
            f"Review indicators: {len(payload.indicators)} "
            f"({len(high)} high) in {', '.join(cats[:4])}"
        )

    if payload.dashboard_url:
        lines.append(f"Dashboard: {payload.dashboard_url}")
    if diff_url:
        lines.append(f"Snapshot: {diff_url}")

    return "\n".join(lines)


class Notifier:
    """Sends change notifications and records delivery outcomes."""

    def __init__(
        self,
        *,
        telegram_enabled: bool = False,
        telegram_token: str = "",
        telegram_chat_id: str = "",
        slack_enabled: bool = False,
        slack_token: str = "",
        slack_channel_id: str = "",
        dashboard_url: str = "",
        timeout: float = 20.0,
    ):
        self.telegram_enabled = telegram_enabled
        self.telegram_token = telegram_token
        self.telegram_chat_id = telegram_chat_id
        self.slack_enabled = slack_enabled
        self.slack_token = slack_token
        self.slack_channel_id = slack_channel_id
        self.dashboard_url = dashboard_url.rstrip("/")
        self.timeout = timeout
        # (channel, asset_id, current_hash) already notified in this process.
        self._sent: set[tuple] = set()

    @property
    def enabled(self) -> bool:
        return self.telegram_enabled or self.slack_enabled

    # ------------------------------------------------------------------
    def notify(
        self,
        payload: NotificationPayload,
        *,
        asset_id: str,
        diff_url: str = "",
    ) -> dict[str, str]:
        """Send to every configured channel. Returns per-channel status."""
        results: dict[str, str] = {}

        for channel in ("telegram", "slack"):
            key = (channel, asset_id, payload.current_hash)
            if key in self._sent:
                results[channel] = "deduplicated"
                continue
            self._sent.add(key)

            try:
                if channel == "telegram" and self.telegram_enabled:
                    self._send_telegram(payload, diff_url)
                elif channel == "slack" and self.slack_enabled:
                    self._send_slack(payload, diff_url)
                else:
                    continue
                results[channel] = "sent"
            except Exception as exc:
                # A failed notification must never break the scan.
                results[channel] = f"failed: {exc}"

        return results

    # ------------------------------------------------------------------
    def test_connection(self, channel: str) -> tuple[bool, str]:
        """Send a small test message. Returns (ok, detail)."""
        try:
            if channel == "telegram":
                self._post_form(
                    f"https://api.telegram.org/bot{self.telegram_token}/sendMessage",
                    {
                        "chat_id": self.telegram_chat_id,
                        "text": "JSMon test notification: configuration is working.",
                    },
                )
                return True, "Telegram test message accepted"
            if channel == "slack":
                self._post_json(
                    "https://slack.com/api/chat.postMessage",
                    {"channel": self.slack_channel_id,
                     "text": "JSMon test notification: configuration is working."},
                    token=self.slack_token,
                )
                return True, "Slack test message accepted"
            return False, f"Unknown channel: {channel}"
        except Exception as exc:
            return False, str(exc)

    # ------------------------------------------------------------------
    def _send_telegram(self, payload: NotificationPayload, diff_url: str) -> None:
        if not (self.telegram_token and self.telegram_chat_id):
            raise NotificationError("Telegram token or chat id missing")

        text = build_message(payload, diff_url)
        url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"

        # Attach the diff as a text file when one is available.
        files: dict[str, tuple] = {}
        data: dict[str, str] = {
            "chat_id": self.telegram_chat_id,
            "caption": text[:1024],
            "parse_mode": "HTML",
        }
        if payload.diff is not None and payload.diff.unified:
            files["document"] = (
                "changes.diff",
                payload.diff.unified.encode("utf-8"),
                "text/plain",
            )

        body, content_type = self._encode_multipart(data, files)
        req = urllib.request.Request(url, data=body, method="POST")
        req.add_header("Content-Type", content_type)
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            result = json.loads(resp.read().decode("utf-8"))
        if not result.get("ok"):
            raise NotificationError(
                f"Telegram API error: {result.get('description', 'unknown')}"
            )

    def _send_slack(self, payload: NotificationPayload, diff_url: str) -> None:
        if not (self.slack_token and self.slack_channel_id):
            raise NotificationError("Slack token or channel missing")

        text = build_message(payload, diff_url)
        channel_id = self.slack_channel_id

        if payload.diff is not None and payload.diff.unified:
            # files.uploadV2 needs a channel id; fall back to chat.postMessage
            # with the diff inline when the upload path is unavailable.
            upload_url = "https://slack.com/api/files.getUploadURLExternal"
            try:
                result = self._post_json(
                    upload_url,
                    {"filename": "changes.diff", "length": len(payload.diff.unified)},
                    token=self.slack_token,
                )
                if result.get("ok"):
                    put_req = urllib.request.Request(
                        result["upload_url"],
                        data=payload.diff.unified.encode("utf-8"),
                        method="POST",
                    )
                    put_req.add_header("Content-Type", "application/octet-stream")
                    with urllib.request.urlopen(put_req, timeout=self.timeout):
                        pass
                    self._post_json(
                        "https://slack.com/api/files.completeUploadExternal",
                        {
                            "files": [{"id": result["file_id"], "title": "JSMon changes"}],
                            "channel_id": channel_id,
                            "initial_comment": text,
                        },
                        token=self.slack_token,
                    )
                    return
            except Exception:
                pass  # fall through to plain message

        self._post_json(
            "https://slack.com/api/chat.postMessage",
            {"channel": channel_id, "text": f"```{text}```"},
            token=self.slack_token,
        )

    # ------------------------------------------------------------------
    def _post_json(self, url: str, payload: dict, *, token: str = "") -> dict:
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        req = urllib.request.Request(
            url, data=json.dumps(payload).encode("utf-8"), headers=headers, method="POST"
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _post_form(self, url: str, payload: dict) -> dict:
        data = urllib.parse.urlencode(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    @staticmethod
    def _encode_multipart(
        fields: dict, files: dict
    ) -> tuple[bytes, str]:
        boundary = "----jsmon-boundary-7f3a91"
        parts: list[bytes] = []

        for name, value in fields.items():
            parts.append(
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                f"{value}\r\n".encode("utf-8")
            )
        for name, (filename, content, mime) in files.items():
            parts.append(
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                f"Content-Type: {mime}\r\n\r\n".encode("utf-8")
            )
            parts.append(content)
            parts.append(b"\r\n")

        parts.append(f"--{boundary}--\r\n".encode("utf-8"))
        return b"".join(parts), f"multipart/form-data; boundary={boundary}"
