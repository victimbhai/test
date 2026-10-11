"""Configuration for the JSMon monitoring engine.

All settings come from environment variables (see .env.example). Nothing
secret is ever written to disk or logged.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Optional


def _bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


def _int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _float(name: str, default: float) -> float:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        return float(raw)
    except ValueError:
        return default


@dataclass
class Settings:
    """Runtime configuration for a scan run."""

    # --- Supabase / PostgREST -------------------------------------------------
    supabase_url: str = field(
        default_factory=lambda: os.environ.get("NEXT_PUBLIC_SUPABASE_URL", "").rstrip("/")
    )
    supabase_secret_key: str = field(
        default_factory=lambda: os.environ.get("SUPABASE_SECRET_KEY", "")
    )
    # Optional direct Postgres connection string. When present the engine uses
    # psycopg instead of PostgREST (preferred: transactional, RLS-bypass-safe).
    database_url: str = field(
        default_factory=lambda: os.environ.get("SUPABASE_DB_URL", "")
    )

    # --- Storage --------------------------------------------------------------
    storage_bucket: str = field(
        default_factory=lambda: os.environ.get("JSMON_STORAGE_BUCKET", "js-snapshots")
    )
    # Signed-URL lifetime in seconds for authenticated snapshot downloads.
    signed_url_ttl: int = field(default_factory=lambda: _int("JSMON_SIGNED_URL_TTL", 900))

    # --- HTTP fetching --------------------------------------------------------
    connect_timeout: float = field(
        default_factory=lambda: _float("JSMON_CONNECT_TIMEOUT", 10.0)
    )
    read_timeout: float = field(
        default_factory=lambda: _float("JSMON_READ_TIMEOUT", 30.0)
    )
    max_bytes: int = field(
        default_factory=lambda: _int("JSMON_MAX_BYTES", 20 * 1024 * 1024)
    )
    max_redirects: int = field(default_factory=lambda: _int("JSMON_MAX_REDIRECTS", 5))
    max_retries: int = field(default_factory=lambda: _int("JSMON_MAX_RETRIES", 2))
    retry_backoff: float = field(
        default_factory=lambda: _float("JSMON_RETRY_BACKOFF", 1.5)
    )
    per_host_min_interval: float = field(
        default_factory=lambda: _float("JSMON_HOST_MIN_INTERVAL", 1.0)
    )
    user_agent: str = field(
        default_factory=lambda: os.environ.get(
            "JSMON_USER_AGENT",
            "JSMonitor/1.0 (+https://github.com/robre/jsmon; authorized security monitoring)",
        )
    )

    # --- Retention ------------------------------------------------------------
    # Number of versions retained per asset. 0 = unlimited.
    max_versions_per_asset: int = field(
        default_factory=lambda: _int("JSMON_MAX_VERSIONS_PER_ASSET", 50)
    )

    # --- Notifications --------------------------------------------------------
    notify_telegram: bool = field(
        default_factory=lambda: _bool("JSMON_NOTIFY_TELEGRAM", False)
    )
    telegram_token: str = field(
        default_factory=lambda: os.environ.get("JSMON_TELEGRAM_TOKEN", "")
    )
    telegram_chat_id: str = field(
        default_factory=lambda: os.environ.get("JSMON_TELEGRAM_CHAT_ID", "")
    )
    notify_slack: bool = field(default_factory=lambda: _bool("JSMON_NOTIFY_SLACK", False))
    slack_token: str = field(
        default_factory=lambda: os.environ.get("JSMON_SLACK_TOKEN", "")
    )
    slack_channel_id: str = field(
        default_factory=lambda: os.environ.get("JSMON_SLACK_CHANNEL_ID", "")
    )
    dashboard_url: str = field(
        default_factory=lambda: os.environ.get("NEXT_PUBLIC_APP_URL", "").rstrip("/")
    )

    # --- Scope ----------------------------------------------------------------
    # Comma-separated allowlist of registrable host suffixes. Empty = no extra
    # restriction beyond the project-level allowlist stored in the database.
    global_host_allowlist: list[str] = field(
        default_factory=lambda: [
            h.strip().lower()
            for h in os.environ.get("JSMON_HOST_ALLOWLIST", "").split(",")
            if h.strip()
        ]
    )

    # --- Run metadata ---------------------------------------------------------
    github_run_id: str = field(
        default_factory=lambda: os.environ.get("GITHUB_RUN_ID", "")
    )
    github_run_number: str = field(
        default_factory=lambda: os.environ.get("GITHUB_RUN_NUMBER", "")
    )
    trigger_type: str = field(
        default_factory=lambda: os.environ.get(
            "JSMON_TRIGGER_TYPE",
            "workflow_dispatch" if _bool("GITHUB_ACTIONS", False) else "manual",
        )
    )
    dry_run: bool = field(default_factory=lambda: _bool("JSMON_DRY_RUN", False))

    @property
    def notifications_configured(self) -> bool:
        if self.notify_telegram and self.telegram_token and self.telegram_chat_id:
            return True
        if self.notify_slack and self.slack_token and self.slack_channel_id:
            return True
        return False

    def validate(self) -> list[str]:
        """Return a list of human-readable configuration problems."""
        problems: list[str] = []
        if not self.supabase_url:
            problems.append("NEXT_PUBLIC_SUPABASE_URL is not set")
        if not (self.supabase_secret_key or self.database_url):
            problems.append(
                "No Supabase credential: set SUPABASE_SECRET_KEY or SUPABASE_DB_URL"
            )
        if self.notify_telegram and not (
            self.telegram_token and self.telegram_chat_id
        ):
            problems.append(
                "JSMON_NOTIFY_TELEGRAM is enabled but JSMON_TELEGRAM_TOKEN / "
                "JSMON_TELEGRAM_CHAT_ID are missing"
            )
        if self.notify_slack and not (self.slack_token and self.slack_channel_id):
            problems.append(
                "JSMON_NOTIFY_SLACK is enabled but JSMON_SLACK_TOKEN / "
                "JSMON_SLACK_CHANNEL_ID are missing"
            )
        return problems

    def redacted_summary(self) -> dict:
        """A log-safe view of the configuration (no secret values)."""
        return {
            "supabase_url": self.supabase_url or "<unset>",
            "storage_bucket": self.storage_bucket,
            "max_bytes": self.max_bytes,
            "timeouts": [self.connect_timeout, self.read_timeout],
            "retries": self.max_retries,
            "max_versions_per_asset": self.max_versions_per_asset,
            "notify_telegram": self.notify_telegram
            and bool(self.telegram_token and self.telegram_chat_id),
            "notify_slack": self.notify_slack
            and bool(self.slack_token and self.slack_channel_id),
            "trigger_type": self.trigger_type,
            "dry_run": self.dry_run,
            "uses_direct_db": bool(self.database_url),
        }


def load_settings() -> Settings:
    return Settings()
