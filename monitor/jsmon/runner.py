"""The scan runner — the refactored core of jsmon.py.

Original flow (jsmon.py ``main``):

    for each endpoint in targets/:
        download -> md5 -> compare with jsmon.json -> save/notify

Problems that flow had for cloud execution:

* state lived in a local ``jsmon.json`` file (lost between runners)
* snapshots were written to the runner's ``downloads/`` directory (ephemeral)
* the run aborted when no notification channel was configured
* no timeouts, no size limits, no retries, no redirect validation
* a failed download looked identical to "unchanged"
* no notion of a scan run, error isolation, or partial success

This runner keeps the same conceptual loop but makes every step durable:
targets come from Supabase, snapshots go to private object storage, results
and change events are written to Postgres, and each asset is isolated so one
failure never aborts the scan.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from . import ssrf
from .config import Settings, load_settings
from .database import AssetRow, Store, build_store
from .diffing import build_diff, change_summary
from .fetcher import AssetFetcher, FetchError, build_fetcher_from_settings
from .notifications import NotificationPayload, Notifier
from .storage import SnapshotStore

LOG = logging.getLogger("jsmon.runner")

_TERMINAL_RUNNING = "running"


@dataclass
class AssetOutcome:
    asset_id: str
    url: str
    status: str  # "baseline" | "unchanged" | "changed" | "error"
    detail: str = ""
    http_status: Optional[int] = None
    new_hash: Optional[str] = None
    old_hash: Optional[str] = None
    size: Optional[int] = None
    previous_size: Optional[int] = None
    version_id: Optional[str] = None
    previous_version_id: Optional[str] = None
    indicators: list = field(default_factory=list)
    change_event_id: Optional[str] = None


@dataclass
class ScanReport:
    run_id: str
    status: str = "running"
    assets_checked: int = 0
    changes_detected: int = 0
    baselines_created: int = 0
    errors_count: int = 0
    started_at: str = ""
    completed_at: str = ""
    outcomes: list[AssetOutcome] = field(default_factory=list)
    error_summary: str = ""

    @property
    def final_status(self) -> str:
        if self.assets_checked == 0 and self.errors_count > 0:
            return "failed"
        if self.errors_count == 0:
            return "success"
        if self.assets_checked > 0:
            return "partial"
        return "failed"

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "status": self.status,
            "assets_checked": self.assets_checked,
            "changes_detected": self.changes_detected,
            "baselines_created": self.baselines_created,
            "errors_count": self.errors_count,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "error_summary": self.error_summary,
            "outcomes": [
                {
                    "asset_id": o.asset_id,
                    "url": o.url,
                    "status": o.status,
                    "detail": o.detail,
                    "http_status": o.http_status,
                    "new_hash": o.new_hash,
                    "old_hash": o.old_hash,
                }
                for o in self.outcomes
            ],
        }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ScanRunner:
    """Executes one monitoring pass over the enabled assets."""

    def __init__(
        self,
        *,
        settings: Optional[Settings] = None,
        store: Optional[Store] = None,
        fetcher: Optional[AssetFetcher] = None,
        snapshots: Optional[SnapshotStore] = None,
        notifier: Optional[Notifier] = None,
    ):
        self.settings = settings or load_settings()
        self.store = store or build_store(
            self.settings.supabase_url,
            self.settings.supabase_secret_key,
            self.settings.database_url,
        )
        self.fetcher = fetcher or build_fetcher_from_settings(self.settings)
        self.snapshots = snapshots or SnapshotStore(
            self.settings.supabase_url,
            self.settings.supabase_secret_key or self._derive_key(),
            self.settings.storage_bucket,
            ttl=self.settings.signed_url_ttl,
        )
        self.notifier = notifier or self._build_notifier()

    def _derive_key(self) -> str:
        # When only a DSN is configured we still need an API key for storage.
        return self.settings.supabase_secret_key or os.environ.get(
            "SUPABASE_STORAGE_KEY", ""
        )

    def _build_notifier(self) -> Optional[Notifier]:
        s = self.settings
        if not (s.notify_telegram or s.notify_slack):
            return None
        return Notifier(
            telegram_enabled=s.notify_telegram,
            telegram_token=s.telegram_token,
            telegram_chat_id=s.telegram_chat_id,
            slack_enabled=s.notify_slack,
            slack_token=s.slack_token,
            slack_channel_id=s.slack_channel_id,
            dashboard_url=s.dashboard_url,
        )

    # ------------------------------------------------------------------
    def run(
        self,
        *,
        project_id: Optional[str] = None,
        asset_id: Optional[str] = None,
        notify: bool = True,
    ) -> ScanReport:
        started = _now_iso()
        run = self.store.create_run(
            trigger_type=self.settings.trigger_type,
            github_run_id=self.settings.github_run_id or None,
        )
        report = ScanReport(run_id=run.id, status="running", started_at=started)

        LOG.info(
            "scan run %s started (trigger=%s, project=%s, asset=%s, dry_run=%s)",
            run.id,
            self.settings.trigger_type,
            project_id or "-",
            asset_id or "-",
            self.settings.dry_run,
        )

        try:
            assets = self.store.list_active_assets(project_id=project_id, asset_id=asset_id)
        except Exception as exc:
            report.errors_count += 1
            report.error_summary = f"Failed to load targets: {exc}"
            LOG.error("%s", report.error_summary)
            self._finish(report, "failed")
            return report

        if not assets:
            LOG.warning("No enabled assets matched this run")
            report.status = "success"
            report.completed_at = _now_iso()
            self._finish(report, "success")
            return report

        LOG.info("Scanning %d asset(s)", len(assets))

        for asset in assets:
            try:
                outcome = self._process_asset(asset, run.id, notify=notify)
            except Exception as exc:  # isolate failures per asset
                LOG.error(
                    "Unhandled error for %s: %s\n%s",
                    asset.url,
                    exc,
                    traceback.format_exc(limit=3),
                )
                outcome = AssetOutcome(
                    asset_id=asset.id,
                    url=asset.url,
                    status="error",
                    detail=f"unhandled: {exc}",
                )

            report.outcomes.append(outcome)
            report.assets_checked += 1

            if outcome.status == "changed":
                report.changes_detected += 1
            elif outcome.status == "baseline":
                report.baselines_created += 1
            elif outcome.status == "error":
                report.errors_count += 1

        report.completed_at = _now_iso()
        final = report.final_status
        LOG.info(
            "scan run %s finished: %s (%d checked, %d changed, %d baseline, %d errors)",
            run.id,
            final,
            report.assets_checked,
            report.changes_detected,
            report.baselines_created,
            report.errors_count,
        )
        self._finish(report, final)
        report.status = final
        return report

    # ------------------------------------------------------------------
    def _finish(self, report: ScanReport, status: str) -> None:
        try:
            self.store.finish_run(
                report.run_id,
                status=status,
                assets_checked=report.assets_checked,
                changes_detected=report.changes_detected,
                errors_count=report.errors_count,
                error_summary=report.error_summary or None,
            )
        except Exception as exc:
            LOG.error("Could not finalise scan run %s: %s", report.run_id, exc)

    # ------------------------------------------------------------------
    def _process_asset(
        self, asset: AssetRow, run_id: str, *, notify: bool
    ) -> AssetOutcome:
        """Check one asset and record the outcome.

        Order matters here:

        1. validate scope before any network access
        2. fetch (conditional when validators are known)
        3. resolve the stored previous version
        4. short-circuit unchanged content (304 or hash equality)
        5. store the new snapshot, then the new version row
        6. record a baseline (first sighting) or a genuine change event
        7. apply retention, then notify

        Every step that touches the network or the database is isolated, so a
        failure here becomes an ``error`` outcome rather than aborting the run.
        """
        checked_at = _now_iso()
        allowlist = list(getattr(asset, "allowed_hosts", []) or [])
        if self.settings.global_host_allowlist:
            allowlist.extend(self.settings.global_host_allowlist)
        scope = allowlist or None

        # 1. validate scope before touching the network
        try:
            target = ssrf.validate_url(asset.url, allowlist=scope)
        except ssrf.SSRFError as exc:
            self.store.update_asset_after_check(
                asset_id=asset.id, http_status=0, checked_at=checked_at
            )
            LOG.warning("scope validation failed for %s: %s", asset.url, exc)
            return AssetOutcome(
                asset_id=asset.id,
                url=asset.url,
                status="error",
                detail=f"scope validation failed: {exc}",
            )

        # 2. fetch (conditional when we have validators)
        try:
            result = self.fetcher.fetch(
                target.url,
                allowlist=scope,
                if_none_match=asset.etag,
                if_modified_since=asset.last_modified,
            )
        except FetchError as exc:
            # An error is recorded as an error, never as a content change.
            self.store.update_asset_after_check(
                asset_id=asset.id,
                http_status=exc.status or 0,
                checked_at=checked_at,
            )
            LOG.warning("fetch failed for %s: %s", asset.url, exc)
            return AssetOutcome(
                asset_id=asset.id,
                url=asset.url,
                status="error",
                detail=str(exc),
                http_status=exc.status,
            )

        self.store.update_asset_after_check(
            asset_id=asset.id,
            http_status=result.status,
            checked_at=checked_at,
            etag=result.etag,
            last_modified=result.last_modified,
        )

        # 3. resolve the stored previous version. Prefer the version the asset
        # points at; fall back to the most recent one.
        previous_version = None
        if asset.latest_version_id:
            candidates = self.store.get_latest_versions(asset.id, limit=2)
            previous_version = next(
                (v for v in candidates if v.id == asset.latest_version_id), None
            )
        if previous_version is None:
            versions = self.store.get_latest_versions(asset.id, limit=1)
            previous_version = versions[0] if versions else None

        previous_hash = previous_version.sha256_hash if previous_version else None

        # 4. unchanged content (304, or hash equality)
        if result.not_modified:
            LOG.info("unchanged (304): %s", asset.url)
            # A 304 proves the server's copy matches what we last stored, so
            # the asset pointer is authoritative. Heal it if either field is
            # stale (they can drift independently).
            if previous_version is not None and (
                asset.latest_version_id != previous_version.id
                or asset.latest_hash != previous_version.sha256_hash
            ):
                self.store.set_latest_version(
                    asset_id=asset.id,
                    version_id=previous_version.id,
                    sha256=previous_version.sha256_hash,
                    changed_at=previous_version.captured_at,
                )
            return AssetOutcome(
                asset_id=asset.id,
                url=asset.url,
                status="unchanged",
                http_status=304,
                new_hash=previous_hash or asset.latest_hash,
                old_hash=previous_hash or asset.latest_hash,
            )

        if previous_hash and previous_hash == result.sha256:
            LOG.info("unchanged (hash match): %s", asset.url)
            # Heal a stale hash/version pointer while we are here: the content
            # is unchanged, so the asset must point at the matching version.
            # Either field can be stale independently of the other.
            if (
                asset.latest_version_id != previous_version.id
                or asset.latest_hash != previous_version.sha256_hash
            ):
                self.store.set_latest_version(
                    asset_id=asset.id,
                    version_id=previous_version.id,
                    sha256=previous_version.sha256_hash,
                    changed_at=previous_version.captured_at,
                )
            return AssetOutcome(
                asset_id=asset.id,
                url=asset.url,
                status="unchanged",
                http_status=result.status,
                new_hash=result.sha256,
                old_hash=previous_hash,
            )

        # Load the previous bytes for diffing (only for genuine changes).
        previous_bytes = b""
        previous_size = 0
        if previous_version is not None:
            previous_size = previous_version.file_size
            try:
                previous_bytes = self.snapshots.download(
                    previous_version.storage_object_path
                )
            except Exception as exc:
                LOG.warning(
                    "could not load previous snapshot for %s (%s); "
                    "diffing against an empty baseline",
                    asset.url,
                    exc,
                )
                previous_bytes = b""

        # 5. store the new snapshot, then the new version row.
        #    Dry run: compute and report the outcome, but persist nothing — no
        #    snapshot, no version row, no change event, no pointer update.
        object_path = self.snapshots.object_path(asset.id, result.sha256)
        if self.settings.dry_run:
            diff = build_diff(
                previous_bytes if previous_bytes else None, result.body
            )
            status = "baseline" if (previous_version is None or not previous_hash) else "changed"
            LOG.info(
                "dry run: would record %s for %s (%s)",
                status,
                asset.url,
                result.sha256_prefix,
            )
            return AssetOutcome(
                asset_id=asset.id,
                url=asset.url,
                status=status,
                http_status=result.status,
                new_hash=result.sha256,
                old_hash=previous_hash,
                size=result.size,
                previous_size=previous_size,
                indicators=diff.indicators,
            )

        try:
            self.snapshots.upload(
                object_path,
                result.body,
                content_type=result.content_type or "text/javascript",
            )
        except Exception as exc:
            LOG.error("snapshot upload failed for %s: %s", asset.url, exc)
            return AssetOutcome(
                asset_id=asset.id,
                url=asset.url,
                status="error",
                detail=f"snapshot upload failed: {exc}",
                http_status=result.status,
                new_hash=result.sha256,
                old_hash=previous_hash,
            )

        version = self.store.insert_version(
            asset_id=asset.id,
            sha256=result.sha256,
            storage_object_path=object_path,
            file_size=result.size,
            scan_run_id=run_id,
        )

        diff = build_diff(
            previous_bytes if previous_bytes else None, result.body
        )

        # 6a. first sighting: record a baseline, not a change
        if previous_version is None or not previous_hash:
            self.store.set_latest_version(
                asset_id=asset.id,
                version_id=version.id,
                sha256=result.sha256,
                changed_at=checked_at,
            )
            self.store.audit_log(
                action="asset_baseline_created",
                entity_type="asset",
                entity_id=asset.id,
                details={
                    "url": asset.url,
                    "sha256": result.sha256,
                    "size": result.size,
                    "scan_run_id": run_id,
                },
            )
            LOG.info(
                "baseline created for %s (%s)", asset.url, result.sha256_prefix
            )
            return AssetOutcome(
                asset_id=asset.id,
                url=asset.url,
                status="baseline",
                http_status=result.status,
                new_hash=result.sha256,
                old_hash=None,
                size=result.size,
                version_id=version.id,
                indicators=diff.indicators,
            )

        # 6b. genuine change: record the event
        size_difference = result.size - previous_size
        summary = change_summary(diff, previous_size, result.size)

        change_event = self.store.insert_change_event(
            asset_id=asset.id,
            previous_version_id=previous_version.id,
            current_version_id=version.id,
            detected_at=checked_at,
            size_difference=size_difference,
            change_metadata=summary,
        )

        self.store.set_latest_version(
            asset_id=asset.id,
            version_id=version.id,
            sha256=result.sha256,
            changed_at=checked_at,
        )

        # 7. retention (never allowed to break the run)
        if self.settings.max_versions_per_asset > 0 and not self.settings.dry_run:
            try:
                stale_paths = self.store.prune_versions(
                    asset.id, keep=self.settings.max_versions_per_asset
                )
                for path in stale_paths:
                    try:
                        self.snapshots.remove(path)
                    except Exception:
                        pass
            except Exception as exc:
                LOG.warning("version pruning failed for %s: %s", asset.url, exc)

        LOG.info(
            "CHANGE detected for %s: %s -> %s (%+d B)",
            asset.url,
            (previous_hash or "")[:16],
            result.sha256_prefix,
            size_difference,
        )

        # 8. notify (a failure here must never break the scan)
        if notify and self.notifier and self.notifier.enabled:
            diff_url = ""
            try:
                diff_url = self.snapshots.create_signed_url(object_path)
            except Exception:
                pass
            payload = NotificationPayload(
                project_name=asset.project_name or "",
                asset_url=asset.url,
                previous_hash=previous_hash,
                current_hash=result.sha256,
                previous_size=previous_size,
                current_size=result.size,
                detected_at=checked_at,
                diff=diff,
                dashboard_url=self.settings.dashboard_url,
                indicators=diff.indicators,
            )
            results = self.notifier.notify(
                payload, asset_id=asset.id, diff_url=diff_url
            )
            change_id = (
                change_event.get("id") if isinstance(change_event, dict) else None
            )
            for channel, status in results.items():
                self.store.insert_notification_event(
                    change_event_id=change_id,
                    asset_id=asset.id,
                    channel=channel,
                    status=status,
                )

        return AssetOutcome(
            asset_id=asset.id,
            url=asset.url,
            status="changed",
            http_status=result.status,
            new_hash=result.sha256,
            old_hash=previous_hash,
            size=result.size,
            previous_size=previous_size,
            version_id=version.id,
            previous_version_id=previous_version.id,
            indicators=diff.indicators,
            change_event_id=(
                change_event.get("id") if isinstance(change_event, dict) else None
            ),
        )

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        stream=sys.stdout,
    )


def main(argv: Optional[list[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="jsmon-runner",
        description="JSMon monitoring engine — scans enabled JavaScript assets "
        "and records changes in Supabase.",
    )
    parser.add_argument("--project-id", help="limit the scan to one project")
    parser.add_argument("--asset-id", help="limit the scan to one asset")
    parser.add_argument(
        "--full-scan",
        action="store_true",
        help="ignored (kept for workflow compatibility); the runner always "
        "processes every eligible target unless --project-id/--asset-id is set",
    )
    parser.add_argument(
        "--no-notify", action="store_true", help="skip notification delivery"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="compute changes without writing snapshots or results",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    _configure_logging(args.verbose)

    settings = load_settings()
    if args.dry_run:
        settings.dry_run = True

    problems = settings.validate()
    if problems:
        for problem in problems:
            LOG.error("configuration error: %s", problem)
        return 2

    LOG.info("configuration: %s", settings.redacted_summary())

    runner = ScanRunner(settings=settings)
    try:
        report = runner.run(
            project_id=args.project_id,
            asset_id=args.asset_id,
            notify=not args.no_notify,
        )
    finally:
        try:
            runner.store.close()
        except Exception:
            pass

    print(
        "\nScan summary: status={status} checked={checked} changed={changed} "
        "baseline={baseline} errors={errors}".format(
            status=report.status,
            checked=report.assets_checked,
            changed=report.changes_detected,
            baseline=report.baselines_created,
            errors=report.errors_count,
        )
    )

    if report.status == "failed":
        return 1
    if report.status == "partial":
        return 0
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
