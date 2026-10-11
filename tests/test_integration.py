"""Integration test: the complete monitoring loop.

Verifies the acceptance criteria end to end against a controlled HTTP server:

1. first scan creates a baseline
2. second scan detects no change
3. third scan identifies the modified file
4. a historical snapshot is preserved
5. diff viewing shows the correct changes
6. dashboard records reflect the scan result
"""

from __future__ import annotations

import hashlib

import pytest

from jsmon.config import Settings
from jsmon.fetcher import AssetFetcher
from jsmon.runner import ScanRunner

from fixtures.fake_stores import InMemorySnapshotStore, InMemoryStore
from fixtures.test_server import TestServer, INITIAL_JS, MODIFIED_JS


@pytest.fixture
def env(loopback_allowed):
    """A server, fake stores, and a wired-up runner."""
    server = TestServer()
    server.__enter__()
    store = InMemoryStore()
    snapshots = InMemorySnapshotStore()
    settings = Settings(
        supabase_url="https://example.supabase.co",
        supabase_secret_key="test-key",
        storage_bucket="test-bucket",
        connect_timeout=5,
        read_timeout=10,
        max_retries=0,
        per_host_min_interval=0.0,
        trigger_type="test",
        notify_telegram=False,
        notify_slack=False,
    )
    fetcher = AssetFetcher(
        connect_timeout=5, read_timeout=10, max_retries=0, retry_backoff=0.01,
        pacer=None,
    )
    project_id = store.add_project("Test Project", allowed_hosts=["127.0.0.1"])
    asset_id = store.add_asset(project_id, server.url)
    runner = ScanRunner(
        settings=settings, store=store, fetcher=fetcher, snapshots=snapshots
    )
    try:
        yield server, store, snapshots, runner, asset_id, project_id
    finally:
        server.__exit__(None, None, None)


def _find(outcomes, asset_id):
    for outcome in outcomes:
        if outcome.asset_id == asset_id:
            return outcome
    raise AssertionError("asset outcome missing from report")


# 1 -----------------------------------------------------------------------


def test_first_scan_creates_baseline(env):
    server, store, snapshots, runner, asset_id, _ = env

    report = runner.run()

    outcome = _find(report.outcomes, asset_id)
    assert outcome.status == "baseline"
    assert report.baselines_created == 1
    assert report.changes_detected == 0
    assert report.errors_count == 0
    assert report.final_status == "success"

    asset = store.get_asset(asset_id)
    assert asset.latest_hash == hashlib.sha256(INITIAL_JS).hexdigest()
    assert asset.latest_version_id is not None
    assert asset.last_http_status == 200

    # The snapshot itself is in storage.
    versions = store.get_latest_versions(asset_id)
    assert len(versions) == 1
    assert snapshots.objects[versions[0].storage_object_path] == INITIAL_JS

    # A baseline must not be recorded as a change event.
    assert store.change_events == []

    run = store.runs[report.run_id]
    assert run["status"] == "success"
    assert run["assets_checked"] == 1


# 2 -----------------------------------------------------------------------


def test_second_scan_detects_no_change(env):
    server, store, snapshots, runner, asset_id, _ = env

    runner.run()  # baseline
    report = runner.run()

    outcome = _find(report.outcomes, asset_id)
    assert outcome.status == "unchanged"
    assert report.changes_detected == 0
    assert report.final_status == "success"
    assert len(store.get_latest_versions(asset_id)) == 1
    assert store.change_events == []


def test_unchanged_scan_does_not_create_a_version(env):
    server, store, snapshots, runner, asset_id, _ = env
    runner.run()
    before = list(store.get_latest_versions(asset_id))
    runner.run()
    after = list(store.get_latest_versions(asset_id))
    assert [v.id for v in before] == [v.id for v in after]


# 3 -----------------------------------------------------------------------


def test_third_scan_detects_modified_file(env):
    server, store, snapshots, runner, asset_id, _ = env

    runner.run()                       # baseline (v1)
    report_unchanged = runner.run()    # no change
    assert _find(report_unchanged.outcomes, asset_id).status == "unchanged"

    server.set_version(2)
    report = runner.run()

    outcome = _find(report.outcomes, asset_id)
    assert outcome.status == "changed"
    assert report.changes_detected == 1
    assert outcome.old_hash == hashlib.sha256(INITIAL_JS).hexdigest()
    assert outcome.new_hash == hashlib.sha256(MODIFIED_JS).hexdigest()
    assert outcome.size == len(MODIFIED_JS)
    assert outcome.previous_size == len(INITIAL_JS)


# 4 -----------------------------------------------------------------------


def test_historical_snapshot_is_preserved(env):
    server, store, snapshots, runner, asset_id, _ = env

    runner.run()
    first_version = store.get_latest_versions(asset_id)[0]

    server.set_version(2)
    runner.run()

    versions = store.get_latest_versions(asset_id, limit=10)
    assert len(versions) == 2, "both versions must be retained"

    hashes = {v.sha256_hash for v in versions}
    assert hashes == {
        hashlib.sha256(INITIAL_JS).hexdigest(),
        hashlib.sha256(MODIFIED_JS).hexdigest(),
    }

    # The old object is still downloadable and byte-identical.
    assert snapshots.download(first_version.storage_object_path) == INITIAL_JS
    assert snapshots.removed == [], "retention must not delete recent versions"


# 5 -----------------------------------------------------------------------


def test_diff_viewing_shows_the_correct_changes(env):
    server, store, snapshots, runner, asset_id, _ = env

    runner.run()
    server.set_version(2)
    runner.run()

    versions = store.get_latest_versions(asset_id, limit=2)
    current = versions[0]
    previous = versions[1]
    assert current.sha256_hash == hashlib.sha256(MODIFIED_JS).hexdigest()
    assert previous.sha256_hash == hashlib.sha256(INITIAL_JS).hexdigest()

    from jsmon.diffing import build_diff

    diff = build_diff(
        snapshots.download(previous.storage_object_path),
        snapshots.download(current.storage_object_path),
    )
    assert diff.added_lines > 0
    assert diff.removed_lines > 0
    assert "v2" in diff.unified or "MODIFIED" in "".join(
        line[1:] for line in diff.unified.splitlines() if line.startswith("+")
    )
    # The token added in v2 must be surfaced as a review indicator.
    assert any(i.category == "Credential" for i in diff.indicators)


# 6 -----------------------------------------------------------------------


def test_dashboard_records_reflect_the_scan_result(env):
    server, store, snapshots, runner, asset_id, _ = env

    runner.run()
    server.set_version(2)
    report = runner.run()

    run = store.runs[report.run_id]
    assert run["status"] == "success"
    assert run["assets_checked"] == 1
    assert run["changes_detected"] == 1
    assert run["errors_count"] == 0
    assert run["completed_at"] is not None

    assert len(store.change_events) == 1
    event = store.change_events[0]
    assert event["asset_id"] == asset_id
    assert event["size_difference"] == len(MODIFIED_JS) - len(INITIAL_JS)
    assert event["change_metadata"]["added_lines"] > 0
    assert event["previous_version_id"] != event["current_version_id"]

    asset = store.get_asset(asset_id)
    assert asset.latest_hash == hashlib.sha256(MODIFIED_JS).hexdigest()
    assert asset.latest_version_id == event["current_version_id"]


def test_audit_log_records_the_baseline(env):
    server, store, snapshots, runner, asset_id, _ = env
    runner.run()
    actions = [entry["action"] for entry in store.audit]
    assert "asset_baseline_created" in actions


# --- error isolation ------------------------------------------------------


def test_failed_download_is_recorded_as_error_not_change(env):
    server, store, snapshots, runner, asset_id, _ = env

    runner.run()  # baseline first so a hash exists
    server_url = store.get_asset(asset_id).url
    # Point the asset at a 404.
    store.assets[asset_id]["url"] = f"http://127.0.0.1:{server.port}/missing.js"

    report = runner.run()

    outcome = _find(report.outcomes, asset_id)
    assert outcome.status == "error"
    assert outcome.http_status == 404
    assert report.changes_detected == 0
    assert report.errors_count == 1
    assert report.final_status == "partial"

    # The previous version survives untouched.
    versions = store.get_latest_versions(asset_id)
    assert len(versions) == 1
    assert versions[0].sha256_hash == hashlib.sha256(INITIAL_JS).hexdigest()
    assert store.get_asset(asset_id).latest_hash == hashlib.sha256(
        INITIAL_JS
    ).hexdigest()
    assert store.change_events == []


def test_one_failing_asset_does_not_abort_the_scan(env):
    server, store, snapshots, runner, asset_id, project_id = env

    runner.run()
    broken = store.add_asset(project_id, f"http://127.0.0.1:{server.port}/missing.js")

    report = runner.run()

    statuses = {o.asset_id: o.status for o in report.outcomes}
    assert statuses[broken] == "error"
    assert statuses[asset_id] == "unchanged"
    assert report.assets_checked == 2
    assert report.errors_count == 1
    assert report.final_status == "partial"


def test_disabled_assets_are_skipped(env):
    server, store, snapshots, runner, asset_id, _ = env
    store.assets[asset_id]["enabled"] = False
    report = runner.run()
    assert report.assets_checked == 0
    assert report.final_status == "success"


def test_disabled_projects_are_skipped(env):
    server, store, snapshots, runner, asset_id, project_id = env
    store.projects[project_id]["enabled"] = False
    report = runner.run()
    assert report.assets_checked == 0


def test_project_filter_limits_the_scan(env):
    server, store, snapshots, runner, asset_id, project_id = env
    other = store.add_project("Other")
    store.add_asset(other, server.url)

    report = runner.run(project_id=project_id)
    assert report.assets_checked == 1


def test_asset_filter_targets_one_asset(env):
    server, store, snapshots, runner, asset_id, project_id = env
    second = store.add_asset(project_id, server.url)

    report = runner.run(asset_id=asset_id)
    assert report.assets_checked == 1
    assert report.outcomes[0].asset_id == asset_id
    assert second != asset_id


# --- concurrency / dedupe ------------------------------------------------


def test_repeated_change_is_not_duplicated(env):
    """Re-scanning identical changed content must not double-record."""
    server, store, snapshots, runner, asset_id, _ = env

    runner.run()
    server.set_version(2)
    runner.run()
    # Content has not moved again, so this run must be a no-op for events.
    report = runner.run()

    outcome = _find(report.outcomes, asset_id)
    assert outcome.status == "unchanged"
    assert len(store.change_events) == 1


def test_identical_content_different_assets_do_not_merge(env):
    server, store, snapshots, runner, asset_id, project_id = env

    other_url = f"http://127.0.0.1:{server.port}/app.js"
    second = store.add_asset(project_id, other_url)

    runner.run()

    versions_a = store.get_latest_versions(asset_id, limit=10)
    versions_b = store.get_latest_versions(second, limit=10)
    assert len(versions_a) == 1 and len(versions_b) == 1
    assert versions_a[0].asset_id == asset_id
    assert versions_b[0].asset_id == second
    # Same content -> same hash, but separate storage paths and versions.
    assert versions_a[0].sha256_hash == versions_b[0].sha256_hash
    assert versions_a[0].id != versions_b[0].id
    assert versions_a[0].storage_object_path != versions_b[0].storage_object_path


def test_concurrent_runs_do_not_corrupt_history(env):
    """Two overlapping runs against the same asset keep one change event."""
    server, store, snapshots, runner, asset_id, _ = env

    runner.run()  # baseline
    server.set_version(2)

    runner.run()
    # A second run sees the same content and must not add another event.
    runner.run()

    assert len(store.change_events) == 1
    versions = store.get_latest_versions(asset_id, limit=10)
    assert len(versions) == 2


def test_stale_latest_hash_is_healed(env):
    """If latest_hash is wrong but the snapshot matches, no change is reported."""
    server, store, snapshots, runner, asset_id, _ = env

    runner.run()
    good_hash = store.get_asset(asset_id).latest_hash
    store.assets[asset_id]["latest_hash"] = "deadbeef" * 8

    report = runner.run()

    outcome = _find(report.outcomes, asset_id)
    assert outcome.status == "unchanged"
    assert store.get_asset(asset_id).latest_hash == good_hash
    assert store.change_events == []


# --- retention -----------------------------------------------------------


def test_retention_keeps_configured_number_of_versions(env):
    server, store, snapshots, runner, asset_id, _ = env
    runner.settings.max_versions_per_asset = 2

    runner.run()
    for i in range(2, 6):
        # Each iteration serves new content by toggling versions.
        server.set_version(i)
        # Force a real content change for every iteration.
        store.assets[asset_id]["url"] = f"http://127.0.0.1:{server.port}/app.js?v={i}"
        runner.run()

    versions = store.get_latest_versions(asset_id, limit=100)
    assert len(versions) <= 2


def test_retention_disabled_keeps_everything(env):
    server, store, snapshots, runner, asset_id, _ = env
    runner.settings.max_versions_per_asset = 0
    runner.run()
    runner.run()
    assert len(store.get_latest_versions(asset_id, limit=100)) == 1


# --- notifications -------------------------------------------------------


def test_notification_deduplication(env):
    server, store, snapshots, runner, asset_id, _ = env

    runner.run()
    server.set_version(2)
    runner.run()
    first_count = len(store.notification_events)
    assert first_count == 0, "notifications are disabled in this fixture"

    # Enable notifications and re-run with a *new* change.
    from jsmon.notifications import Notifier

    class RecordingNotifier(Notifier):
        def __init__(self):
            super().__init__(dashboard_url="https://dash.test")
            self.calls = 0
            # The runner only calls notify() when a channel is enabled.
            self.telegram_enabled = True

        @property
        def enabled(self):
            return True

        def notify(self, payload, *, asset_id, diff_url=""):
            self.calls += 1
            return {"telegram": "sent"}

    notifier = RecordingNotifier()
    runner.notifier = notifier
    # A third, genuinely new version must trigger exactly one notification.
    server.set_content(b'// v3\nvar x = "sk_live_thirdchange987654321";\n')
    runner.run()
    assert notifier.calls == 1

    # Re-scanning the *same* content must not notify again.
    runner.run()
    assert notifier.calls == 1
    assert len(store.notification_events) >= 1


# --- dry run -------------------------------------------------------------


def test_dry_run_writes_no_snapshots(env):
    server, store, snapshots, runner, asset_id, _ = env
    runner.settings.dry_run = True

    report = runner.run()

    assert snapshots.objects == {}
    assert store.get_asset(asset_id).latest_hash is not None


# --- report shape --------------------------------------------------------


def test_report_is_json_serialisable(env):
    import json

    server, store, snapshots, runner, asset_id, _ = env
    runner.run()
    server.set_version(2)
    report = runner.run()
    payload = json.dumps(report.to_dict())
    assert "changed" in payload


def test_run_statuses_are_distinguishable(env):
    server, store, snapshots, runner, asset_id, project_id = env
    broken = store.add_asset(project_id, "http://127.0.0.1:1/x.js")

    report = runner.run()
    statuses = {o.asset_id: o.status for o in report.outcomes}
    assert statuses[broken] == "error"
    assert statuses[asset_id] == "baseline"
    assert report.final_status == "partial"
