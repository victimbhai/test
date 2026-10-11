"""End-to-end verification of the automatic trigger loop.

Chain under test:

    add target (API)  ->  dispatch_jobs row  ->  drain  ->  GitHub
    workflow_dispatch  ->  runner argv  ->  scan_runs / assets rows

The first two links are covered by tests/web/dispatch-live.test.ts. This test
closes the loop at the far end: it proves the workflow inputs the dispatcher
sends are translated into the argv the Python runner actually parses, and that
the runner then writes the expected rows.

It uses the real ``jsmon.runner`` module with in-memory stores and a local
fixture HTTP server, so the whole path runs for real without Supabase or
GitHub.
"""

from __future__ import annotations

import hashlib
import re
import os
import re
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "monitor"))

from jsmon.config import Settings
from jsmon.fetcher import AssetFetcher
from jsmon.runner import ScanRunner

from fixtures.fake_stores import InMemorySnapshotStore, InMemoryStore
from fixtures.test_server import INITIAL_JS, TestServer


# ---------------------------------------------------------------------------
# 1. The workflow shell must turn inputs into the argv the runner parses.
# ---------------------------------------------------------------------------

WORKFLOW_PATH = os.path.join(
    os.path.dirname(__file__),
    "..",
    ".github",
    "workflows",
    "jsmon-monitor.yml",
)


def _extract_arg_rules() -> list[tuple[str, str, str]]:
    """Parse the workflow's ARGS-building logic into (condition, flag) rules.

    Rather than shelling out (the CI/host `bash -s` stdin path is not reliable
    for multi-line `if` blocks on every platform), the workflow file is parsed
    directly. The rules are simple and stable:

        if [ <cond> ]; then
          ARGS="$ARGS <flag> ..."
        fi

    Returns a list of (kind, flag, source) where kind is one of
    "nonempty" / "equals".
    """
    text = open(WORKFLOW_PATH, encoding="utf-8").read()
    start = text.index('ARGS=""')
    end = text.index('echo "Running: python runner.py${ARGS}"')
    block = text[start:end]

    rules: list[tuple[str, str, str]] = []
    pattern = re.compile(
        r'if \[\s*(?P<cond>.+?)\s*\];\s*then\s*'
        r'ARGS="\$ARGS\s+(?P<flag>--[a-z-]+)',
        re.DOTALL,
    )

    for match in pattern.finditer(block):
        condition = " ".join(match.group("cond").split())
        flag = match.group("flag")
        kind = "equals" if " = " in condition else "nonempty"
        rules.append((kind, flag, condition))

    return rules


def _resolve_input(expression: str) -> str:
    """Turn a shell token like "${{ inputs.notify }}" into "inputs.notify"."""
    cleaned = expression.strip().strip('"').strip("'")
    cleaned = cleaned.replace("${{", "").replace("}}", "").strip()
    return cleaned


def _argv_for(
    project_id: str = "",
    asset_id: str = "",
    notify: str = "true",
    dry_run: str = "false",
) -> list[str]:
    """Apply the parsed workflow rules to a set of inputs, as bash would."""
    inputs = {
        "inputs.project_id": project_id,
        "inputs.asset_id": asset_id,
        "inputs.notify": notify,
        "inputs.dry_run": dry_run,
    }

    argv: list[str] = []
    for kind, flag, condition in _extract_arg_rules():
        if kind == "equals":
            left, _, right = condition.partition(" = ")
            name = _resolve_input(left)
            expected = right.strip().strip('"').strip("'")
            if inputs.get(name, "") != expected:
                continue
            argv.append(flag)
            continue

        # "nonempty": -n "<input>"
        name = _resolve_input(condition.replace("-n", ""))
        value = inputs.get(name, "")
        if not value:
            continue
        argv.append(flag)
        argv.append(value)

    return argv


def test_workflow_passes_project_id_to_the_runner():
    argv = _argv_for(project_id="proj-123")
    assert "--project-id" in argv
    assert argv[argv.index("--project-id") + 1] == "proj-123"


def test_workflow_passes_asset_id_to_the_runner():
    argv = _argv_for(asset_id="asset-456")
    assert "--asset-id" in argv
    assert argv[argv.index("--asset-id") + 1] == "asset-456"


def test_workflow_maps_notify_false_to_no_notify():
    argv = _argv_for(notify="false")
    assert "--no-notify" in argv

    argv = _argv_for(notify="true")
    assert "--no-notify" not in argv


def test_workflow_maps_dry_run_true_to_dry_run():
    argv = _argv_for(dry_run="true")
    assert "--dry-run" in argv

    argv = _argv_for(dry_run="false")
    assert "--dry-run" not in argv


def test_workflow_emits_no_args_for_a_plain_full_scan():
    argv = _argv_for()
    assert argv == []


def test_workflow_inputs_match_the_dispatcher_payload():
    """The dispatcher sends these keys; the workflow must declare each one."""
    text = open(WORKFLOW_PATH, encoding="utf-8").read()
    for key in ("project_id", "asset_id", "full_scan", "notify", "dry_run"):
        assert f"{key}:" in text, f"workflow is missing the {key} input"


# ---------------------------------------------------------------------------
# 2. The runner must honour --project-id / --asset-id exactly as dispatched.
# ---------------------------------------------------------------------------


@pytest.fixture
def loopback_allowed(monkeypatch):
    monkeypatch.setenv("JSMON_TEST_ALLOW_LOOPBACK", "1")
    yield


def _make_runner(store, snapshots, server, **overrides):
    settings = Settings(
        supabase_url="https://example.supabase.co",
        supabase_secret_key="test-key",
        max_retries=0,
        per_host_min_interval=0.0,
        trigger_type="workflow_dispatch",
        github_run_id="999",
        notify_telegram=False,
        notify_slack=False,
        **overrides,
    )
    fetcher = AssetFetcher(
        connect_timeout=5, read_timeout=10, max_retries=0, retry_backoff=0.01
    )
    return ScanRunner(
        settings=settings, store=store, fetcher=fetcher, snapshots=snapshots
    )


def test_dispatched_asset_scope_scans_only_that_target(loopback_allowed):
    with TestServer() as server:
        store = InMemoryStore()
        snapshots = InMemorySnapshotStore()

        wanted = store.add_project("Wanted", allowed_hosts=["127.0.0.1"])
        other = store.add_project("Other", allowed_hosts=["127.0.0.1"])
        wanted_asset = store.add_asset(wanted, server.url)
        other_asset = store.add_asset(other, server.url)

        runner = _make_runner(store, snapshots, server)
        report = runner.run(asset_id=wanted_asset)

        assert report.assets_checked == 1
        assert report.outcomes[0].asset_id == wanted_asset
        # The other project's asset was untouched.
        assert store.get_asset(other_asset).latest_hash is None


def test_dispatched_project_scope_scans_only_that_project(loopback_allowed):
    with TestServer() as server:
        store = InMemoryStore()
        snapshots = InMemorySnapshotStore()

        mine = store.add_project("Mine", allowed_hosts=["127.0.0.1"])
        theirs = store.add_project("Theirs", allowed_hosts=["127.0.0.1"])
        my_asset = store.add_asset(mine, server.url)
        their_asset = store.add_asset(theirs, server.url)

        runner = _make_runner(store, snapshots, server)
        report = runner.run(project_id=mine)

        assert report.assets_checked == 1
        assert store.get_asset(my_asset).latest_hash is not None
        assert store.get_asset(their_asset).latest_hash is None


def test_full_scan_without_scope_covers_every_enabled_target(loopback_allowed):
    with TestServer() as server:
        store = InMemoryStore()
        snapshots = InMemorySnapshotStore()

        first = store.add_project("One", allowed_hosts=["127.0.0.1"])
        second = store.add_project("Two", allowed_hosts=["127.0.0.1"])
        store.add_asset(first, server.url)
        store.add_asset(second, server.url)

        runner = _make_runner(store, snapshots, server)
        report = runner.run()

        assert report.assets_checked == 2


# ---------------------------------------------------------------------------
# 3. The dispatched run must produce real, inspectable dashboard records.
# ---------------------------------------------------------------------------


def test_dispatched_run_writes_a_baseline_the_dashboard_can_read(loopback_allowed):
    with TestServer() as server:
        store = InMemoryStore()
        snapshots = InMemorySnapshotStore()

        project = store.add_project("Live", allowed_hosts=["127.0.0.1"])
        asset_id = store.add_asset(project, server.url)

        runner = _make_runner(store, snapshots, server)
        report = runner.run(asset_id=asset_id)

        assert report.final_status == "success"

        run = store.runs[report.run_id]
        assert run["status"] == "success"
        assert run["assets_checked"] == 1
        assert run["github_run_id"] == "999"
        assert run["trigger_type"] == "workflow_dispatch"

        asset = store.get_asset(asset_id)
        assert asset.latest_hash == hashlib.sha256(INITIAL_JS).hexdigest()
        assert asset.last_http_status == 200

        versions = store.get_latest_versions(asset_id)
        assert len(versions) == 1
        assert snapshots.objects[versions[0].storage_object_path] == INITIAL_JS


def test_dispatched_run_detects_a_real_change_and_records_a_diff(loopback_allowed):
    with TestServer() as server:
        store = InMemoryStore()
        snapshots = InMemorySnapshotStore()

        project = store.add_project("Live", allowed_hosts=["127.0.0.1"])
        asset_id = store.add_asset(project, server.url)

        runner = _make_runner(store, snapshots, server)
        runner.run(asset_id=asset_id)          # baseline

        server.set_version(2)                 # the asset genuinely changes
        report = runner.run(asset_id=asset_id)

        assert report.changes_detected == 1
        assert len(store.change_events) == 1

        event = store.change_events[0]
        assert event["change_metadata"]["added_lines"] > 0
        assert event["size_difference"] != 0

        # Two versions retained, so the diff viewer has both sides.
        versions = store.get_latest_versions(asset_id, limit=5)
        assert len(versions) == 2

        from jsmon.diffing import build_diff

        diff = build_diff(
            snapshots.download(versions[1].storage_object_path),
            snapshots.download(versions[0].storage_object_path),
        )
        assert diff.added_lines > 0
        assert diff.unified


def test_dry_run_records_nothing(loopback_allowed):
    with TestServer() as server:
        store = InMemoryStore()
        snapshots = InMemorySnapshotStore()

        project = store.add_project("Dry", allowed_hosts=["127.0.0.1"])
        asset_id = store.add_asset(project, server.url)

        runner = _make_runner(store, snapshots, server, dry_run=True)
        runner.run(asset_id=asset_id)

        assert snapshots.objects == {}
        assert store.get_latest_versions(asset_id) == []
