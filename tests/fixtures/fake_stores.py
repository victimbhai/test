"""In-memory fakes for the database and storage backends.

These let the full scan lifecycle be exercised without Supabase, including the
duplicate/immutability semantics the real schema enforces with unique keys.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from jsmon.database import (
    AssetRow,
    RunRow,
    Store,
    VersionRow,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def new_id() -> str:
    return str(uuid.uuid4())


class InMemoryStore(Store):
    """A Store implementation backed by plain dicts."""

    def __init__(self):
        self.projects: dict[str, dict] = {}
        self.assets: dict[str, dict] = {}
        self.versions: dict[str, dict] = {}
        self.change_events: list[dict] = []
        self.notification_events: list[dict] = []
        self.runs: dict[str, dict] = {}
        self.audit: list[dict] = []

    # -- helpers -------------------------------------------------------
    def add_project(
        self, name: str = "Test Project", allowed_hosts: Optional[list] = None,
        enabled: bool = True,
    ) -> str:
        pid = new_id()
        self.projects[pid] = {
            "id": pid,
            "name": name,
            "enabled": enabled,
            "allowed_hosts": allowed_hosts or [],
        }
        return pid

    def add_asset(
        self,
        project_id: str,
        url: str,
        *,
        enabled: bool = True,
        latest_hash: Optional[str] = None,
        latest_version_id: Optional[str] = None,
        etag: Optional[str] = None,
    ) -> str:
        aid = new_id()
        self.assets[aid] = {
            "id": aid,
            "project_id": project_id,
            "url": url,
            "enabled": enabled,
            "latest_hash": latest_hash,
            "latest_version_id": latest_version_id,
            "etag": etag,
            "last_modified": None,
            "last_http_status": None,
            "last_checked_at": None,
            "last_changed_at": None,
        }
        return aid

    # -- Store interface -----------------------------------------------
    def list_active_assets(self, *, project_id=None, asset_id=None):
        out = []
        for asset in self.assets.values():
            if not asset["enabled"]:
                continue
            project = self.projects.get(asset["project_id"])
            if project is None or not project["enabled"]:
                continue
            if project_id and asset["project_id"] != project_id:
                continue
            if asset_id and asset["id"] != asset_id:
                continue
            row = AssetRow(
                id=asset["id"],
                project_id=asset["project_id"],
                url=asset["url"],
                enabled=True,
                latest_hash=asset["latest_hash"],
                latest_version_id=asset["latest_version_id"],
                last_http_status=asset["last_http_status"],
                etag=asset["etag"],
                last_modified=asset["last_modified"],
                project_name=project["name"],
            )
            row.allowed_hosts = project["allowed_hosts"]  # type: ignore[attr-defined]
            out.append(row)
        return out

    def get_asset(self, asset_id):
        asset = self.assets.get(asset_id)
        if not asset:
            return None
        return AssetRow(
            id=asset["id"],
            project_id=asset["project_id"],
            url=asset["url"],
            enabled=asset["enabled"],
            latest_hash=asset["latest_hash"],
            latest_version_id=asset["latest_version_id"],
            last_http_status=asset["last_http_status"],
        )

    def create_run(self, *, trigger_type, github_run_id):
        rid = new_id()
        self.runs[rid] = {
            "id": rid,
            "github_run_id": github_run_id,
            "trigger_type": trigger_type,
            "status": "running",
            "started_at": _now(),
            "completed_at": None,
            "assets_checked": 0,
            "changes_detected": 0,
            "errors_count": 0,
            "error_summary": None,
        }
        return RunRow(
            id=rid, github_run_id=github_run_id,
            trigger_type=trigger_type, status="running",
        )

    def finish_run(self, run_id, *, status, assets_checked, changes_detected,
                   errors_count, error_summary=None):
        run = self.runs[run_id]
        run.update(
            status=status,
            completed_at=_now(),
            assets_checked=assets_checked,
            changes_detected=changes_detected,
            errors_count=errors_count,
            error_summary=error_summary,
        )

    def insert_version(self, *, asset_id, sha256, storage_object_path, file_size,
                       scan_run_id):
        # Unique per (asset, hash): re-inserting identical content is a no-op.
        for version in self.versions.values():
            if version["asset_id"] == asset_id and version["sha256_hash"] == sha256:
                return VersionRow(
                    id=version["id"], asset_id=asset_id, sha256_hash=sha256,
                    storage_object_path=version["storage_object_path"],
                    file_size=version["file_size"],
                    captured_at=version["captured_at"],
                    scan_run_id=version.get("scan_run_id"),
                )
        vid = new_id()
        self.versions[vid] = {
            "id": vid, "asset_id": asset_id, "sha256_hash": sha256,
            "storage_object_path": storage_object_path, "file_size": file_size,
            "captured_at": _now(), "scan_run_id": scan_run_id,
        }
        return VersionRow(
            id=vid, asset_id=asset_id, sha256_hash=sha256,
            storage_object_path=storage_object_path, file_size=file_size,
            captured_at=self.versions[vid]["captured_at"],
            scan_run_id=scan_run_id,
        )

    def update_asset_after_check(self, *, asset_id, http_status, checked_at,
                                 etag=None, last_modified=None):
        asset = self.assets[asset_id]
        asset["last_http_status"] = http_status
        asset["last_checked_at"] = checked_at
        if etag is not None:
            asset["etag"] = etag
        if last_modified is not None:
            asset["last_modified"] = last_modified

    def set_latest_version(self, *, asset_id, version_id, sha256, changed_at):
        asset = self.assets[asset_id]
        asset["latest_version_id"] = version_id
        asset["latest_hash"] = sha256
        asset["last_changed_at"] = changed_at

    def insert_change_event(self, *, asset_id, previous_version_id,
                            current_version_id, detected_at, size_difference,
                            change_metadata):
        for event in self.change_events:
            if (event["asset_id"] == asset_id
                    and event["current_version_id"] == current_version_id):
                return event
        event = {
            "id": new_id(), "asset_id": asset_id,
            "previous_version_id": previous_version_id,
            "current_version_id": current_version_id,
            "detected_at": detected_at,
            "size_difference": size_difference,
            "change_metadata": change_metadata,
        }
        self.change_events.append(event)
        return event

    def insert_notification_event(self, *, change_event_id, asset_id, channel,
                                  status, error=None):
        self.notification_events.append({
            "id": new_id(), "change_event_id": change_event_id,
            "asset_id": asset_id, "channel": channel, "status": status,
            "error": error, "sent_at": _now(),
        })

    def get_latest_versions(self, asset_id, *, limit=2):
        rows = [v for v in self.versions.values() if v["asset_id"] == asset_id]
        rows.sort(key=lambda v: v["captured_at"], reverse=True)
        return [
            VersionRow(
                id=v["id"], asset_id=v["asset_id"], sha256_hash=v["sha256_hash"],
                storage_object_path=v["storage_object_path"],
                file_size=v["file_size"], captured_at=v["captured_at"],
                scan_run_id=v.get("scan_run_id"),
            )
            for v in rows[:limit]
        ]

    def prune_versions(self, asset_id, *, keep):
        rows = [v for v in self.versions.values() if v["asset_id"] == asset_id]
        rows.sort(key=lambda v: v["captured_at"], reverse=True)
        stale = rows[keep:]
        paths = [v["storage_object_path"] for v in stale]
        for version in stale:
            del self.versions[version["id"]]
        return paths

    def audit_log(self, *, action, entity_type, entity_id, details):
        self.audit.append({
            "action": action, "entity_type": entity_type,
            "entity_id": entity_id, "details": details, "created_at": _now(),
        })


class InMemorySnapshotStore:
    """In-memory stand-in for Supabase Storage."""

    def __init__(self):
        self.objects: dict[str, bytes] = {}
        self.removed: list[str] = []

    def object_path(self, asset_id: str, sha256: str, extension: str = "js") -> str:
        return f"{asset_id}/{sha256}.{extension}"

    def upload(self, path: str, data: bytes, *, content_type="text/javascript"):
        self.objects[path] = data
        return True

    def download(self, path: str) -> bytes:
        if path not in self.objects:
            raise KeyError(f"object not found: {path}")
        return self.objects[path]

    def create_signed_url(self, path: str, *, ttl: int = 900) -> str:
        return f"https://storage.test/sign/{path}?ttl={ttl}"

    def remove(self, path: str) -> bool:
        self.removed.append(path)
        return self.objects.pop(path, None) is not None
