"""Database access for the monitoring engine.

Two interchangeable backends implement the same interface:

* :class:`PostgrestStore` — talks to Supabase's PostgREST API with the secret
  key. Works everywhere with no extra driver.
* :class:`PostgresStore` — uses ``psycopg`` over a direct connection string
  when one is configured, giving real transactions for concurrent runs.

The engine only ever needs the operations in :class:`Store`, so the runner
code is identical whichever backend is active.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Optional


class DatabaseError(Exception):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class ProjectRow:
    id: str
    name: str
    primary_domain: Optional[str]
    enabled: bool
    allowed_hosts: list[str]


@dataclass
class AssetRow:
    id: str
    project_id: str
    url: str
    enabled: bool
    latest_hash: Optional[str]
    latest_version_id: Optional[str]
    last_http_status: Optional[int]
    etag: Optional[str] = None
    last_modified: Optional[str] = None
    project_name: str = ""


@dataclass
class VersionRow:
    id: str
    asset_id: str
    sha256_hash: str
    storage_object_path: str
    file_size: int
    captured_at: str
    scan_run_id: Optional[str]


@dataclass
class RunRow:
    id: str
    github_run_id: Optional[str]
    trigger_type: str
    status: str


class Store:
    """Interface implemented by both database backends."""

    def list_active_assets(
        self,
        *,
        project_id: Optional[str] = None,
        asset_id: Optional[str] = None,
    ) -> list[AssetRow]:  # pragma: no cover - interface
        raise NotImplementedError

    def get_asset(self, asset_id: str) -> Optional[AssetRow]:  # pragma: no cover
        raise NotImplementedError

    def create_run(
        self, *, trigger_type: str, github_run_id: Optional[str]
    ) -> RunRow:  # pragma: no cover
        raise NotImplementedError

    def finish_run(
        self,
        run_id: str,
        *,
        status: str,
        assets_checked: int,
        changes_detected: int,
        errors_count: int,
        error_summary: Optional[str] = None,
    ) -> None:  # pragma: no cover
        raise NotImplementedError

    def insert_version(
        self,
        *,
        asset_id: str,
        sha256: str,
        storage_object_path: str,
        file_size: int,
        scan_run_id: str,
    ) -> VersionRow:  # pragma: no cover
        raise NotImplementedError

    def update_asset_after_check(
        self,
        *,
        asset_id: str,
        http_status: int,
        checked_at: str,
        etag: Optional[str] = None,
        last_modified: Optional[str] = None,
    ) -> None:  # pragma: no cover
        raise NotImplementedError

    def set_latest_version(
        self, *, asset_id: str, version_id: str, sha256: str, changed_at: str
    ) -> None:  # pragma: no cover
        raise NotImplementedError

    def insert_change_event(
        self,
        *,
        asset_id: str,
        previous_version_id: Optional[str],
        current_version_id: str,
        detected_at: str,
        size_difference: int,
        change_metadata: dict,
    ) -> dict:  # pragma: no cover
        raise NotImplementedError

    def insert_notification_event(
        self,
        *,
        change_event_id: Optional[str],
        asset_id: str,
        channel: str,
        status: str,
        error: Optional[str] = None,
    ) -> None:  # pragma: no cover
        raise NotImplementedError

    def get_latest_versions(
        self, asset_id: str, *, limit: int = 2
    ) -> list[VersionRow]:  # pragma: no cover
        raise NotImplementedError

    def prune_versions(
        self, asset_id: str, *, keep: int
    ) -> list[str]:  # pragma: no cover
        raise NotImplementedError

    def audit_log(
        self, *, action: str, entity_type: str, entity_id: Optional[str], details: dict
    ) -> None:  # pragma: no cover
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover
        pass


# ---------------------------------------------------------------------------
# PostgREST backend
# ---------------------------------------------------------------------------


class PostgrestStore(Store):
    def __init__(self, supabase_url: str, api_key: str):
        self.base = supabase_url.rstrip("/")
        self.api_key = api_key

    # -- plumbing -------------------------------------------------------
    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[dict] = None,
        body: Any = None,
        prefer: Optional[str] = None,
        expect: tuple[int, ...] = (200, 201),
    ) -> Any:
        url = f"{self.base}/rest/v1/{path}"
        if params:
            url = f"{url}?{urllib.parse.urlencode(params, doseq=True)}"
        data = None
        headers = {
            "apikey": self.api_key,
            "Authorization": f"Bearer {self.api_key}",
            "Accept": "application/json",
        }
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if prefer:
            headers["Prefer"] = prefer

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                raw = resp.read().decode("utf-8")
                if not raw:
                    return None
                return json.loads(raw)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:500]
            raise DatabaseError(
                f"PostgREST {method} {path} failed ({exc.code}): {detail}"
            ) from exc

    @staticmethod
    def _as_list(value: Any) -> list:
        if value is None:
            return []
        return value if isinstance(value, list) else [value]

    # -- reads ----------------------------------------------------------
    def list_active_assets(
        self,
        *,
        project_id: Optional[str] = None,
        asset_id: Optional[str] = None,
    ) -> list[AssetRow]:
        params = {
            "select": "id,project_id,url,enabled,latest_hash,latest_version_id,"
            "last_http_status,last_checked_at,projects!inner(id,name,enabled,"
            "primary_domain,allowed_hosts)",
            "enabled": "eq.true",
            "projects.enabled": "eq.true",
            "order": "url.asc",
        }
        if project_id:
            params["project_id"] = f"eq.{project_id}"
        if asset_id:
            params["id"] = f"eq.{asset_id}"

        rows = self._as_list(self._request("GET", "assets", params=params))
        out: list[AssetRow] = []
        for row in rows:
            project = row.get("projects") or {}
            hosts = project.get("allowed_hosts") or []
            out.append(
                AssetRow(
                    id=row["id"],
                    project_id=row["project_id"],
                    url=row["url"],
                    enabled=bool(row.get("enabled")),
                    latest_hash=row.get("latest_hash"),
                    latest_version_id=row.get("latest_version_id"),
                    last_http_status=row.get("last_http_status"),
                    project_name=project.get("name", ""),
                    etag=row.get("etag"),
                    last_modified=row.get("last_modified"),
                )
            )
            row.setdefault("_allow", hosts)
            out[-1].allowed_hosts = hosts  # type: ignore[attr-defined]
        return out

    def get_asset(self, asset_id: str) -> Optional[AssetRow]:
        rows = self._as_list(
            self._request(
                "GET", "assets", params={"id": f"eq.{asset_id}", "select": "*"}
            )
        )
        if not rows:
            return None
        row = rows[0]
        return AssetRow(
            id=row["id"],
            project_id=row["project_id"],
            url=row["url"],
            enabled=bool(row.get("enabled")),
            latest_hash=row.get("latest_hash"),
            latest_version_id=row.get("latest_version_id"),
            last_http_status=row.get("last_http_status"),
        )

    # -- writes ---------------------------------------------------------
    def create_run(self, *, trigger_type: str, github_run_id: Optional[str]) -> RunRow:
        payload = {
            "trigger_type": trigger_type,
            "github_run_id": github_run_id,
            "status": "running",
            "started_at": _now(),
            "assets_checked": 0,
            "changes_detected": 0,
            "errors_count": 0,
        }
        rows = self._as_list(
            self._request(
                "POST",
                "scan_runs",
                body=payload,
                prefer="return=representation",
            )
        )
        if not rows:
            raise DatabaseError("scan_runs insert returned no row")
        row = rows[0]
        return RunRow(
            id=row["id"],
            github_run_id=row.get("github_run_id"),
            trigger_type=row.get("trigger_type", trigger_type),
            status=row.get("status", "running"),
        )

    def finish_run(
        self,
        run_id: str,
        *,
        status: str,
        assets_checked: int,
        changes_detected: int,
        errors_count: int,
        error_summary: Optional[str] = None,
    ) -> None:
        payload: dict[str, Any] = {
            "status": status,
            "completed_at": _now(),
            "assets_checked": assets_checked,
            "changes_detected": changes_detected,
            "errors_count": errors_count,
        }
        if error_summary:
            payload["error_summary"] = error_summary[:4000]
        self._request("PATCH", "scan_runs", params={"id": f"eq.{run_id}"}, body=payload)

    def insert_version(
        self,
        *,
        asset_id: str,
        sha256: str,
        storage_object_path: str,
        file_size: int,
        scan_run_id: str,
    ) -> VersionRow:
        payload = {
            "asset_id": asset_id,
            "sha256_hash": sha256,
            "storage_object_path": storage_object_path,
            "file_size": file_size,
            "captured_at": _now(),
            "scan_run_id": scan_run_id,
        }
        # on_conflict avoids duplicate rows if the same content is re-inserted.
        rows = self._as_list(
            self._request(
                "POST",
                "asset_versions",
                body=payload,
                params={"on_conflict": "asset_id,sha256_hash"},
                prefer="return=representation,resolution=ignore-duplicates",
            )
        )
        if not rows:
            existing = self._as_list(
                self._request(
                    "GET",
                    "asset_versions",
                    params={
                        "asset_id": f"eq.{asset_id}",
                        "sha256_hash": f"eq.{sha256}",
                        "select": "*",
                        "limit": 1,
                    },
                )
            )
            if not existing:
                raise DatabaseError("asset_versions insert produced no row")
            row = existing[0]
        else:
            row = rows[0]
        return VersionRow(
            id=row["id"],
            asset_id=row["asset_id"],
            sha256_hash=row["sha256_hash"],
            storage_object_path=row["storage_object_path"],
            file_size=row.get("file_size", file_size),
            captured_at=row.get("captured_at", payload["captured_at"]),
            scan_run_id=row.get("scan_run_id", scan_run_id),
        )

    def update_asset_after_check(
        self,
        *,
        asset_id: str,
        http_status: int,
        checked_at: str,
        etag: Optional[str] = None,
        last_modified: Optional[str] = None,
    ) -> None:
        payload: dict[str, Any] = {
            "last_checked_at": checked_at,
            "last_http_status": http_status,
            "updated_at": checked_at,
        }
        if etag is not None:
            payload["etag"] = etag
        if last_modified is not None:
            payload["last_modified"] = last_modified
        self._request("PATCH", "assets", params={"id": f"eq.{asset_id}"}, body=payload)

    def set_latest_version(
        self, *, asset_id: str, version_id: str, sha256: str, changed_at: str
    ) -> None:
        payload = {
            "latest_version_id": version_id,
            "latest_hash": sha256,
            "last_changed_at": changed_at,
            "updated_at": changed_at,
        }
        self._request("PATCH", "assets", params={"id": f"eq.{asset_id}"}, body=payload)

    def insert_change_event(
        self,
        *,
        asset_id: str,
        previous_version_id: Optional[str],
        current_version_id: str,
        detected_at: str,
        size_difference: int,
        change_metadata: dict,
    ) -> dict:
        payload = {
            "asset_id": asset_id,
            "previous_version_id": previous_version_id,
            "current_version_id": current_version_id,
            "detected_at": detected_at,
            "size_difference": size_difference,
            "change_metadata": change_metadata,
        }
        # Dedupe: a (asset, current version) pair can only produce one event.
        rows = self._as_list(
            self._request(
                "POST",
                "change_events",
                body=payload,
                params={"on_conflict": "asset_id,current_version_id"},
                prefer="return=representation,resolution=ignore-duplicates",
            )
        )
        if rows:
            return rows[0]
        existing = self._as_list(
            self._request(
                "GET",
                "change_events",
                params={
                    "asset_id": f"eq.{asset_id}",
                    "current_version_id": f"eq.{current_version_id}",
                    "select": "*",
                    "limit": 1,
                },
            )
        )
        return existing[0] if existing else payload

    def insert_notification_event(
        self,
        *,
        change_event_id: Optional[str],
        asset_id: str,
        channel: str,
        status: str,
        error: Optional[str] = None,
    ) -> None:
        payload = {
            "change_event_id": change_event_id,
            "asset_id": asset_id,
            "channel": channel,
            "status": status,
            "sent_at": _now(),
        }
        if error:
            payload["error"] = error[:500]
        self._request("POST", "notification_events", body=payload)

    def get_latest_versions(self, asset_id: str, *, limit: int = 2) -> list[VersionRow]:
        rows = self._as_list(
            self._request(
                "GET",
                "asset_versions",
                params={
                    "asset_id": f"eq.{asset_id}",
                    "select": "*",
                    "order": "captured_at.desc",
                    "limit": limit,
                },
            )
        )
        return [
            VersionRow(
                id=r["id"],
                asset_id=r["asset_id"],
                sha256_hash=r["sha256_hash"],
                storage_object_path=r["storage_object_path"],
                file_size=r.get("file_size", 0),
                captured_at=r.get("captured_at", ""),
                scan_run_id=r.get("scan_run_id"),
            )
            for r in rows
        ]

    def prune_versions(self, asset_id: str, *, keep: int) -> list[str]:
        if keep <= 0:
            return []
        versions = self._as_list(
            self._request(
                "GET",
                "asset_versions",
                params={
                    "asset_id": f"eq.{asset_id}",
                    "select": "id,storage_object_path,captured_at",
                    "order": "captured_at.desc",
                },
            )
        )
        if len(versions) <= keep:
            return []
        stale = versions[keep:]
        paths = [v["storage_object_path"] for v in stale]
        ids = ",".join(f'"{v["id"]}"' for v in stale)
        self._request("DELETE", "asset_versions", params={"id": f"in.({ids})"})
        return paths

    def audit_log(
        self, *, action: str, entity_type: str, entity_id: Optional[str], details: dict
    ) -> None:
        try:
            self._request(
                "POST",
                "audit_logs",
                body={
                    "action": action,
                    "entity_type": entity_type,
                    "entity_id": entity_id,
                    "details": details,
                    "created_at": _now(),
                },
            )
        except DatabaseError:
            # Auditing must never break a scan.
            pass


# ---------------------------------------------------------------------------
# Direct Postgres backend (optional, transactional)
# ---------------------------------------------------------------------------


class PostgresStore(Store):
    """Transactional backend using psycopg over a direct connection."""

    def __init__(self, dsn: str):
        try:
            import psycopg  # type: ignore
            from psycopg.rows import dict_row  # type: ignore
        except ImportError as exc:  # pragma: no cover
            raise DatabaseError(
                "psycopg is required for SUPABASE_DB_URL support: pip install psycopg[binary]"
            ) from exc
        self._conn = psycopg.connect(dsn, row_factory=dict_row, autocommit=True)

    def _query(self, sql: str, params: tuple = ()) -> list[dict]:
        with self._conn.cursor() as cur:
            cur.execute(sql, params)
            if cur.description is None:
                return []
            return cur.fetchall()

    def _execute(self, sql: str, params: tuple = ()) -> None:
        with self._conn.cursor() as cur:
            cur.execute(sql, params)

    def list_active_assets(
        self,
        *,
        project_id: Optional[str] = None,
        asset_id: Optional[str] = None,
    ) -> list[AssetRow]:
        sql = """
            SELECT a.id, a.project_id, a.url, a.enabled, a.latest_hash,
                   a.latest_version_id, a.last_http_status, a.etag, a.last_modified,
                   p.name AS project_name, COALESCE(p.allowed_hosts, '[]'::jsonb) AS allowed_hosts
            FROM assets a
            JOIN projects p ON p.id = a.project_id
            WHERE a.enabled AND p.enabled
        """
        params: list[Any] = []
        if project_id:
            sql += " AND a.project_id = %s"
            params.append(project_id)
        if asset_id:
            sql += " AND a.id = %s"
            params.append(asset_id)
        sql += " ORDER BY a.url ASC"
        rows = self._query(sql, tuple(params))
        out: list[AssetRow] = []
        for r in rows:
            hosts = r.get("allowed_hosts") or []
            if isinstance(hosts, str):
                hosts = json.loads(hosts)
            out.append(
                AssetRow(
                    id=r["id"],
                    project_id=r["project_id"],
                    url=r["url"],
                    enabled=bool(r["enabled"]),
                    latest_hash=r.get("latest_hash"),
                    latest_version_id=r.get("latest_version_id"),
                    last_http_status=r.get("last_http_status"),
                    etag=r.get("etag"),
                    last_modified=r.get("last_modified"),
                    project_name=r.get("project_name", ""),
                )
            )
            out[-1].allowed_hosts = hosts  # type: ignore[attr-defined]
        return out

    def get_asset(self, asset_id: str) -> Optional[AssetRow]:
        rows = self._query(
            "SELECT * FROM assets WHERE id = %s LIMIT 1", (asset_id,)
        )
        if not rows:
            return None
        r = rows[0]
        return AssetRow(
            id=r["id"],
            project_id=r["project_id"],
            url=r["url"],
            enabled=bool(r["enabled"]),
            latest_hash=r.get("latest_hash"),
            latest_version_id=r.get("latest_version_id"),
            last_http_status=r.get("last_http_status"),
        )

    def create_run(self, *, trigger_type: str, github_run_id: Optional[str]) -> RunRow:
        rows = self._query(
            """
            INSERT INTO scan_runs (github_run_id, trigger_type, status, started_at)
            VALUES (%s, %s, 'running', now())
            RETURNING id, github_run_id, trigger_type, status
            """,
            (github_run_id, trigger_type),
        )
        r = rows[0]
        return RunRow(
            id=r["id"],
            github_run_id=r.get("github_run_id"),
            trigger_type=r.get("trigger_type", trigger_type),
            status=r.get("status", "running"),
        )

    def finish_run(
        self,
        run_id: str,
        *,
        status: str,
        assets_checked: int,
        changes_detected: int,
        errors_count: int,
        error_summary: Optional[str] = None,
    ) -> None:
        self._execute(
            """
            UPDATE scan_runs
            SET status = %s, completed_at = now(), assets_checked = %s,
                changes_detected = %s, errors_count = %s, error_summary = %s
            WHERE id = %s
            """,
            (
                status,
                assets_checked,
                changes_detected,
                errors_count,
                (error_summary or None) and error_summary[:4000],
                run_id,
            ),
        )

    def insert_version(
        self,
        *,
        asset_id: str,
        sha256: str,
        storage_object_path: str,
        file_size: int,
        scan_run_id: str,
    ) -> VersionRow:
        rows = self._query(
            """
            INSERT INTO asset_versions
                (asset_id, sha256_hash, storage_object_path, file_size, captured_at, scan_run_id)
            VALUES (%s, %s, %s, %s, now(), %s)
            ON CONFLICT (asset_id, sha256_hash) DO NOTHING
            RETURNING id, asset_id, sha256_hash, storage_object_path, file_size, captured_at, scan_run_id
            """,
            (asset_id, sha256, storage_object_path, file_size, scan_run_id),
        )
        if rows:
            r = rows[0]
        else:
            existing = self._query(
                """
                SELECT id, asset_id, sha256_hash, storage_object_path, file_size, captured_at, scan_run_id
                FROM asset_versions WHERE asset_id = %s AND sha256_hash = %s LIMIT 1
                """,
                (asset_id, sha256),
            )
            if not existing:
                raise DatabaseError("asset_versions insert produced no row")
            r = existing[0]
        return VersionRow(
            id=r["id"],
            asset_id=r["asset_id"],
            sha256_hash=r["sha256_hash"],
            storage_object_path=r["storage_object_path"],
            file_size=r.get("file_size", file_size),
            captured_at=str(r.get("captured_at", "")),
            scan_run_id=r.get("scan_run_id"),
        )

    def update_asset_after_check(
        self,
        *,
        asset_id: str,
        http_status: int,
        checked_at: str,
        etag: Optional[str] = None,
        last_modified: Optional[str] = None,
    ) -> None:
        self._execute(
            """
            UPDATE assets
            SET last_checked_at = %s, last_http_status = %s, updated_at = %s,
                etag = COALESCE(%s, etag),
                last_modified = COALESCE(%s, last_modified)
            WHERE id = %s
            """,
            (checked_at, http_status, checked_at, etag, last_modified, asset_id),
        )

    def set_latest_version(
        self, *, asset_id: str, version_id: str, sha256: str, changed_at: str
    ) -> None:
        self._execute(
            """
            UPDATE assets
            SET latest_version_id = %s, latest_hash = %s, last_changed_at = %s,
                updated_at = %s
            WHERE id = %s
            """,
            (version_id, sha256, changed_at, changed_at, asset_id),
        )

    def insert_change_event(
        self,
        *,
        asset_id: str,
        previous_version_id: Optional[str],
        current_version_id: str,
        detected_at: str,
        size_difference: int,
        change_metadata: dict,
    ) -> dict:
        rows = self._query(
            """
            INSERT INTO change_events
                (asset_id, previous_version_id, current_version_id, detected_at,
                 size_difference, change_metadata)
            VALUES (%s, %s, %s, %s, %s, %s::jsonb)
            ON CONFLICT (asset_id, current_version_id) DO NOTHING
            RETURNING *
            """,
            (
                asset_id,
                previous_version_id,
                current_version_id,
                detected_at,
                size_difference,
                json.dumps(change_metadata),
            ),
        )
        if rows:
            return rows[0]
        existing = self._query(
            """
            SELECT * FROM change_events
            WHERE asset_id = %s AND current_version_id = %s LIMIT 1
            """,
            (asset_id, current_version_id),
        )
        return existing[0] if existing else {}

    def insert_notification_event(
        self,
        *,
        change_event_id: Optional[str],
        asset_id: str,
        channel: str,
        status: str,
        error: Optional[str] = None,
    ) -> None:
        self._execute(
            """
            INSERT INTO notification_events
                (change_event_id, asset_id, channel, status, error, sent_at)
            VALUES (%s, %s, %s, %s, %s, now())
            """,
            (change_event_id, asset_id, channel, status, (error or None) and error[:500]),
        )

    def get_latest_versions(self, asset_id: str, *, limit: int = 2) -> list[VersionRow]:
        rows = self._query(
            """
            SELECT id, asset_id, sha256_hash, storage_object_path, file_size,
                   captured_at, scan_run_id
            FROM asset_versions
            WHERE asset_id = %s
            ORDER BY captured_at DESC, id DESC
            LIMIT %s
            """,
            (asset_id, limit),
        )
        return [
            VersionRow(
                id=r["id"],
                asset_id=r["asset_id"],
                sha256_hash=r["sha256_hash"],
                storage_object_path=r["storage_object_path"],
                file_size=r.get("file_size", 0),
                captured_at=str(r.get("captured_at", "")),
                scan_run_id=r.get("scan_run_id"),
            )
            for r in rows
        ]

    def prune_versions(self, asset_id: str, *, keep: int) -> list[str]:
        if keep <= 0:
            return []
        rows = self._query(
            """
            SELECT id, storage_object_path FROM asset_versions
            WHERE asset_id = %s
            ORDER BY captured_at DESC
            OFFSET %s
            """,
            (asset_id, keep),
        )
        if not rows:
            return []
        paths = [r["storage_object_path"] for r in rows]
        ids = [r["id"] for r in rows]
        self._execute(
            "DELETE FROM asset_versions WHERE id = ANY(%s::uuid[])", (ids,)
        )
        return paths

    def audit_log(
        self, *, action: str, entity_type: str, entity_id: Optional[str], details: dict
    ) -> None:
        try:
            self._execute(
                """
                INSERT INTO audit_logs (action, entity_type, entity_id, details, created_at)
                VALUES (%s, %s, %s, %s::jsonb, now())
                """,
                (action, entity_type, entity_id, json.dumps(details)),
            )
        except Exception:
            pass

    def close(self) -> None:
        try:
            self._conn.close()
        except Exception:
            pass


def build_store(supabase_url: str, secret_key: str, database_url: str = "") -> Store:
    """Pick the transactional backend when a DSN is available."""
    if database_url:
        return PostgresStore(database_url)
    return PostgrestStore(supabase_url, secret_key)
