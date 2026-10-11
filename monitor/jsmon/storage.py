"""Supabase Storage access for immutable JavaScript snapshots.

Snapshots are stored in a private bucket under a deterministic object path so
that identical content is stored once:

    <owner-prefix>/<asset-uuid>/<sha256>.js

Objects are treated as immutable: a given asset + hash is never rewritten,
which keeps historical references stable. Downloads are issued as short-lived
signed URLs and are only requested by authenticated API routes.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional


class StorageError(Exception):
    pass


class SnapshotStore:
    """Minimal Supabase Storage client (no third-party SDK required)."""

    def __init__(self, supabase_url: str, api_key: str, bucket: str, *, ttl: int = 900):
        self.supabase_url = supabase_url.rstrip("/")
        self.api_key = api_key
        self.bucket = bucket
        self.ttl = max(60, ttl)

    # ------------------------------------------------------------------
    def object_path(self, asset_id: str, sha256: str, extension: str = "js") -> str:
        """Deterministic, collision-free object path for a snapshot."""
        safe_ext = extension if re_safe(extension) else "js"
        return f"{asset_id}/{sha256}.{safe_ext}"

    # ------------------------------------------------------------------
    def upload(self, path: str, data: bytes, *, content_type: str = "text/javascript") -> bool:
        """Upload a snapshot. Returns True when it already existed (idempotent)."""
        url = (
            f"{self.supabase_url}/storage/v1/object/{self.bucket}/"
            f"{urllib.parse.quote(path, safe='/')}"
        )
        req = urllib.request.Request(url, data=data, method="POST")
        self._apply_headers(req)
        req.add_header("Content-Type", content_type)
        # x-upsert=false keeps snapshots immutable: identical content is a no-op.
        req.add_header("x-upsert", "false")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.status in (200, 201)
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")[:300]
            # 409 = object already exists, which is fine for immutable storage.
            if exc.code == 409 or "Duplicate" in body or "already exists" in body:
                return True
            raise StorageError(f"Upload failed ({exc.code}): {body}") from exc

    # ------------------------------------------------------------------
    def create_signed_url(self, path: str, *, ttl: Optional[int] = None) -> str:
        """Create a short-lived signed download URL."""
        seconds = ttl or self.ttl
        url = (
            f"{self.supabase_url}/storage/v1/object/sign/{self.bucket}/"
            f"{urllib.parse.quote(path, safe='/')}"
        )
        payload = json.dumps({"expiresIn": seconds}).encode("utf-8")
        req = urllib.request.Request(url, data=payload, method="POST")
        self._apply_headers(req)
        req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            raise StorageError(f"Signing failed ({exc.code})") from exc
        signed = body.get("signedURL") or body.get("signedUrl")
        if not signed:
            raise StorageError("Storage returned no signed URL")
        if signed.startswith("/"):
            signed = f"{self.supabase_url}/storage/v1{signed}"
        return signed

    # ------------------------------------------------------------------
    def download(self, path: str) -> bytes:
        """Download a snapshot using the privileged key (server-side only)."""
        url = (
            f"{self.supabase_url}/storage/v1/object/authenticated/{self.bucket}/"
            f"{urllib.parse.quote(path, safe='/')}"
        )
        req = urllib.request.Request(url)
        self._apply_headers(req)
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return resp.read()
        except urllib.error.HTTPError as exc:
            raise StorageError(f"Download failed ({exc.code})") from exc

    # ------------------------------------------------------------------
    def remove(self, path: str) -> bool:
        url = (
            f"{self.supabase_url}/storage/v1/object/{self.bucket}/"
            f"{urllib.parse.quote(path, safe='/')}"
        )
        req = urllib.request.Request(url, method="DELETE")
        self._apply_headers(req)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return resp.status in (200, 204)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return False
            raise StorageError(f"Delete failed ({exc.code})") from exc

    def _apply_headers(self, req: urllib.request.Request) -> None:
        req.add_header("Authorization", f"Bearer {self.api_key}")
        req.add_header("apikey", self.api_key)


def re_safe(value: str) -> bool:
    return bool(value) and value.isalnum() and len(value) <= 10
