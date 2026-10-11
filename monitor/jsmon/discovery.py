"""JavaScript asset discovery from an authorized page.

The original jsmon had no discovery at all — operators hand-maintained files
in ``targets/``. This module adds optional discovery: given one authorized
HTML page, extract the JavaScript it references.

Scope rules:
* Only same-host assets are enrolled by default.
* A hostname allowlist may extend the allowed hosts.
* No crawling: only the single supplied page is fetched, once.
* Arbitrary third-party references are surfaced as *suggestions* but are not
  auto-enrolled.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable, Optional
from urllib.parse import urljoin, urlparse

from . import ssrf

_SCRIPT_SRC = re.compile(
    r"""<script\b[^>]*?\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>""",
    re.IGNORECASE | re.DOTALL,
)
_MODULE_PRELOAD = re.compile(
    r"""<link\b[^>]*?\brel\s*=\s*(?:"(modulepreload|preload)"|'(modulepreload|preload)')[^>]*?\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))[^>]*>""",
    re.IGNORECASE | re.DOTALL,
)
_AS_ATTR = re.compile(r"""\bas\s*=\s*["']?(script|worker)["']?""", re.IGNORECASE)

_JS_EXTENSIONS = (".js", ".mjs", ".cjs")
_MIME_JS = ("javascript", "ecmascript", "module")


@dataclass
class DiscoveryResult:
    """The outcome of scanning one page for JavaScript references."""

    page_url: str
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    duplicates_removed: int = 0
    errors: list[str] = field(default_factory=list)

    @property
    def total_found(self) -> int:
        return len(self.in_scope) + len(self.out_of_scope)


def _matches_module_hint(link_tag: str) -> bool:
    """A preload link only counts when it declares a script-ish ``as``."""
    if "modulepreload" in link_tag.lower():
        return True
    return bool(_AS_ATTR.search(link_tag))


def _looks_like_javascript(url: str, link_as: Optional[str] = None) -> bool:
    path = urlparse(url).path.lower()
    if any(path.endswith(ext) for ext in _JS_EXTENSIONS):
        return True
    if link_as and link_as.lower() in ("script", "worker"):
        return True
    if any(path.endswith(f"{m}") for m in _MIME_JS):
        return True
    # Extensionless paths that look like bundle endpoints (e.g. /build/app).
    return bool(re.search(r"/(build|bundle|assets?|static|_next|webpack)/", path))


def discover_from_html(
    html: str,
    page_url: str,
    *,
    allowlist: Optional[list[str]] = None,
    include_out_of_scope: bool = True,
) -> DiscoveryResult:
    """Extract JavaScript URLs referenced by one HTML document.

    ``allowlist`` restricts which hosts may be auto-enrolled. When it is
    ``None`` the page's own host is the only in-scope host.
    """
    result = DiscoveryResult(page_url=page_url)
    page_host = (urlparse(page_url).hostname or "").lower()

    candidates: list[str] = []

    for match in _SCRIPT_SRC.finditer(html):
        src = next((g for g in match.groups() if g), "")
        if src:
            candidates.append(src)

    for match in _MODULE_PRELOAD.finditer(html):
        tag = match.group(0)
        rel = (match.group(1) or match.group(2) or "").lower()
        href = next((g for g in match.groups()[2:] if g), "")
        if not href:
            continue
        if rel == "preload" and not _matches_module_hint(tag):
            continue
        candidates.append(href)

    seen: set[str] = set()
    normalized_out: set[str] = set()

    for raw in candidates:
        raw = raw.strip()
        if not raw or raw.startswith("#") or raw.lower().startswith("data:"):
            continue
        if raw.lower().startswith("javascript:"):
            continue

        try:
            absolute = urljoin(page_url, raw)
            absolute = ssrf.normalize_url(absolute)
        except ValueError:
            result.errors.append(f"Could not normalise reference: {raw[:120]}")
            continue

        if absolute in seen:
            continue

        try:
            parsed = urlparse(absolute)
        except ValueError:
            result.errors.append(f"Malformed reference: {raw[:120]}")
            continue

        host = (parsed.hostname or "").lower()
        if not host:
            continue

        if not _looks_like_javascript(absolute):
            # Only report references that plausibly are JavaScript.
            if not absolute.lower().endswith(_JS_EXTENSIONS):
                continue

        seen.add(absolute)

        effective_allowlist = allowlist if allowlist else [page_host]
        if ssrf.host_in_scope(host, effective_allowlist):
            result.in_scope.append(absolute)
        else:
            if include_out_of_scope:
                result.out_of_scope.append(absolute)
            else:
                result.duplicates_removed += 0

    result.in_scope = _dedupe(result.in_scope)
    result.out_of_scope = _dedupe(result.out_of_scope)
    return result


def _dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        if item in seen:
            continue
        seen.add(item)
        out.append(item)
    return out


def parse_url_list(text: str) -> tuple[list[str], list[str]]:
    """Parse a newline-separated URL list into (valid, invalid).

    Accepts plain text, comma/whitespace separated lines, and ignores
    comments (``#``) and blank lines.
    """
    valid: list[str] = []
    invalid: list[str] = []

    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Tolerate comma separated single lines.
        parts = [line] if "," not in line else [p.strip() for p in line.split(",")]
        for part in parts:
            if not part:
                continue
            try:
                parsed = ssrf.validate_url(part, resolve=False)
                valid.append(ssrf.normalize_url(parsed.url))
            except ssrf.SSRFError as exc:
                invalid.append(f"{part} ({exc})")

    return _dedupe(valid), invalid
