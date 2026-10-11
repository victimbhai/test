"""HTTP fetching for JavaScript assets.

Replaces the original ``get_endpoint()`` (which used a bare
``requests.get`` with no timeout, no size limit and no redirect checks) with a
guarded fetcher:

* bounded connect/read timeouts
* streaming download with a hard byte ceiling
* explicit redirect allow-listing (every hop is SSRF re-validated)
* bounded retries with exponential backoff on transient failures
* conditional GET support (ETag / If-Modified-Since) so unchanged assets are
  not needlessly re-downloaded
* per-host pacing so a scan never hammers one origin
"""

from __future__ import annotations

import hashlib
import socket
import ssl
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Optional

from . import ssrf

_TRANSIENT_STATUS = {408, 425, 429, 500, 502, 503, 504}


class FetchError(Exception):
    """A fetch failed in a way that is an error, not a content change."""

    def __init__(self, message: str, *, status: Optional[int] = None, retryable: bool = False):
        super().__init__(message)
        self.status = status
        self.retryable = retryable


class ContentTooLargeError(FetchError):
    pass


@dataclass
class FetchResult:
    """The outcome of fetching one asset."""

    url: str
    final_url: str
    status: int
    body: bytes
    sha256: str
    size: int
    content_type: str = ""
    etag: Optional[str] = None
    last_modified: Optional[str] = None
    headers: dict = field(default_factory=dict)
    not_modified: bool = False
    attempts: int = 1

    @property
    def sha256_prefix(self) -> str:
        """First 16 hex chars — used as a short, stable display id."""
        return self.sha256[:16]

    @property
    def is_error(self) -> bool:
        return self.status >= 400 or self.not_modified


class HostPacer:
    """Ensures a minimum delay between requests to the same host."""

    def __init__(self, min_interval: float = 1.0) -> None:
        self.min_interval = max(0.0, min_interval)
        self._last: dict[str, float] = {}

    def wait(self, host: str) -> None:
        if self.min_interval <= 0:
            return
        now = time.monotonic()
        last = self._last.get(host)
        if last is not None:
            delay = self.min_interval - (now - last)
            if delay > 0:
                time.sleep(delay)
        self._last[host] = time.monotonic()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirect handling is done manually so every hop can be validated."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class AssetFetcher:
    """Validated, bounded HTTP fetcher for monitoring targets."""

    def __init__(
        self,
        *,
        connect_timeout: float = 10.0,
        read_timeout: float = 30.0,
        max_bytes: int = 20 * 1024 * 1024,
        max_redirects: int = 5,
        max_retries: int = 2,
        retry_backoff: float = 1.5,
        user_agent: str = "JSMonitor/1.0",
        pacer: Optional[HostPacer] = None,
        verify_tls: bool = True,
    ) -> None:
        self.connect_timeout = connect_timeout
        self.read_timeout = read_timeout
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects
        self.max_retries = max_retries
        self.retry_backoff = retry_backoff
        self.user_agent = user_agent
        self.pacer = pacer or HostPacer(0.0)

        context = ssl.create_default_context()
        if not verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self._opener = urllib.request.build_opener(
            _NoRedirect(), urllib.request.HTTPSHandler(context=context)
        )

    # ------------------------------------------------------------------
    def fetch(
        self,
        url: str,
        *,
        allowlist: Optional[list[str]] = None,
        if_none_match: Optional[str] = None,
        if_modified_since: Optional[str] = None,
    ) -> FetchResult:
        """Fetch a URL, returning a FetchResult or raising FetchError."""
        current = ssrf.validate_url(url, allowlist=allowlist)
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "*/*",
            "Accept-Encoding": "identity",
        }
        if if_none_match:
            headers["If-None-Match"] = if_none_match
        if if_modified_since:
            headers["If-Modified-Since"] = if_modified_since

        attempts = 0
        last_error: Optional[Exception] = None

        while attempts <= self.max_retries:
            attempts += 1
            try:
                return self._fetch_once(current.url, headers, allowlist, attempts)
            except ContentTooLargeError:
                raise
            except FetchError as exc:
                last_error = exc
                if not exc.retryable or attempts > self.max_retries:
                    raise
                time.sleep(self.retry_backoff * (2 ** (attempts - 1)))
            except (urllib.error.URLError, socket.timeout, TimeoutError, OSError) as exc:
                last_error = exc
                reason = getattr(exc, "reason", exc)
                # DNS/connection failures are retryable; TLS/verify errors are not.
                retryable = not isinstance(reason, ssl.SSLError)
                if not retryable or attempts > self.max_retries:
                    raise FetchError(
                        f"Network error for {current.url}: {reason}",
                        retryable=retryable,
                    ) from exc
                time.sleep(self.retry_backoff * (2 ** (attempts - 1)))

        raise FetchError(f"Failed to fetch {url}: {last_error}")

    # ------------------------------------------------------------------
    def _fetch_once(
        self,
        url: str,
        headers: dict,
        allowlist: Optional[list[str]],
        attempt: int,
    ) -> FetchResult:
        """Fetch one URL, validating and following redirects manually."""
        redirects = 0
        current_url = url

        while True:
            parsed = ssrf.urlparse(current_url)
            self.pacer.wait(parsed.hostname or "")

            request = urllib.request.Request(current_url, headers=dict(headers))
            response = None
            try:
                response = self._opener.open(request, timeout=self._timeout)
            except urllib.error.HTTPError as exc:
                # A 3xx surfaces as an HTTPError because redirects are disabled
                # on the opener; treat it as a redirect, not a failure.
                if exc.code in (301, 302, 303, 307, 308):
                    location = exc.headers.get("Location") if exc.headers else None
                    if not location:
                        raise FetchError(
                            f"Redirect ({exc.code}) without a Location header "
                            f"from {current_url}",
                            status=exc.code,
                        ) from exc
                    redirects += 1
                    if redirects > self.max_redirects:
                        raise FetchError(
                            f"Too many redirects from {url}", status=exc.code
                        ) from exc
                    current_url = self._validate_hop(
                        current_url, location, allowlist
                    )
                    continue
                return self._handle_http_error(exc, current_url, attempt)
            except urllib.error.URLError as exc:
                reason = getattr(exc, "reason", exc)
                raise FetchError(
                    f"Network error for {current_url}: {reason}",
                    retryable=not isinstance(reason, ssl.SSLError),
                ) from exc

            with response:
                status = getattr(response, "status", 200)

                if status in (301, 302, 303, 307, 308):
                    location = response.headers.get("Location")
                    if not location:
                        raise FetchError(
                            f"Redirect ({status}) without a Location header "
                            f"from {current_url}",
                            status=status,
                        )
                    redirects += 1
                    if redirects > self.max_redirects:
                        raise FetchError(
                            f"Too many redirects from {url}", status=status
                        )
                    current_url = self._validate_hop(
                        current_url, location, allowlist
                    )
                    continue

                if status == 304:
                    return FetchResult(
                        url=url,
                        final_url=current_url,
                        status=304,
                        body=b"",
                        sha256="",
                        size=0,
                        content_type=response.headers.get("Content-Type", ""),
                        etag=response.headers.get("ETag"),
                        last_modified=response.headers.get("Last-Modified"),
                        headers=dict(response.headers),
                        not_modified=True,
                        attempts=attempt,
                    )

                if status >= 400:
                    raise FetchError(
                        f"HTTP {status} fetching {current_url}",
                        status=status,
                        retryable=status in _TRANSIENT_STATUS,
                    )

                body = self._read_bounded(response, current_url, status)
                sha = hashlib.sha256(body).hexdigest()

                return FetchResult(
                    url=url,
                    final_url=current_url,
                    status=status,
                    body=body,
                    sha256=sha,
                    size=len(body),
                    content_type=response.headers.get("Content-Type", ""),
                    etag=response.headers.get("ETag"),
                    last_modified=response.headers.get("Last-Modified"),
                    headers=dict(response.headers),
                    attempts=attempt,
                )

    def _validate_hop(
        self, from_url: str, location: str, allowlist: Optional[list[str]]
    ) -> str:
        """Re-validate a redirect target before it is followed.

        Every hop is checked for network safety (scheme, DNS, IP class) and,
        when a scope allowlist is in force, for scope.
        """
        try:
            next_target = ssrf.validate_redirect(from_url, location)
        except ssrf.SSRFError as exc:
            raise FetchError(f"Unsafe redirect from {from_url}: {exc}") from exc

        if allowlist is not None and not ssrf.host_in_scope(
            next_target.host, allowlist
        ):
            raise FetchError(
                f"Redirect to '{next_target.host}' leaves the configured "
                "authorization scope"
            )
        return next_target.url

    @property
    def _timeout(self) -> float:
        return self.connect_timeout + self.read_timeout

    # ------------------------------------------------------------------
    def _read_bounded(self, response, url: str, status: int) -> bytes:
        """Read the body while enforcing the byte ceiling."""
        declared = response.headers.get("Content-Length")
        if declared:
            try:
                if int(declared) > self.max_bytes:
                    raise ContentTooLargeError(
                        f"Response from {url} declares {declared} bytes which "
                        f"exceeds the {self.max_bytes} byte limit",
                        status=status,
                    )
            except ValueError:
                pass

        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = response.read(64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > self.max_bytes:
                raise ContentTooLargeError(
                    f"Response from {url} exceeded the {self.max_bytes} byte limit",
                    status=status,
                )
            chunks.append(chunk)
        return b"".join(chunks)

    # ------------------------------------------------------------------
    def _handle_http_error(
        self, exc: urllib.error.HTTPError, url: str, attempt: int
    ) -> FetchResult:
        status = exc.code
        if status == 304:
            return FetchResult(
                url=url,
                final_url=url,
                status=304,
                body=b"",
                sha256="",
                size=0,
                etag=exc.headers.get("ETag") if exc.headers else None,
                last_modified=(
                    exc.headers.get("Last-Modified") if exc.headers else None
                ),
                not_modified=True,
                attempts=attempt,
            )
        if status in _TRANSIENT_STATUS and attempt <= self.max_retries:
            raise FetchError(
                f"Transient HTTP {status} fetching {url}",
                status=status,
                retryable=True,
            )
        # 4xx/5xx is a real error state for the asset. Keep the retryable
        # classification so callers can tell transient from permanent failures
        # even after the retry budget is exhausted.
        raise FetchError(
            f"HTTP {status} fetching {url}",
            status=status,
            retryable=status in _TRANSIENT_STATUS,
        )


def build_fetcher_from_settings(settings) -> AssetFetcher:
    """Construct an AssetFetcher from a jsmon.config.Settings instance."""
    return AssetFetcher(
        connect_timeout=settings.connect_timeout,
        read_timeout=settings.read_timeout,
        max_bytes=settings.max_bytes,
        max_redirects=settings.max_redirects,
        max_retries=settings.max_retries,
        retry_backoff=settings.retry_backoff,
        user_agent=settings.user_agent,
        pacer=HostPacer(settings.per_host_min_interval),
    )
