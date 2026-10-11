"""URL validation and SSRF protection for monitoring targets.

The monitoring engine fetches arbitrary URLs supplied by the operator, so it
must never be pointed at internal infrastructure. Every fetch is validated
against scheme, DNS resolution and IP classification, and every redirect hop
is re-validated before it is followed.
"""

from __future__ import annotations

import ipaddress
import os
import socket
from dataclasses import dataclass
from urllib.parse import urlparse, urljoin

ALLOWED_SCHEMES = ("http", "https")

# Networks that are always rejected as fetch destinations.
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local + cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.0.0.0/24"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::ffff:0:0/96"),
]

# Networks the test-only hatch is allowed to relax.
_LOOPBACK_NETWORKS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)

_BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata",
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "instance-data.ec2.internal",
}


class SSRFError(ValueError):
    """Raised when a URL fails validation as a safe monitoring target."""


@dataclass(frozen=True)
class ParsedTarget:
    """A validated monitoring target."""

    url: str
    scheme: str
    host: str
    port: int
    path: str

    @property
    def netloc(self) -> str:
        default_port = 443 if self.scheme == "https" else 80
        if self.port and self.port != default_port:
            return f"{self.host}:{self.port}"
        return self.host


def _is_blocked_ip(
    ip: ipaddress._BaseAddress, *, allow_loopback: bool = False
) -> bool:
    """Classify an IP address as blocked or permitted.

    ``allow_loopback`` (tests only) permits 127.0.0.0/8 and ::1 so the local
    fixture server can be exercised. The link-local range 169.254.0.0/16 —
    which covers the cloud metadata endpoints — is NEVER relaxed, and neither
    is the blocked-hostname list.
    """
    # An IPv4-mapped IPv6 address (::ffff:127.0.0.1) must be judged by the
    # IPv4 address it wraps, otherwise the mapped range slips through.
    if (
        isinstance(ip, ipaddress.IPv6Address)
        and ip.ipv4_mapped is not None
        and isinstance(ip.ipv4_mapped, ipaddress.IPv4Address)
    ):
        return _is_blocked_ip(ip.ipv4_mapped, allow_loopback=allow_loopback)

    for net in _BLOCKED_NETWORKS:
        if ip.version != net.version:
            continue
        if allow_loopback and net in _LOOPBACK_NETWORKS:
            continue
        if ip in net:
            return True
    return False


def _classify(
    host: str, *, allow_loopback: bool = False
) -> tuple[bool, list[str]]:
    """Resolve a hostname and classify every resolved address.

    Returns (is_safe, resolved_ips). ``allow_loopback`` relaxes the loopback
    checks for tests only; the cloud metadata and link-local ranges stay
    blocked regardless, because those are the SSRF targets that matter.
    """
    # A literal IP address never needs DNS.
    try:
        literal = ipaddress.ip_address(host)
        return (
            not _is_blocked_ip(literal, allow_loopback=allow_loopback)
        ), [str(literal)]
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise SSRFError(f"Could not resolve host '{host}': {exc}") from exc

    ips: list[str] = []
    for info in infos:
        sockaddr = info[4]
        ips.append(sockaddr[0])

    if not ips:
        raise SSRFError(f"Host '{host}' resolved to no addresses")

    for raw in ips:
        try:
            ip = ipaddress.ip_address(raw)
        except ValueError:
            return False, ips
        if _is_blocked_ip(ip, allow_loopback=allow_loopback):
            return False, ips
    return True, ips


def host_in_scope(host: str, allowlist: list[str] | None) -> bool:
    """Check a hostname against an explicit scope allowlist.

    An entry matches when it equals the host, is a parent domain of it
    (``.example.com`` style suffix match), or is a literal IP that equals the
    host.
    """
    if not allowlist:
        # No allowlist configured: the caller decided not to restrict scope.
        return True
    host = host.lower().rstrip(".")
    for entry in allowlist:
        entry = (entry or "").strip().lower().lstrip("*.").rstrip(".")
        if not entry:
            continue
        if host == entry or host.endswith("." + entry):
            return True
    return False


# Test-only escape hatch. The test suite runs a controlled HTTP server on
# loopback and must be able to exercise the fetcher against it. Production
# code never sets this. Read dynamically so tests can toggle it per-test.
def _env_allows_loopback() -> bool:
    return os.environ.get("JSMON_TEST_ALLOW_LOOPBACK", "").lower() in (
        "1",
        "true",
        "yes",
    )


def validate_url(
    url: str,
    *,
    allowlist: list[str] | None = None,
    resolve: bool = True,
) -> ParsedTarget:
    """Validate a URL as a safe, in-scope monitoring target.

    Raises SSRFError when the URL is malformed, uses an unsupported scheme,
    resolves into a blocked network, or falls outside the configured scope.
    """
    if not isinstance(url, str) or not url.strip():
        raise SSRFError("URL must be a non-empty string")

    candidate = url.strip()
    try:
        parsed = urlparse(candidate)
    except ValueError as exc:
        raise SSRFError(f"Malformed URL: {exc}") from exc

    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise SSRFError(
            f"Unsupported URL scheme '{scheme or '(none)'}': only http/https allowed"
        )

    if not parsed.hostname:
        raise SSRFError("URL has no hostname")

    host = parsed.hostname.lower().rstrip(".")
    if not _env_allows_loopback() and host in _BLOCKED_HOSTNAMES:
        raise SSRFError(f"Host '{host}' is a reserved internal name")

    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise SSRFError(f"Invalid port: {exc}") from exc

    if not host_in_scope(host, allowlist):
        raise SSRFError(
            f"Host '{host}' is outside the configured authorization scope"
        )

    if resolve:
        safe, ips = _classify(host, allow_loopback=_env_allows_loopback())
        if not safe:
            raise SSRFError(
                f"Host '{host}' resolves to a blocked address ({', '.join(ips[:4])})"
            )

    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    return ParsedTarget(
        url=candidate, scheme=scheme, host=host, port=port, path=path
    )


def validate_redirect(from_url: str, location: str) -> ParsedTarget:
    """Validate a redirect target before it is followed."""
    absolute = urljoin(from_url, location)
    return validate_url(absolute, allowlist=None, resolve=True)


def normalize_url(url: str) -> str:
    """Canonicalise a URL so identical assets compare equal.

    Lowercases scheme and host, removes the default port, strips the fragment,
    and sorts query parameters. The path is left untouched apart from
    collapsing empty paths to '/'.
    """
    parsed = urlparse(url.strip())
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower().rstrip(".")
    try:
        port = parsed.port
    except ValueError:
        port = None
    default = 443 if scheme == "https" else 80
    netloc = host if port in (None, default) else f"{host}:{port}"
    if parsed.username or parsed.password:
        netloc = f"{parsed.username}@{netloc}"

    path = parsed.path or "/"
    query = parsed.query
    if query:
        pairs = sorted(q for q in query.split("&") if q)
        query = "&".join(pairs)

    rebuilt = f"{scheme}://{netloc}{path}"
    if query:
        rebuilt += f"?{query}"
    return rebuilt
