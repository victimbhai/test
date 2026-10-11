"""Tests for URL validation and SSRF protection."""

from __future__ import annotations

import os
import socket
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from jsmon import ssrf

HOST_ALLOWLIST = ["example.com"]


@pytest.mark.parametrize(
    "url",
    [
        "https://example.com/static/main.js",
        "http://example.com/a/b.js?v=2",
        "https://sub.example.com/deep/path/app.mjs",
    ],
)
def test_accepts_in_scope_public_urls(url):
    parsed = ssrf.validate_url(url, allowlist=HOST_ALLOWLIST, resolve=False)
    assert parsed.scheme in ("http", "https")
    assert parsed.host.endswith("example.com")


@pytest.mark.parametrize(
    "url",
    [
        # localhost / loopback
        "http://localhost/admin.js",
        "http://127.0.0.1/config.js",
        "http://2130706433/app.js",
        "http://[::1]/app.js",
        # private ranges
        "http://10.0.0.5/app.js",
        "http://192.168.1.1/app.js",
        "http://172.16.0.1/app.js",
        # cloud metadata
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/computeMetadata/v1/",
        # non-http schemes
        "file:///etc/passwd",
        "gopher://example.com/",
        "ftp://example.com/app.js",
        "javascript:alert(1)",
        "data:text/javascript,alert(1)",
        # malformed
        "",
        "   ",
        "not a url",
    ],
)
def test_rejects_unsafe_or_out_of_scope_urls(url):
    with pytest.raises(ssrf.SSRFError):
        ssrf.validate_url(url, allowlist=HOST_ALLOWLIST, resolve=False)


def test_rejects_host_outside_scope():
    with pytest.raises(ssrf.SSRFError) as exc:
        ssrf.validate_url("https://evil.com/app.js", allowlist=HOST_ALLOWLIST,
                          resolve=False)
    assert "scope" in str(exc.value).lower()


def test_no_allowlist_allows_any_public_host():
    # With no allowlist the caller has not restricted scope; the public host
    # must still pass.
    parsed = ssrf.validate_url("https://any-host.example/app.js", allowlist=None,
                               resolve=False)
    assert parsed.host == "any-host.example"


def test_private_dns_resolution_is_blocked(loopback_blocked):
    """A public hostname that resolves to a private IP must be rejected."""
    server_holder = {}

    class RedirectHandler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

    # Bind a loopback server and resolve it by a name that points at 127.0.0.1.
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
    server_holder["httpd"] = httpd
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    try:
        # 'localhost' resolves to 127.0.0.1, which is a blocked network.
        with pytest.raises(ssrf.SSRFError):
            ssrf.validate_url(
                f"http://localhost:{port}/app.js", resolve=True, allowlist=None
            )
    finally:
        httpd.shutdown()
        httpd.server_close()


def test_redirect_into_private_network_is_rejected(loopback_blocked):
    with pytest.raises(ssrf.SSRFError):
        ssrf.validate_redirect("https://example.com/a.js", "http://169.254.169.254/")


def test_redirect_out_of_scope_detected_by_caller():
    # validate_redirect only enforces network safety; scope is enforced by the
    # caller using host_in_scope. Use a literal IP so the test never depends on
    # public DNS.
    target = ssrf.validate_redirect(
        "https://example.com/a.js", "https://93.184.216.34/b.js"
    )
    assert target.host == "93.184.216.34"
    assert ssrf.host_in_scope("93.184.216.34", ["example.com"]) is False


def test_resolution_failure_is_rejected(loopback_blocked):
    with pytest.raises(ssrf.SSRFError):
        ssrf.validate_url(
            "https://this-host-does-not-exist-jsmon-test.invalid/app.js",
            resolve=True,
        )


@pytest.mark.parametrize(
    "host,allowlist,expected",
    [
        ("example.com", ["example.com"], True),
        ("sub.example.com", ["example.com"], True),
        ("deep.sub.example.com", [".example.com"], True),
        ("notexample.com", ["example.com"], False),
        ("example.com.evil.net", ["example.com"], False),
        ("cdn.other.net", ["example.com", "other.net"], True),
        ("anything.test", [], True),
    ],
)
def test_host_in_scope(host, allowlist, expected):
    assert ssrf.host_in_scope(host, allowlist) is expected


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("https://EXAMPLE.com:443/a.js", "https://example.com/a.js"),
        ("http://example.com:80/a.js", "http://example.com/a.js"),
        ("https://example.com", "https://example.com/"),
        ("https://example.com/a.js#frag", "https://example.com/a.js"),
        ("https://example.com/a.js?b=2&a=1", "https://example.com/a.js?a=1&b=2"),
        ("https://example.com/a.js?a=1&a=1", "https://example.com/a.js?a=1&a=1"),
    ],
)
def test_normalize_url(raw, expected):
    assert ssrf.normalize_url(raw) == expected


def test_parse_url_list():
    from jsmon import discovery

    text = """
    # a comment
    https://example.com/a.js

    https://example.com/b.js
    https://example.com/a.js
    not-a-url
    http://localhost/x.js
    """
    valid, invalid = discovery.parse_url_list(text)
    assert valid == ["https://example.com/a.js", "https://example.com/b.js"]
    assert len(invalid) == 2
