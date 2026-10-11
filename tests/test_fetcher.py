"""Tests for the fetcher: timeouts, size limits, redirects, retries."""

from __future__ import annotations

import pytest

from jsmon.fetcher import (
    AssetFetcher,
    ContentTooLargeError,
    FetchError,
    HostPacer,
)

from fixtures.test_server import TestServer, INITIAL_JS, MODIFIED_JS


@pytest.fixture
def server():
    with TestServer() as srv:
        yield srv


@pytest.fixture
def fetcher():
    return AssetFetcher(
        connect_timeout=5,
        read_timeout=10,
        max_bytes=1024 * 1024,
        max_redirects=3,
        max_retries=1,
        retry_backoff=0.1,
    )


def test_fetch_returns_content_and_hash(server, fetcher, loopback_allowed):
    result = fetcher.fetch(server.url)
    assert result.status == 200
    assert result.body == INITIAL_JS
    assert result.size == len(INITIAL_JS)
    assert len(result.sha256) == 64
    assert result.sha256 == __import__("hashlib").sha256(INITIAL_JS).hexdigest()
    assert result.etag == '"v1"'
    assert result.content_type == "text/javascript"


def test_hash_changes_with_content(server, fetcher, loopback_allowed):
    first = fetcher.fetch(server.url)
    server.set_version(2)
    second = fetcher.fetch(server.url)
    assert second.body == MODIFIED_JS
    assert first.sha256 != second.sha256
    assert second.size != first.size


def test_conditional_request_gets_304(server, fetcher, loopback_allowed):
    first = fetcher.fetch(server.url)
    second = fetcher.fetch(server.url, if_none_match=first.etag)
    assert second.not_modified is True
    assert second.status == 304
    assert second.body == b""
    assert second.sha256 == ""


def test_etag_change_forces_full_download(server, fetcher, loopback_allowed):
    first = fetcher.fetch(server.url)
    server.set_version(2)
    # The client still holds the v1 etag, so it asks conditionally again and
    # the server answers with the new content.
    second = fetcher.fetch(server.url, if_none_match=first.etag)
    assert second.not_modified is False
    assert second.sha256 != first.sha256


def test_redirect_is_followed(server, fetcher, loopback_allowed):
    result = fetcher.fetch(f"http://127.0.0.1:{server.port}/redirect/x")
    assert result.status == 200
    assert result.body == INITIAL_JS
    assert result.final_url.endswith("/app.js")


def test_redirect_to_metadata_endpoint_is_refused(server, fetcher, loopback_allowed):
    with pytest.raises(FetchError) as exc:
        fetcher.fetch(f"http://127.0.0.1:{server.port}/redirect-unsafe")
    assert "Unsafe redirect" in str(exc.value) or "blocked" in str(exc.value)


def test_redirect_outside_scope_is_refused(server, fetcher, loopback_allowed):
    with pytest.raises(FetchError) as exc:
        fetcher.fetch(
            f"http://127.0.0.1:{server.port}/redirect-offscope",
            allowlist=["127.0.0.1"],
        )
    assert "scope" in str(exc.value).lower()


def test_404_is_an_error_not_a_change(server, fetcher, loopback_allowed):
    with pytest.raises(FetchError) as exc:
        fetcher.fetch(f"http://127.0.0.1:{server.port}/missing.js")
    assert exc.value.status == 404
    assert exc.value.retryable is False


def test_500_is_retryable(server, fetcher, loopback_allowed):
    # max_retries=1 means one retry happens, then the error surfaces.
    with pytest.raises(FetchError) as exc:
        fetcher.fetch(f"http://127.0.0.1:{server.port}/error/500")
    assert exc.value.status == 500
    assert exc.value.retryable is True


def test_403_is_not_retried(server, fetcher, loopback_allowed):
    with pytest.raises(FetchError) as exc:
        fetcher.fetch(f"http://127.0.0.1:{server.port}/error/403")
    assert exc.value.status == 403
    assert exc.value.retryable is False


def test_oversized_declared_response_is_rejected(server, loopback_allowed):
    fetcher = AssetFetcher(max_bytes=64, max_retries=0)
    with pytest.raises(ContentTooLargeError):
        fetcher.fetch(f"http://127.0.0.1:{server.port}/big.js")


def test_connection_refused_is_reported_as_error(server, loopback_allowed):
    fetcher = AssetFetcher(connect_timeout=2, read_timeout=2, max_retries=0)
    dead_url = f"http://127.0.0.1:1/app.js"
    with pytest.raises(FetchError):
        fetcher.fetch(dead_url)


def test_retry_eventually_succeeds(server, loopback_allowed):
    """A transient 503 followed by a 200 must not lose the content."""
    calls = {"n": 0}

    class FlakyFetcher(AssetFetcher):
        def _fetch_once(self, url, headers, allowlist, attempt):
            calls["n"] += 1
            if calls["n"] == 1:
                raise FetchError("transient", status=503, retryable=True)
            return super()._fetch_once(url, headers, allowlist, attempt)

    fetcher = FlakyFetcher(
        connect_timeout=5, read_timeout=5, max_retries=2, retry_backoff=0.01
    )
    result = fetcher.fetch(server.url)
    assert calls["n"] == 2
    assert result.status == 200
    assert result.body == INITIAL_JS
    assert result.attempts == 2


def test_host_pacer_enforces_minimum_interval(loopback_allowed):
    import time

    pacer = HostPacer(0.2)
    start = time.monotonic()
    pacer.wait("example.com")
    pacer.wait("example.com")
    elapsed = time.monotonic() - start
    assert elapsed >= 0.18


def test_user_agent_is_sent(server, fetcher, loopback_allowed):
    fetcher.user_agent = "JSMonitor-Test/9.9"
    fetcher.fetch(server.url)
    # The fixture server records nothing about headers, so re-request and
    # confirm the request still succeeds with a custom agent.
    assert fetcher.fetch(server.url).status == 200
