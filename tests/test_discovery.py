"""Tests for JavaScript discovery from an authorized page."""

from __future__ import annotations

from jsmon import discovery

PAGE_URL = "https://app.example.com/index.html"

HTML = """
<!doctype html>
<html>
<head>
  <script src="/static/main.js"></script>
  <script src="https://cdn.example.com/assets/vendor.js"></script>
  <script type="module" src="/js/module-entry.mjs"></script>
  <link rel="modulepreload" href="/js/chunk-a.js">
  <link rel="preload" href="/js/chunk-b.js" as="script">
  <link rel="preload" href="/fonts/type.woff2" as="font">
  <link rel="stylesheet" href="/css/app.css">
  <script src="//cdn.other.net/tracker.js"></script>
  <script src="data:text/javascript,void(0)"></script>
  <script defer src="/static/main.js"></script>
</head>
<body><h1>hi</h1></body>
</html>
"""


def test_discovers_same_host_scripts():
    result = discovery.discover_from_html(HTML, PAGE_URL, allowlist=["app.example.com"])
    urls = " ".join(result.in_scope)
    assert "https://app.example.com/static/main.js" in urls
    assert "https://app.example.com/js/module-entry.mjs" in urls
    assert "https://app.example.com/js/chunk-a.js" in urls
    assert "https://app.example.com/js/chunk-b.js" in urls


def test_third_party_is_reported_but_not_enrolled():
    result = discovery.discover_from_html(
        HTML, PAGE_URL, allowlist=["app.example.com"]
    )
    in_scope = " ".join(result.in_scope)
    assert "cdn.other.net" not in in_scope
    assert any("cdn.other.net" in u for u in result.out_of_scope)


def test_allowlist_can_include_cdn():
    result = discovery.discover_from_html(
        HTML, PAGE_URL, allowlist=["app.example.com", "cdn.example.com"]
    )
    assert any("cdn.example.com/assets/vendor.js" in u for u in result.in_scope)


def test_non_javascript_is_ignored():
    result = discovery.discover_from_html(HTML, PAGE_URL, allowlist=["app.example.com"])
    joined = " ".join(result.in_scope + result.out_of_scope)
    assert "app.css" not in joined
    assert "type.woff2" not in joined


def test_duplicates_are_removed():
    result = discovery.discover_from_html(HTML, PAGE_URL, allowlist=["app.example.com"])
    assert len(result.in_scope) == len(set(result.in_scope))


def test_data_urls_and_empty_src_are_skipped():
    result = discovery.discover_from_html(HTML, PAGE_URL, allowlist=["app.example.com"])
    assert not any(u.startswith("data:") for u in result.in_scope)
    assert result.total_found > 0


def test_default_scope_is_page_host():
    result = discovery.discover_from_html(HTML, PAGE_URL, allowlist=None)
    for url in result.in_scope:
        assert "app.example.com" in url


def test_no_scripts_returns_empty():
    result = discovery.discover_from_html(
        "<html><body>nothing</body></html>", PAGE_URL, allowlist=["app.example.com"]
    )
    assert result.in_scope == []
    assert result.total_found == 0


def test_relative_urls_are_absolutised():
    html = '<script src="assets/app.js"></script>'
    result = discovery.discover_from_html(
        html, "https://app.example.com/dashboard/page.html",
        allowlist=["app.example.com"],
    )
    assert "https://app.example.com/dashboard/assets/app.js" in result.in_scope


def test_query_strings_are_preserved():
    html = '<script src="/app.js?v=abc123&x=1"></script>'
    result = discovery.discover_from_html(
        html, PAGE_URL, allowlist=["app.example.com"]
    )
    assert any("app.js?v=abc123&x=1" in u for u in result.in_scope)


def test_parse_url_list_bulk_import():
    text = """
    # my program targets
    https://a.example.com/one.js
    https://b.example.com/two.js
    https://a.example.com/one.js
    garbage line
    """
    valid, invalid = discovery.parse_url_list(text)
    assert valid == [
        "https://a.example.com/one.js",
        "https://b.example.com/two.js",
    ]
    assert len(invalid) == 1
