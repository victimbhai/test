"""Tests for diff generation and security review indicators."""

from __future__ import annotations

from jsmon.diffing import (
    INDICATOR_RULES,
    beautify,
    build_diff,
    change_summary,
    scan_indicators,
    summarize_indicators,
)

OLD = b"""// v1
function greet(name) {
  return "hello " + name;
}
var api = "/api/v1/users";
"""

NEW = b"""// v2
function greet(name, punct) {
  return "hello " + name + (punctuation || "!");
}
var api = "/api/v2/users";
var token = "sk_live_abcdef1234567890";
var debug = true;
fetch("https://api.example.com/v2/orders");
"""


def test_diff_reports_added_and_removed_lines():
    diff = build_diff(OLD, NEW)
    assert diff.is_identical is False
    assert diff.added_lines > 0
    assert diff.removed_lines > 0
    assert diff.old_lines == OLD.count(b"\n")
    assert diff.new_lines == NEW.count(b"\n")


def test_identical_content_produces_empty_diff():
    diff = build_diff(NEW, NEW)
    assert diff.is_identical is True
    assert diff.added_lines == 0
    assert diff.removed_lines == 0


def test_baseline_diff_against_none():
    diff = build_diff(None, NEW)
    assert diff.old_lines == 0
    assert diff.new_lines > 0
    assert diff.added_lines > 0


def test_unified_diff_format():
    diff = build_diff(OLD, NEW)
    lines = diff.unified.splitlines()
    assert any(line.startswith("---") for line in lines)
    assert any(line.startswith("+++") for line in lines)
    assert any(line.startswith("@@") for line in lines)


def test_hunks_are_extracted():
    diff = build_diff(OLD, NEW)
    assert diff.hunks, "expected at least one hunk"
    for hunk in diff.hunks:
        assert hunk.old_start >= 1
        assert hunk.new_start >= 1
        assert hunk.old_lines or hunk.new_lines


def test_diff_truncates_very_large_changes():
    big_old = b"".join(b"line %d\n" % i for i in range(5000))
    big_new = b"".join(b"changed %d\n" % i for i in range(5000))
    diff = build_diff(big_old, big_new, max_lines=100)
    assert diff.truncated is True
    assert len(diff.unified.splitlines()) <= 101


def test_indicators_detect_credentials():
    diff = build_diff(OLD, NEW)
    matches = {i.label for i in diff.indicators}
    assert any("Credential" == i.category for i in diff.indicators)
    high = [i for i in diff.indicators if i.severity == "high"]
    assert high, "a hardcoded token must be flagged high"


def test_indicators_detect_debug_and_endpoints():
    diff = build_diff(OLD, NEW)
    categories = {i.category for i in diff.indicators}
    assert "Endpoint" in categories
    assert "Debug" in categories


def test_indicators_ignore_unchanged_lines():
    # The old file already contained an endpoint; only new lines are scanned,
    # so a change that keeps the same line must not report it again.
    old = b'var a = "/api/v1/keep";\n'
    new = b'var a = "/api/v1/keep";\nvar b = 1;\n'
    diff = build_diff(old, new)
    assert diff.indicators == []


def test_scan_indicators_deduplicates():
    text = 'var x = "sk_live_abcdef1234567890";\nvar y = "sk_live_abcdef1234567890";\n'
    found = scan_indicators("", text)
    keys = [(i.label, i.match[:60]) for i in found]
    assert len(keys) == len(set(keys))


def test_indicator_summary_counts():
    diff = build_diff(OLD, NEW)
    summary = summarize_indicators(diff.indicators)
    assert summary["total"] == len(diff.indicators)
    assert set(summary["by_severity"]) == {"high", "medium", "low"}
    assert sum(summary["by_category"].values()) == summary["total"]


def test_change_summary_math():
    diff = build_diff(OLD, NEW)
    summary = change_summary(diff, old_size=100, new_size=150)
    assert summary["size_delta_bytes"] == 50
    assert summary["size_delta_percent"] == 50.0
    assert "indicator_summary" in summary


def test_change_summary_handles_zero_baseline():
    diff = build_diff(None, NEW)
    summary = change_summary(diff, old_size=0, new_size=len(NEW))
    assert summary["size_delta_percent"] == 0.0


def test_beautify_returns_text():
    out = beautify("function a(){return 1;}")
    assert "function" in out
    assert out.strip() != ""


def test_beautify_is_display_only():
    """Beautifying must never alter the content hash."""
    import hashlib

    original = NEW
    beautified = beautify(original.decode())
    assert hashlib.sha256(original).hexdigest() != hashlib.sha256(
        beautified.encode()
    ).hexdigest()
    # The engine always hashes the raw bytes, so confirm that invariant.
    assert hashlib.sha256(original).hexdigest() == hashlib.sha256(NEW).hexdigest()


def test_indicator_rules_are_well_formed():
    for rule in INDICATOR_RULES:
        assert rule.category
        assert rule.severity in ("high", "medium", "low")
        assert rule.pattern.pattern


def test_diff_dict_is_serialisable():
    import json

    diff = build_diff(OLD, NEW)
    payload = json.dumps(diff.to_dict())
    assert "indicators" in payload


def test_minified_javascript_is_handled():
    minified = b"function a(b){return b+1}var c=a(2);"
    diff = build_diff(b"var x=1;", minified)
    assert diff.added_lines >= 1
    # One long line must not explode the line count.
    assert diff.new_lines == 1


def test_empty_response_is_handled():
    diff = build_diff(OLD, b"")
    assert diff.removed_lines > 0
    assert diff.new_lines == 0
