"""Pytest configuration and shared fixtures for the monitoring engine suite."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "monitor"))
sys.path.insert(0, os.path.dirname(__file__))

# NOTE: JSMON_TEST_ALLOW_LOOPBACK is deliberately NOT set globally here.
#
# The negative SSRF tests must fail closed, i.e. they assert that loopback and
# private ranges are rejected with the hatch *off*. Tests that talk to the
# loopback fixture server opt in with the `loopback_allowed` fixture below.


@pytest.fixture
def loopback_allowed(monkeypatch):
    """Allow loopback fetches for the duration of one test."""
    monkeypatch.setenv("JSMON_TEST_ALLOW_LOOPBACK", "1")
    yield


@pytest.fixture
def loopback_blocked(monkeypatch):
    """Assert the SSRF guard is armed for a test (default state)."""
    monkeypatch.delenv("JSMON_TEST_ALLOW_LOOPBACK", raising=False)
    from jsmon import ssrf as ssrf_module

    assert ssrf_module._env_allows_loopback() is False, (
        "loopback must be blocked unless a test opts in"
    )
    yield
