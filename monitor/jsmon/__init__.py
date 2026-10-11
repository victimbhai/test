"""JSMon — JavaScript change monitoring engine (refactored).

This package is a rewrite of the original single-file ``jsmon.py`` CLI into a
durable, cloud-runnable monitoring engine.

Module map
----------
``config``        environment-driven settings
``ssrf``          URL validation + SSRF protection
``fetcher``       bounded HTTP fetching with redirect validation
``discovery``     JavaScript discovery from an authorized page
``diffing``       diff generation + security review indicators
``storage``       immutable snapshot storage (Supabase Storage)
``database``      persistent state (Supabase PostgREST or direct Postgres)
``notifications`` Telegram / Slack delivery
``runner``        the scan loop (replaces ``main()`` in the original)

Compatibility with the original tool
------------------------------------
The original CLI behaviours are preserved in spirit:

* a first-time fetch creates a baseline rather than reporting a change
* unchanged content is skipped
* a changed file produces a notification with the old/new hashes, the file
  sizes, and a diff

Everything that made it unreliable in the cloud — local JSON state,
ephemeral snapshot files, no timeouts, notification-mandatory startup — has
been replaced with persistent storage and explicit error handling.
"""

__version__ = "2.0.0"

__all__ = [
    "config",
    "ssrf",
    "fetcher",
    "discovery",
    "diffing",
    "storage",
    "database",
    "notifications",
    "runner",
]
