"""Entry point for the monitoring worker (run by GitHub Actions)."""

from __future__ import annotations

import sys

from jsmon.runner import main

if __name__ == "__main__":
    sys.exit(main())
