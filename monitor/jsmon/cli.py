"""CLI helpers for URL discovery and target validation.

Used by the dashboard's server-side API routes (via subprocess-free direct
import) and useful standalone:

    python -m jsmon.discover https://example.com --allowlist example.com
    python -m jsmon.validate https://example.com/app.js
"""

from __future__ import annotations

import argparse
import json
import sys

from . import discovery, ssrf


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="jsmon-discover")
    sub = parser.add_subparsers(dest="command", required=True)

    disc = sub.add_parser("discover", help="extract JavaScript URLs from a page")
    disc.add_argument("url")
    disc.add_argument("--allowlist", help="comma-separated host allowlist")
    disc.add_argument("--no-out-of-scope", action="store_true")
    disc.add_argument(
        "--fetch", action="store_true", help="fetch the page (default: read stdin)"
    )

    val = sub.add_parser("validate", help="validate one or more URLs")
    val.add_argument("urls", nargs="+")

    args = parser.parse_args(argv)

    if args.command == "validate":
        allowlist = None
        ok = True
        for url in args.urls:
            try:
                parsed = ssrf.validate_url(url, allowlist=allowlist)
                print(json.dumps({"url": url, "valid": True, "host": parsed.host,
                                  "scheme": parsed.scheme}))
            except ssrf.SSRFError as exc:
                ok = False
                print(json.dumps({"url": url, "valid": False, "error": str(exc)}))
        return 0 if ok else 1

    if args.command == "discover":
        allowlist = (
            [h.strip() for h in args.allowlist.split(",") if h.strip()]
            if args.allowlist
            else None
        )
        if args.fetch:
            from .fetcher import AssetFetcher

            fetcher = AssetFetcher(user_agent="JSMonitor/1.0 (discovery)")
            result = fetcher.fetch(args.url, allowlist=allowlist)
            html = result.body.decode("utf-8", "replace")
        else:
            html = sys.stdin.read()

        found = discovery.discover_from_html(
            html,
            args.url,
            allowlist=allowlist,
            include_out_of_scope=not args.no_out_of_scope,
        )
        print(
            json.dumps(
                {
                    "page_url": found.page_url,
                    "in_scope": found.in_scope,
                    "out_of_scope": found.out_of_scope,
                    "total_found": found.total_found,
                    "errors": found.errors,
                },
                indent=2,
            )
        )
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
