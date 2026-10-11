"""Test fixtures: a controlled HTTP server that serves mutable JavaScript.

The server exposes two endpoints that the tests flip between an initial and a
modified version, so the full baseline -> unchanged -> changed cycle can be
verified against a real socket without touching the network.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

INITIAL_JS = b"""// test asset v1
function greet(name) {
  return "hello " + name;
}
var api = "/api/v1/users";
console.log(greet("world"));
"""

MODIFIED_JS = b"""// test asset v2
function greet(name, punctuation) {
  return "hello " + name + (punctuation || "!");
}
var api = "/api/v2/users";
var token = "sk_live_abcdef1234567890";
console.log(greet("world", "?"));
"""


class StatefulHandler(BaseHTTPRequestHandler):
    # Class-level state shared by every request in the process.
    version = 1
    etag = '"v1"'
    status_code = 200
    has_custom = False
    custom_body = b""
    request_log: list[str] = []

    def log_message(self, fmt, *args):  # silence stderr noise
        pass

    def _send(self, body: bytes, content_type: str, code: int = 200, extra=None):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def do_GET(self):  # noqa: N802 (http.server API)
        StatefulHandler.request_log.append(self.path)

        if self.path.startswith("/error/"):
            code = int(self.path.split("/")[2])
            self._send(b"nope", "text/plain", code)
            return

        if self.path.startswith("/redirect/"):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{self.server.server_port}/app.js")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if self.path.startswith("/redirect-unsafe"):
            # Points at the cloud metadata endpoint: must never be followed.
            self.send_response(302)
            self.send_header("Location", "http://169.254.169.254/latest/meta-data/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if self.path.startswith("/redirect-offscope"):
            self.send_response(302)
            self.send_header("Location", "https://evil.example.net/app.js")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if self.path.startswith("/big.js"):
            self.send_response(200)
            self.send_header("Content-Type", "text/javascript")
            self.send_header("Content-Length", str(30 * 1024 * 1024))
            self.end_headers()
            # Write a small amount then hang up: the size ceiling must catch it.
            self.wfile.write(b"A" * 1024)
            self.close_connection = True
            return

        if self.path.startswith("/app.js"):
            if_none_match = self.headers.get("If-None-Match")
            if if_none_match and if_none_match == StatefulHandler.etag:
                self._send(b"", "text/javascript", 304, {"ETag": StatefulHandler.etag})
                return
            if StatefulHandler.has_custom:
                body = StatefulHandler.custom_body
            else:
                body = INITIAL_JS if StatefulHandler.version == 1 else MODIFIED_JS
            self._send(
                body,
                "text/javascript",
                200,
                {"ETag": StatefulHandler.etag,
                 "Last-Modified": "Wed, 21 Oct 2015 07:28:00 GMT"},
            )
            return

        if self.path.startswith("/"):
            self._send(b"<html><body>not found</body></html>", "text/html", 404)
            return

        self._send(b"", "text/plain", 404)

    def do_HEAD(self):  # noqa: N802
        self.do_GET()


class TestServer:  # noqa: E225  (fixture helper, not a test class)
    """Context manager wrapping the fixture HTTP server."""

    def __init__(self):
        self.httpd: ThreadingHTTPServer | None = None
        self.thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        assert self.httpd is not None, "server not started"
        return self.httpd.server_address[1]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/app.js"

    def __enter__(self) -> "TestServer":
        self.reset()
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), StatefulHandler)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, *exc_info) -> None:
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        # Reset again so leaked state cannot bleed into the next test.
        self.reset()

    @staticmethod
    def reset() -> None:
        """Restore the handler to a pristine state.

        State is class-level, so a test that sets custom content and then
        fails early could otherwise leak it into every later test.
        """
        StatefulHandler.version = 1
        StatefulHandler.etag = '"v1"'
        StatefulHandler.status_code = 200
        StatefulHandler.has_custom = False
        StatefulHandler.custom_body = b""
        StatefulHandler.request_log = []

    # -- helpers -------------------------------------------------------
    def set_version(self, version: int) -> None:
        StatefulHandler.version = version
        StatefulHandler.etag = f'"v{version}"'

    def set_content(self, content: bytes) -> None:
        """Serve arbitrary content once (used for one-off changes)."""
        StatefulHandler.custom_body = content
        StatefulHandler.has_custom = True
        StatefulHandler.etag = '"custom"'

    def clear_custom(self) -> None:
        StatefulHandler.has_custom = False
        StatefulHandler.custom_body = b""
        StatefulHandler.etag = f'"v{StatefulHandler.version}"'

    def page_url(self, html: str) -> str:
        """Serve an arbitrary HTML body at /page.html and return its URL."""
        return f"http://127.0.0.1:{self.port}/page.html"
