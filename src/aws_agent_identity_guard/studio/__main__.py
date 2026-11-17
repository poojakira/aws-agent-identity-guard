"""Single-user loopback HTTP interface. No AWS client or credentials are loaded."""

from __future__ import annotations

import argparse
import json
import time
from collections import deque
from contextlib import suppress
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from .analysis import InputError, provenance, review_change

ASSETS = Path(__file__).parent
MAX_BODY_BYTES = 196608


class StudioServer(HTTPServer):
    def __init__(self, address, handler):
        super().__init__(address, handler)
        self.hits: deque[float] = deque()


def unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InputError("Duplicate request fields are not supported")
        result[key] = value
    return result


class Handler(BaseHTTPRequestHandler):
    @property
    def studio(self) -> StudioServer:
        if not isinstance(self.server, StudioServer):
            raise RuntimeError("Unexpected internal server configuration")
        return self.server

    def setup(self):
        super().setup()
        self.connection.settimeout(5)

    def log_message(self, format, *args):
        pass

    def respond(self, status, body, content_type="application/json"):
        data = json.dumps(body).encode() if content_type == "application/json" else body
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        self.end_headers()
        with suppress(BrokenPipeError, ConnectionResetError):
            self.wfile.write(data)

    def boundary(self):
        authority = f"127.0.0.1:{self.studio.server_port}"
        if (
            self.client_address[0] != "127.0.0.1"
            or len(self.headers.get_all("Host", [])) != 1
            or len(self.headers.get_all("Origin", [])) > 1
            or self.headers.get("Host") != authority
            or self.headers.get("Origin", f"http://{authority}") != f"http://{authority}"
        ):
            self.respond(403, {"error": "Only the local same-origin operator is allowed"})
            return False
        return True

    def do_GET(self):
        if not self.boundary():
            return
        if self.path == "/health":
            self.respond(200, {"status": "ok", **provenance()})
        elif self.path in {"/", "/studio.js", "/studio.css"}:
            filename, kind = {
                "/": ("index.html", "text/html"),
                "/studio.js": ("studio.js", "text/javascript"),
                "/studio.css": ("studio.css", "text/css"),
            }[self.path]
            self.respond(200, (ASSETS / filename).read_bytes(), kind)
        else:
            self.respond(404, {"error": "Not found"})

    def do_POST(self):
        if not self.boundary():
            return
        if self.path != "/api/review":
            self.respond(404, {"error": "Not found"})
            return
        now = time.monotonic()
        while self.studio.hits and self.studio.hits[0] <= now - 60:
            self.studio.hits.popleft()
        if len(self.studio.hits) >= 30:
            self.respond(429, {"error": "Request limit reached; retry in one minute"})
            return
        self.studio.hits.append(now)
        if (
            self.headers.get("Transfer-Encoding")
            or self.headers.get("Content-Type") != "application/json"
        ):
            self.respond(415, {"error": "A bounded application/json body is required"})
            return
        try:
            if len(self.headers.get_all("Content-Length", [])) != 1:
                raise InputError("One Content-Length is required")
            length = int(self.headers["Content-Length"])
            if not 1 <= length <= MAX_BODY_BYTES:
                self.respond(413, {"error": "Request body must be 1 to 196608 bytes"})
                return
            # Read exactly the declared bounded body; do not buffer an unlimited stream.
            body = self.rfile.read(length)
            if len(body) != length:
                raise InputError("Incomplete request body")
            payload = json.loads(body, object_pairs_hook=unique_pairs)
            if not isinstance(payload, dict):
                raise InputError("Request must be a JSON object")
            report = review_change(payload)
        except InputError as exc:
            self.respond(400, {"error": str(exc)})
            return
        except (ValueError, TypeError, RecursionError, UnicodeError):
            self.respond(400, {"error": "Invalid request JSON or unsupported policy structure"})
            return
        except Exception:
            self.respond(500, {"error": "Static engine failed; no successful analysis established"})
            return
        self.respond(200, report)


def create_server(port=8762):
    return StudioServer(("127.0.0.1", port), Handler)


def main():
    parser = argparse.ArgumentParser(
        description="Single-user local IAM Permission Engineering Studio"
    )
    parser.add_argument("--port", type=int, default=8762)
    args = parser.parse_args()
    with create_server(args.port) as server:
        print(
            f"IAM Permission Engineering Studio: http://127.0.0.1:{server.server_port}", flush=True
        )
        with suppress(KeyboardInterrupt):
            server.serve_forever()


if __name__ == "__main__":
    main()
