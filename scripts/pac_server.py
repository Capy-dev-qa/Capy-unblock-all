#!/usr/bin/env python3
"""Minimal PAC HTTP server for torification (browser-agnostic)."""

from __future__ import annotations

import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


PAC = Path(os.environ.get("TORIFICATION_PAC", "~/.config/torification/proxy.pac")).expanduser()
PORT = int(os.environ.get("TORIFICATION_PAC_PORT", "18767"))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        pass

    def do_GET(self) -> None:
        if self.path.split("?")[0] not in ("/proxy.pac", "/"):
            self.send_error(404)
            return
        if not PAC.is_file():
            self.send_error(503, "PAC not generated yet")
            return
        body = PAC.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "application/x-ns-proxy-autoconfig")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    print(f"PAC server http://127.0.0.1:{PORT}/proxy.pac → {PAC}", flush=True)
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()


if __name__ == "__main__":
    main()
