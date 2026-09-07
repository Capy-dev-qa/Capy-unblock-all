"""Local HTTP CONNECT proxy that tunnels through Tor SOCKS5."""

from __future__ import annotations

import logging
import os
import select
import socket
import threading
from urllib.parse import urlsplit

from torification.socks5 import SocksError, socks5_connect

log = logging.getLogger("torification.cursor-proxy")
_BUF = 65536


def _splice(a: socket.socket, b: socket.socket) -> None:
    sockets = [a, b]
    try:
        while True:
            r, _, x = select.select(sockets, [], sockets, 120)
            if x or not r:
                break
            for src in r:
                dst = b if src is a else a
                try:
                    data = src.recv(_BUF)
                except OSError:
                    return
                if not data:
                    return
                try:
                    dst.sendall(data)
                except OSError:
                    return
    finally:
        for s in sockets:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                s.close()
            except OSError:
                pass


def _read_headers(conn: socket.socket) -> bytes:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > 64_000:
            break
    return buf


def _handle_client(conn: socket.socket, socks_host: str, socks_port: int) -> None:
    conn.settimeout(30)
    try:
        raw = _read_headers(conn)
        if not raw:
            return
        head, _, rest = raw.partition(b"\r\n\r\n")
        first = head.split(b"\r\n", 1)[0].decode("latin1", "replace")
        parts = first.split()
        if len(parts) < 2:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            return
        method, target = parts[0].upper(), parts[1]
        if method == "CONNECT":
            hostport = target
            if ":" in hostport:
                host, port_s = hostport.rsplit(":", 1)
            else:
                host, port_s = hostport, "443"
            try:
                port = int(port_s)
            except ValueError:
                conn.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                return
            try:
                remote = socks5_connect(host, port, socks_host, socks_port)
            except (OSError, SocksError) as exc:
                log.info("CONNECT %s:%s failed: %s", host, port, exc)
                conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                return
            conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            if rest:
                try:
                    remote.sendall(rest)
                except OSError:
                    remote.close()
                    return
            conn.settimeout(None)
            _splice(conn, remote)
            return
        parsed = urlsplit(target)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if not host:
            conn.sendall(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
            return
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        try:
            remote = socks5_connect(host, port, socks_host, socks_port)
        except (OSError, SocksError) as exc:
            log.info("%s %s failed: %s", method, host, exc)
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
            return
        req_line = f"{method} {path} HTTP/1.1\r\n".encode("latin1")
        header_block = head.split(b"\r\n", 1)[1] if b"\r\n" in head else b""
        remote.sendall(req_line + header_block + b"\r\n\r\n" + rest)
        conn.settimeout(None)
        _splice(conn, remote)
    except OSError:
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve(
    listen_host: str = "127.0.0.1",
    listen_port: int = 18768,
    socks_host: str = "127.0.0.1",
    socks_port: int = 9054,
) -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((listen_host, listen_port))
    srv.listen(128)
    log.info("Cursor HTTP proxy http://%s:%s → SOCKS5 %s:%s", listen_host, listen_port, socks_host, socks_port)
    while True:
        conn, _addr = srv.accept()
        threading.Thread(target=_handle_client, args=(conn, socks_host, socks_port), daemon=True).start()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    listen = os.environ.get("TORIFICATION_CURSOR_PROXY", "127.0.0.1:18768")
    socks = os.environ.get("TORIFICATION_SOCKS", "127.0.0.1:9054")
    lh, lp = listen.rsplit(":", 1)
    sh, sp = socks.rsplit(":", 1)
    serve(lh, int(lp), sh, int(sp))


if __name__ == "__main__":
    main()
