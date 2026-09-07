"""Minimal SOCKS5 CONNECT client (no extra deps)."""

from __future__ import annotations

import socket
import struct


class SocksError(OSError):
    pass


def socks5_connect(
    dest_host: str,
    dest_port: int,
    socks_host: str = "127.0.0.1",
    socks_port: int = 9054,
    timeout: float = 20.0,
) -> socket.socket:
    sock = socket.create_connection((socks_host, socks_port), timeout=timeout)
    try:
        sock.sendall(b"\x05\x01\x00")
        hello = _recv_exact(sock, 2)
        if hello != b"\x05\x00":
            raise SocksError(f"SOCKS5 auth rejected: {hello!r}")
        host_b = dest_host.encode("idna")
        if len(host_b) > 255:
            raise SocksError(f"hostname too long: {dest_host}")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(host_b)]) + host_b + struct.pack("!H", dest_port))
        hdr = _recv_exact(sock, 4)
        if hdr[0] != 5 or hdr[1] != 0:
            raise SocksError(f"SOCKS5 CONNECT failed: status={hdr[1]}")
        atyp = hdr[3]
        if atyp == 1:
            _recv_exact(sock, 4 + 2)
        elif atyp == 3:
            n = _recv_exact(sock, 1)[0]
            _recv_exact(sock, n + 2)
        elif atyp == 4:
            _recv_exact(sock, 16 + 2)
        else:
            raise SocksError(f"SOCKS5 bad atyp={atyp}")
        sock.settimeout(None)
        return sock
    except Exception:
        sock.close()
        raise


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise SocksError("SOCKS5 connection closed")
        buf += chunk
    return buf
