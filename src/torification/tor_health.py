"""Tor instance health: restart, NEWNYM, bootstrap check."""

from __future__ import annotations

import socket
import subprocess
import time
from pathlib import Path


def port_open(port: int) -> bool:
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=2)
        s.close()
        return True
    except OSError:
        return False


def socks_works(port: int, timeout: float = 12.0) -> bool:
    from torification.tcp_probe import probe_via_socks

    r = probe_via_socks("www.gstatic.com", 443, "127.0.0.1", port, int(timeout * 1000))
    return r.state.value in ("ok", "tcp_ok", "tls_ok", "http_ok")


def ensure_torification_tor(socks_port: int, control_port: int, cookie_path: Path) -> bool:
    if port_open(socks_port) and socks_works(socks_port):
        return True
    subprocess.run(["systemctl", "--user", "restart", "torification-tor.service"], check=False)
    deadline = time.time() + 120
    while time.time() < deadline:
        if port_open(socks_port) and socks_works(socks_port):
            return True
        time.sleep(3)
    return False


def signal_newnym(control_port: int, cookie_path: Path) -> bool:
    if not cookie_path.is_file():
        return False
    try:
        import binascii

        from torification.bridge_race import parse_bridges  # noqa: F401

        cookie = binascii.hexlify(cookie_path.read_bytes()).decode()
        s = socket.create_connection(("127.0.0.1", control_port), timeout=10)
        f = s.makefile("rw", encoding="utf-8", newline="\r\n")
        f.write(f"AUTHENTICATE {cookie}\r\n")
        f.flush()
        f.readline()
        f.write("SIGNAL NEWNYM\r\n")
        f.flush()
        line = f.readline()
        s.close()
        return line.startswith("250")
    except OSError:
        return False
