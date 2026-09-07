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

        cookie = binascii.hexlify(cookie_path.read_bytes()).decode()
        s = socket.create_connection(("127.0.0.1", control_port), timeout=10)
        try:
            # newline="" — иначе makefile сам добавит \r\n к уже указанному \r\n → \r\r\n
            f = s.makefile("rw", encoding="utf-8", newline="")
            f.write(f"AUTHENTICATE {cookie}\r\n")
            f.flush()
            auth = f.readline()
            if not auth.startswith("250"):
                return False
            f.write("SIGNAL NEWNYM\r\n")
            f.flush()
            line = f.readline()
            return line.startswith("250")
        finally:
            s.close()
    except OSError:
        return False
