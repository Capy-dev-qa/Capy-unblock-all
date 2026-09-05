"""Start / stop / status for torification systemd --user units."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

SERVICES = (
    "torification-tor.service",
    "torification-pac.service",
    "torification.service",
    "torification-cursor-proxy.service",
)

LABELS = {
    "torification-tor.service": "Tor :9054",
    "torification-pac.service": "PAC-сервер",
    "torification.service": "Демон",
    "torification-cursor-proxy.service": "Cursor → Tor",
}


@dataclass(frozen=True)
class ServiceStatus:
    unit: str
    label: str
    active: bool
    enabled: bool


def _systemctl(*args: str, timeout: float = 15) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["systemctl", "--user", *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def is_active(unit: str) -> bool:
    r = _systemctl("is-active", "--quiet", unit)
    return r.returncode == 0


def is_enabled(unit: str) -> bool:
    r = _systemctl("is-enabled", "--quiet", unit)
    return r.returncode == 0


def status_all() -> list[ServiceStatus]:
    return [
        ServiceStatus(unit=u, label=LABELS[u], active=is_active(u), enabled=is_enabled(u))
        for u in SERVICES
    ]


def all_running(rows: list[ServiceStatus] | None = None) -> bool:
    rows = rows if rows is not None else status_all()
    return bool(rows) and all(s.active for s in rows)


def autostart_enabled(rows: list[ServiceStatus] | None = None) -> bool:
    rows = rows if rows is not None else status_all()
    return bool(rows) and all(s.enabled for s in rows)


def start_all() -> subprocess.CompletedProcess[str]:
    r = _systemctl("start", *SERVICES, timeout=30)
    if r.returncode == 0:
        _apply_cursor_proxy_safe()
    return r


def stop_all() -> subprocess.CompletedProcess[str]:
    _restore_cursor_proxy_safe()
    return _systemctl("stop", *SERVICES, timeout=30)


def _apply_cursor_proxy_safe() -> None:
    try:
        _wait_local_port(18768, timeout_s=8.0)
        from torification.cursor_proxy import apply_cursor_proxy

        apply_cursor_proxy()
    except Exception:
        pass


def _restore_cursor_proxy_safe() -> None:
    try:
        from torification.cursor_proxy import restore_cursor_proxy

        restore_cursor_proxy()
    except Exception:
        pass


def _wait_local_port(port: int, timeout_s: float = 8.0) -> bool:
    import socket
    import time

    deadline = time.time() + timeout_s
    while time.time() < deadline:
        sock = socket.socket()
        sock.settimeout(0.3)
        try:
            sock.connect(("127.0.0.1", port))
            return True
        except OSError:
            time.sleep(0.2)
        finally:
            try:
                sock.close()
            except OSError:
                pass
    return False


def cursor_through_tor() -> bool:
    try:
        from torification.cursor_proxy import cursor_proxy_status

        return cursor_proxy_status().applied
    except Exception:
        return False


def set_autostart(enabled: bool) -> subprocess.CompletedProcess[str]:
    if enabled:
        return _systemctl("enable", *SERVICES, timeout=30)
    return _systemctl("disable", *SERVICES, timeout=30)


def chrome_launcher() -> str | None:
    path = shutil.which("chrome-torification")
    if path:
        return path
    home = Path.home() / ".local/bin/chrome-torification"
    return str(home) if home.is_file() else None
