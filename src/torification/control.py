"""Start / stop / status for torification systemd --user units."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass

SERVICES = (
    "torification-tor.service",
    "torification-pac.service",
    "torification.service",
)

LABELS = {
    "torification-tor.service": "Tor :9054",
    "torification-pac.service": "PAC-сервер",
    "torification.service": "Демон",
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
    return _systemctl("start", *SERVICES, timeout=30)


def stop_all() -> subprocess.CompletedProcess[str]:
    return _systemctl("stop", *SERVICES, timeout=30)


def set_autostart(enabled: bool) -> subprocess.CompletedProcess[str]:
    if enabled:
        return _systemctl("enable", *SERVICES, timeout=30)
    return _systemctl("disable", *SERVICES, timeout=30)


def chrome_launcher() -> str | None:
    path = shutil.which("chrome-torification")
    if path:
        return path
    from pathlib import Path

    home = Path.home() / ".local/bin/chrome-torification"
    return str(home) if home.is_file() else None
