"""Browser-agnostic host discovery: ss + browser History DBs."""

from __future__ import annotations

import os
import re
import shutil
import sqlite3
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from torification.netutil import looks_like_ip


@dataclass
class BrowserEvent:
    host: str
    source: str  # ss | chrome_history | firefox_history
    ts: float


BROWSER_BIN_RE = re.compile(
    r"(chrome|chromium|firefox|brave|msedge|opera)",
    re.I,
)


def _chrome_history_paths() -> list[Path]:
    base = Path.home() / ".config"
    paths: list[Path] = []
    for name in ("google-chrome", "chromium", "BraveSoftware/Brave-Browser", "microsoft-edge", "opera"):
        hist = base / name / "Default" / "History"
        if hist.is_file():
            paths.append(hist)
        # extra profiles
        prof = base / name
        if prof.is_dir():
            for p in prof.glob("Profile */History"):
                paths.append(p)
    return paths


def _firefox_history_paths() -> list[Path]:
    base = Path.home() / ".mozilla/firefox"
    if not base.is_dir():
        return []
    return list(base.glob("*.default*/places.sqlite"))


def _query_history_sql(db_path: Path, sql: str, params: tuple = ()) -> list[str]:
    hosts: list[str] = []
    try:
        conn = sqlite3.connect(str(db_path))
        cur = conn.execute(sql, params)
        for (url,) in cur:
            host = urlparse(url).hostname
            if host:
                hosts.append(host.lower())
        conn.close()
    except sqlite3.Error:
        pass
    return hosts


def _open_history_copy(hist: Path) -> Path | None:
    try:
        fd, path = tempfile.mkstemp(suffix=".History")
        os.close(fd)
        shutil.copy2(hist, path)
        return Path(path)
    except OSError:
        return None


def read_history_since(since_ts: float, process_names: list[str]) -> list[BrowserEvent]:
    events: list[BrowserEvent] = []
    chrome_ts = (since_ts + 11644473600) * 1_000_000

    for hist in _chrome_history_paths():
        tmp = _open_history_copy(hist)
        if not tmp:
            continue
        try:
            for host in _query_history_sql(
                tmp,
                "SELECT url FROM urls WHERE last_visit_time > ? ORDER BY last_visit_time DESC LIMIT 50",
                (chrome_ts,),
            ):
                events.append(BrowserEvent(host=host, source="chrome_history", ts=time.time()))
        finally:
            tmp.unlink(missing_ok=True)

    for hist in _firefox_history_paths():
        tmp = _open_history_copy(hist)
        if not tmp:
            continue
        try:
            for host in _query_history_sql(
                tmp,
                """
                SELECT p.url FROM moz_places p
                JOIN moz_historyvisits v ON v.place_id = p.id
                WHERE v.visit_date > ?
                ORDER BY v.visit_date DESC LIMIT 50
                """,
                (int(since_ts * 1_000_000),),
            ):
                events.append(BrowserEvent(host=host, source="firefox_history", ts=time.time()))
        finally:
            tmp.unlink(missing_ok=True)

    return events


def read_recent_history(limit: int = 40) -> list[BrowserEvent]:
    """Последние N URL — даже если вкладка не успела загрузиться в History with since."""
    events: list[BrowserEvent] = []
    seen: set[str] = set()

    for hist in _chrome_history_paths():
        tmp = _open_history_copy(hist)
        if not tmp:
            continue
        try:
            for host in _query_history_sql(
                tmp,
                "SELECT url FROM urls ORDER BY last_visit_time DESC LIMIT ?",
                (limit,),
            ):
                if host not in seen:
                    seen.add(host)
                    events.append(BrowserEvent(host=host, source="chrome_recent", ts=time.time()))
        finally:
            tmp.unlink(missing_ok=True)

    return events


def read_typed_urls(limit: int = 20) -> list[BrowserEvent]:
    """URL, введённые в адресную строку (даже если страница не загрузилась)."""
    events: list[BrowserEvent] = []
    for hist in _chrome_history_paths():
        tmp = _open_history_copy(hist)
        if not tmp:
            continue
        try:
            for host in _query_history_sql(
                tmp,
                "SELECT url FROM urls WHERE typed_count > 0 ORDER BY last_visit_time DESC LIMIT ?",
                (limit,),
            ):
                events.append(BrowserEvent(host=host, source="chrome_typed", ts=time.time()))
        finally:
            tmp.unlink(missing_ok=True)
    return events


def read_ss_pending_hosts(process_names: list[str]) -> list[BrowserEvent]:
    """SYN-SENT — сайт открыт, но TCP не проходит (History может быть пуст)."""
    from torification.netutil import is_asset_cdn_host, is_telegram_dc_ip

    pids = _browser_pids(process_names)
    if not pids:
        return []
    try:
        out = subprocess.check_output(["ss", "-H", "-tnp"], text=True, timeout=5)
    except (subprocess.SubprocessError, FileNotFoundError):
        return []

    events: list[BrowserEvent] = []
    for line in out.splitlines():
        if "users:" not in line:
            continue
        pid_match = re.search(r"pid=(\d+)", line)
        if not pid_match or int(pid_match.group(1)) not in pids:
            continue
        cols = line.split()
        if len(cols) < 5:
            continue
        state, remote = cols[0], cols[4]
        if state not in ("SYN-SENT", "SYN-RECV"):
            continue
        if remote.startswith("127.") or remote.startswith("[::1]"):
            continue
        if remote.startswith("["):
            ip = remote.split("]")[0][1:]
        else:
            ip = remote.rsplit(":", 1)[0]
        if is_telegram_dc_ip(ip) or is_asset_cdn_host(ip):
            continue
        events.append(BrowserEvent(host=ip, source="ss_pending", ts=time.time()))
    return events


def _browser_pids(process_names: list[str]) -> set[int]:
    pids: set[int] = set()
    for name in process_names:
        try:
            out = subprocess.check_output(["pgrep", "-x", name], text=True, timeout=3)
        except subprocess.CalledProcessError:
            continue
        except FileNotFoundError:
            break
        for line in out.splitlines():
            line = line.strip()
            if line.isdigit():
                pids.add(int(line))
    if pids:
        return pids
    # fallback: main binary path (Chrome renders as 'chrome' in ss, comm may differ)
    try:
        out = subprocess.check_output(
            ["pgrep", "-f", r"/opt/google/chrome/chrome"],
            text=True,
            timeout=3,
        )
        for line in out.splitlines():
            if line.strip().isdigit():
                pids.add(int(line.strip()))
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return pids


def read_ss_connections(process_names: list[str]) -> list[BrowserEvent]:
    """Parse ss -tnp for browser TCP connections (SYN-SENT / ESTABLISHED)."""
    pids = _browser_pids(process_names)
    if not pids:
        return []
    try:
        out = subprocess.check_output(["ss", "-H", "-tnp"], text=True, timeout=5)
    except (subprocess.SubprocessError, FileNotFoundError):
        return []

    events: list[BrowserEvent] = []
    for line in out.splitlines():
        if "users:" not in line:
            continue
        pid_match = re.search(r"pid=(\d+)", line)
        if not pid_match or int(pid_match.group(1)) not in pids:
            continue
        # Local Address:Port Peer Address:Port
        cols = line.split()
        if len(cols) < 5:
            continue
        state = cols[0]
        remote = cols[4]
        if state not in ("ESTAB", "SYN-SENT", "SYN-RECV", "FIN-WAIT-1", "FIN-WAIT-2"):
            continue
        if remote.startswith("127.") or remote.startswith("[::1]"):
            continue
        if remote.startswith("["):
            ip = remote.split("]")[0][1:]
        else:
            ip = remote.rsplit(":", 1)[0]
        events.append(BrowserEvent(host=ip, source="ss", ts=time.time()))
    return events


def resolve_ip_to_host(ip: str, cache: dict[str, str], timeout_s: float = 2.0) -> str:
    if ip in cache:
        return cache[ip]
    if not looks_like_ip(ip):
        return ip
    result = [ip]

    def _lookup() -> None:
        try:
            import socket

            host, _, _ = socket.gethostbyaddr(ip)
            result[0] = host.lower()
        except OSError:
            result[0] = ip

    t = threading.Thread(target=_lookup, daemon=True)
    t.start()
    t.join(timeout_s)
    cache[ip] = result[0]
    return cache[ip]
