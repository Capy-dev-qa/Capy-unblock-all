"""Discover hosts from live browser TCP connections (ss), not Chrome history."""

from __future__ import annotations

import re
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from torification.connection_watcher import (
    _browser_pids,
    _chrome_history_paths,
    _open_history_copy,
    read_ss_pending_hosts,
    resolve_ip_to_host,
)
from torification.netutil import is_asset_cdn_host, is_telegram_dc_ip, looks_like_ip

EMBED_HOST_RE = re.compile(
    r"https?://([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)",
    re.I,
)

SEARCH_ENGINES = frozenset({
    "google.com", "www.google.com", "google.ru", "www.google.ru",
    "yandex.ru", "ya.ru", "bing.com", "duckduckgo.com",
})

DOMAIN_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)


@dataclass
class Discovery:
    """active = live TCP от браузера; search_candidates = догадки только при открытом Google."""

    active: set[str]
    search_candidates: set[str]

    @property
    def all_hosts(self) -> set[str]:
        return self.active | self.search_candidates


def query_to_host_candidates(query: str) -> set[str]:
    """rule34vid → rule34video.com (только осмысленные запросы, без gmail.org)."""
    out: set[str] = set()
    q = unquote(query or "").strip().lower()
    if not q or " " in q:
        return out
    q = q.split()[0]
    if len(q) < 6 or q.startswith("http"):
        return out
    if DOMAIN_RE.match(q):
        out.add(q)
        return out
    if not re.match(r"^[a-z0-9][a-z0-9-]{4,}$", q):
        return out
    out.add(f"{q}.com")
    if q.endswith("vid") and not q.endswith("video"):
        base = q[:-3]
        if len(base) >= 3:
            out.add(f"{base}video.com")
    return out


def hosts_from_url_direct(url: str) -> set[str]:
    out: set[str] = set()
    try:
        parsed = urlparse(url)
        h = parsed.hostname
        if h:
            host = h.lower().rstrip(".")
            if host not in SEARCH_ENGINES:
                out.add(host)
        if h and h in SEARCH_ENGINES and parsed.path == "/url":
            qs = parse_qs(parsed.query)
            for key in ("q", "url"):
                for val in qs.get(key, []):
                    for embedded in EMBED_HOST_RE.finditer(unquote(val)):
                        out.add(embedded.group(1).lower().rstrip("."))
    except Exception:
        pass
    for m in EMBED_HOST_RE.finditer(url):
        h = m.group(1).lower().rstrip(".")
        if h not in SEARCH_ENGINES:
            out.add(h)
    return out


def hosts_from_search_url(url: str) -> set[str]:
    out: set[str] = set()
    try:
        parsed = urlparse(url)
        h = parsed.hostname
        if not h or h.lower().rstrip(".") not in SEARCH_ENGINES:
            return out
        if "/search" not in parsed.path:
            return out
        qs = parse_qs(parsed.query)
        for key in ("q", "oq"):
            for val in qs.get(key, []):
                out.update(query_to_host_candidates(val))
    except Exception:
        pass
    return out


def hosts_from_url(url: str) -> set[str]:
    out = hosts_from_url_direct(url)
    out.update(hosts_from_search_url(url))
    return out


def _on_search_engine(active: set[str]) -> bool:
    for h in active:
        hl = h.lower().rstrip(".")
        if hl in SEARCH_ENGINES:
            return True
        for se in SEARCH_ENGINES:
            if hl == se or hl.endswith("." + se):
                return True
    return False


def _query_urls(db: Path, sql: str, params: tuple = ()) -> list[str]:
    urls: list[str] = []
    try:
        conn = sqlite3.connect(str(db))
        for (url,) in conn.execute(sql, params):
            if url:
                urls.append(url)
        conn.close()
    except sqlite3.Error:
        pass
    return urls


def read_urls_since(since_ts: float, limit: int = 10) -> list[str]:
    """Только для search-кандидатов, когда открыт Google — не для общего discovery."""
    chrome_ts = (since_ts + 11644473600) * 1_000_000
    urls: list[str] = []
    for hist in _chrome_history_paths():
        tmp = _open_history_copy(hist)
        if not tmp:
            continue
        try:
            urls.extend(_query_urls(
                tmp,
                "SELECT url FROM urls WHERE last_visit_time > ? ORDER BY last_visit_time DESC LIMIT ?",
                (chrome_ts, limit),
            ))
        finally:
            tmp.unlink(missing_ok=True)
    return urls


def read_ss_active_ips(process_names: list[str]) -> list[str]:
    import subprocess

    pids = _browser_pids(process_names)
    if not pids:
        return []
    try:
        out = subprocess.check_output(["ss", "-H", "-tnp"], text=True, timeout=5)
    except (subprocess.SubprocessError, FileNotFoundError):
        return []

    ips: list[str] = []
    for line in out.splitlines():
        if "users:" not in line or "chrome" not in line:
            continue
        pid_match = re.search(r"pid=(\d+)", line)
        if not pid_match or int(pid_match.group(1)) not in pids:
            continue
        cols = line.split()
        if len(cols) < 5:
            continue
        if cols[0] not in ("ESTAB", "SYN-SENT", "SYN-RECV"):
            continue
        remote = cols[4]
        if remote.startswith("127.") or ":9050" in remote or ":9054" in remote:
            continue
        if remote.startswith("["):
            ip = remote.split("]")[0][1:]
        else:
            ip = remote.rsplit(":", 1)[0]
        if is_telegram_dc_ip(ip) or is_asset_cdn_host(ip):
            continue
        ips.append(ip)
    return ips


def discover_hosts(process_names: list[str], since_ts: float, dns_cache: dict[str, str]) -> Discovery:
    """Только live TCP (ss). История Chrome — только search?q= пока открыт Google."""
    active: set[str] = set()
    candidates: set[str] = set()

    for ev in read_ss_pending_hosts(process_names):
        h = ev.host
        if looks_like_ip(h):
            h = resolve_ip_to_host(h, dns_cache)
        h = h.lower().rstrip(".")
        if h and h not in SEARCH_ENGINES and not is_asset_cdn_host(h):
            active.add(h)

    for ip in read_ss_active_ips(process_names):
        h = resolve_ip_to_host(ip, dns_cache)
        h = h.lower().rstrip(".")
        if h and not looks_like_ip(h) and h not in SEARCH_ENGINES and not is_asset_cdn_host(h):
            active.add(h)

    if _on_search_engine(active):
        for url in read_urls_since(since_ts, 10):
            candidates.update(hosts_from_search_url(url))

    candidates -= active
    return Discovery(active=active, search_candidates=candidates)
