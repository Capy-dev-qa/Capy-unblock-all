"""Application-level site probe: HTTP body + Cloudflare/block detection.

TCP/TLS «ok» недостаточно — OpenAI/ChatGPT отдают tls_ok, но HTTP 403 + blank page.
"""

from __future__ import annotations

import os
import re
import subprocess
import tempfile
from dataclasses import dataclass

BROWSER_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
)

BLOCK_BODY_RE = re.compile(
    r"not available in your|unsupported country|access denied|"
    r"cf-mitigated|cloudflare.*challenge|attention required|"
    r"request blocked|geo.?block|region.*restrict",
    re.I,
)


@dataclass
class HttpProbeResult:
    ok: bool
    status: int
    bytes: int
    reason: str
    latency_ms: float = 0.0


@dataclass
class AppProbeResult:
    host: str
    direct: HttpProbeResult
    via_socks: HttpProbeResult | None
    needs_torify: bool
    tor_helps: bool
    suggest_bridge_race: bool


def _curl_probe(
    url: str,
    timeout_s: int = 15,
    socks_port: int | None = None,
) -> HttpProbeResult:
    fd, body_path = tempfile.mkstemp(prefix="torification-probe-")
    os.close(fd)
    try:
        cmd = [
            "curl", "-sS", "-L", "--compressed", "--max-time", str(timeout_s),
            "-A", BROWSER_UA,
            "-o", body_path,
            "-w", "%{http_code} %{size_download} %{time_total}",
            url,
        ]
        if socks_port is not None:
            cmd = ["curl", "--socks5-hostname", f"127.0.0.1:{socks_port}"] + cmd[1:]

        try:
            out = subprocess.check_output(
                cmd, text=True, stderr=subprocess.DEVNULL, timeout=timeout_s + 3,
            )
            parts = out.strip().split()
            status = int(parts[0]) if parts else 0
            nbytes = int(float(parts[1])) if len(parts) > 1 else 0
            latency = float(parts[2]) * 1000 if len(parts) > 2 else 0.0
        except subprocess.TimeoutExpired:
            return HttpProbeResult(False, 0, 0, "timeout")
        except subprocess.CalledProcessError as e:
            reason = "timeout" if e.returncode == 28 else f"curl_{e.returncode}"
            return HttpProbeResult(False, 0, 0, reason)
        except (ValueError, IndexError) as e:
            return HttpProbeResult(False, 0, 0, str(e)[:80])

        try:
            with open(body_path, "rb") as f:
                body = f.read(65536).decode("utf-8", errors="replace")
        except OSError:
            body = ""

        return _classify_http(status, nbytes, body, latency)
    finally:
        try:
            os.unlink(body_path)
        except OSError:
            pass


def _classify_http(status: int, nbytes: int, body: str, latency_ms: float) -> HttpProbeResult:
    if status == 0:
        return HttpProbeResult(False, 0, nbytes, "no_response", latency_ms)

    if status >= 500:
        return HttpProbeResult(False, status, nbytes, f"http_{status}", latency_ms)

    # Geo/DPI/WAF: 403, 451; таймаут прокси 408/425; rate-limit 429.
    if status in (403, 408, 425, 429, 451):
        return HttpProbeResult(False, status, nbytes, f"http_{status}", latency_ms)

    # 401/404/405/410 — сайт отвечает, это не блокировка канала.
    if 400 <= status < 500:
        return HttpProbeResult(True, status, nbytes, "ok", latency_ms)

    if BLOCK_BODY_RE.search(body):
        return HttpProbeResult(False, status, nbytes, "block_body", latency_ms)

    # SPA: пустая/крошечная страница при «успешном» 200 — подозрительно для главных доменов
    if status == 200 and nbytes < 200 and "<html" not in body.lower():
        return HttpProbeResult(False, status, nbytes, "empty_body", latency_ms)

    if status in (200, 204, 301, 302, 307, 308) or (200 <= status < 400):
        return HttpProbeResult(True, status, nbytes, "ok", latency_ms)

    return HttpProbeResult(False, status, nbytes, f"http_{status}", latency_ms)


def probe_site(
    host: str,
    socks_ports: list[int] | None = None,
    timeout_s: int = 15,
) -> AppProbeResult:
    """Probe https://host/ direct and via Tor SOCKS port(s)."""
    host = host.lower().rstrip(".")
    url = f"https://{host}/"
    direct = _curl_probe(url, timeout_s=timeout_s)

    best_socks: HttpProbeResult | None = None
    best_port: int | None = None
    for port in socks_ports or []:
        r = _curl_probe(url, timeout_s=timeout_s, socks_port=port)
        if r.ok and (best_socks is None or not best_socks.ok):
            best_socks = r
            best_port = port
        elif best_socks is None and r.status > 0:
            best_socks = r
            best_port = port

    tor_helps = bool(best_socks and best_socks.ok and not direct.ok)
    needs_torify = tor_helps
    suggest_race = not direct.ok and not tor_helps and bool(socks_ports)

    if best_socks and best_port and tor_helps:
        best_socks.reason = f"{best_socks.reason}@:{best_port}"

    return AppProbeResult(
        host=host,
        direct=direct,
        via_socks=best_socks,
        needs_torify=needs_torify,
        tor_helps=tor_helps,
        suggest_bridge_race=suggest_race,
    )
