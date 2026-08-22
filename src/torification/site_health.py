"""Application-level health checks (TCP alone is not enough)."""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass


@dataclass
class SiteStatus:
    name: str
    ok: bool
    detail: str


def _socks_curl(url: str, port: int, timeout: int = 12) -> tuple[bool, str]:
    try:
        code = subprocess.check_output(
            [
                "curl", "-fsS", "--max-time", str(timeout),
                "--socks5-hostname", f"127.0.0.1:{port}",
                "-o", "/dev/null", "-w", "%{http_code}",
                url,
            ],
            text=True,
            timeout=timeout + 2,
        ).strip()
        return code.startswith("2") or code == "204", f"http_{code}"
    except subprocess.CalledProcessError as e:
        return False, f"curl_fail_{e.returncode}"
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return False, str(e)


def _port_open(port: int) -> bool:
    try:
        out = subprocess.check_output(["ss", "-lntH", f"sport = :{port}"], text=True, timeout=3)
        return bool(out.strip())
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def _chrome_syn_sent_to_telegram_dc() -> bool:
    """Stuck SYN-SENT to Telegram DC (2+ sockets) — «Waiting for network»."""
    stuck = 0
    try:
        out = subprocess.check_output(["ss", "-H", "-tnp"], text=True, timeout=5)
    except (subprocess.SubprocessError, FileNotFoundError):
        return False
    for line in out.splitlines():
        if "chrome" not in line or "SYN-SENT" not in line:
            continue
        if re.search(r"149\.154\.|91\.108\.", line):
            stuck += 1
            if stuck >= 2:
                return True
    return False


def check_telegram() -> SiteStatus:
    if _chrome_syn_sent_to_telegram_dc():
        return SiteStatus("telegram", False, "Chrome SYN-SENT к DC 149.154.x.x — DIRECT заблокирован, нужен Tor :9050")

    if not _port_open(9050):
        return SiteStatus("telegram", False, "Tor :9050 не слушает (sudo systemctl start tor)")

    ok, detail = _socks_curl("https://web.telegram.org/", 9050)
    if ok:
        return SiteStatus("telegram", True, f"web.telegram.org через Tor OK ({detail})")
    return SiteStatus("telegram", False, f"Tor :9050 есть, но web.telegram.org: {detail}")


def check_torification_tor(socks_port: int = 9054) -> SiteStatus:
    if not _port_open(socks_port):
        return SiteStatus("torification-tor", False, f"порт {socks_port} не слушает")
    ok, detail = _socks_curl("https://www.gstatic.com/generate_204", socks_port)
    return SiteStatus(
        "torification-tor",
        ok,
        f"цепочки OK ({detail})" if ok else detail,
    )


def check_pac_has_telegram(pac_path: str) -> SiteStatus:
    from pathlib import Path

    p = Path(pac_path).expanduser()
    if not p.is_file():
        return SiteStatus("pac", False, f"нет файла {p}")
    text = p.read_text(encoding="utf-8")
    if "telegram.org" in text and "9050" in text:
        return SiteStatus("pac", True, "Telegram → SOCKS :9050 в PAC")
    if 'return "DIRECT"' in text and "telegram" not in text:
        return SiteStatus("pac", False, "PAC пустой — всё DIRECT, Telegram не через Tor")
    return SiteStatus("pac", False, "правила Telegram в PAC не найдены")


def run_all_checks(cfg: dict) -> list[SiteStatus]:
    pac_out = cfg.get("pac", {}).get("output", "~/.config/torification/proxy.pac")
    socks = int(cfg.get("tor", {}).get("socks_port", 9054))
    return [
        check_pac_has_telegram(pac_out),
        check_telegram(),
        check_torification_tor(socks),
    ]
