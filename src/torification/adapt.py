"""Adaptive unblock strategies: DPI, bridge down, TCP reset, CF, etc."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from torification.app_probe import AppProbeResult
from torification.tcp_probe import ProbeResult, is_blocked


class BlockKind(str, Enum):
    OK = "ok"
    DPI = "dpi"              # TCP/TLS ok, HTTP timeout/reset — типично ТСПУ
    TCP_BLOCK = "tcp_block"  # SYN timeout / RST
    HTTP_BLOCK = "http_block"  # 403/451/empty
    TOR_DOWN = "tor_down"    # SOCKS не отвечает
    BOTH_FAIL = "both_fail"  # direct и Tor не работают → гонка мостов
    CF_CHALLENGE = "cf"        # Cloudflare 403 обе стороны


@dataclass
class AdaptPlan:
    kind: BlockKind
    action: str  # torify | bridge_race | restart_tor | newnym | none
    port: int | None = None
    detail: str = ""


def classify_block(
    app: AppProbeResult,
    direct_tcp: ProbeResult | None = None,
) -> AdaptPlan:
    if app.direct.ok:
        return AdaptPlan(BlockKind.OK, "none", detail="direct ok")

    if app.needs_torify and app.via_socks:
        port = 9054
        if app.via_socks.reason and "@:" in app.via_socks.reason:
            try:
                port = int(app.via_socks.reason.rsplit("@:", 1)[-1])
            except ValueError:
                pass
        kind = BlockKind.DPI
        if direct_tcp and not is_blocked(direct_tcp):
            kind = BlockKind.DPI
        elif "403" in app.direct.reason:
            kind = BlockKind.HTTP_BLOCK
        return AdaptPlan(kind, "torify", port=port, detail=app.direct.reason)

    if "403" in app.direct.reason and app.via_socks and not app.via_socks.ok:
        return AdaptPlan(BlockKind.CF_CHALLENGE, "bridge_race", detail="cf_both_sides")

    if direct_tcp and not is_blocked(direct_tcp) and not app.direct.ok:
        return AdaptPlan(BlockKind.DPI, "bridge_race", detail="dpi_http_fail_tor_also")

    if app.suggest_bridge_race:
        return AdaptPlan(BlockKind.BOTH_FAIL, "bridge_race", detail=app.direct.reason)

    return AdaptPlan(BlockKind.TCP_BLOCK, "bridge_race", detail=app.direct.reason)
