"""Feature extraction for block detection ML classifier."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any

from torification.tcp_probe import ProbeResult, ProbeState


@dataclass
class BlockFeatures:
    host: str
    port: int
    latency_ms: float
    state_onehot_timeout: int
    state_onehot_refused: int
    state_onehot_unreachable: int
    state_onehot_tls_error: int
    state_onehot_ok: int
    direct_failed: int
    socks_ok: int
    socks_latency_ms: float
    retry_count: int
    hour_of_day: int

    def to_vector(self) -> list[float]:
        return [
            float(self.port),
            self.latency_ms,
            float(self.state_onehot_timeout),
            float(self.state_onehot_refused),
            float(self.state_onehot_unreachable),
            float(self.state_onehot_tls_error),
            float(self.state_onehot_ok),
            float(self.direct_failed),
            float(self.socks_ok),
            self.socks_latency_ms,
            float(self.retry_count),
            float(self.hour_of_day),
        ]

    @staticmethod
    def feature_names() -> list[str]:
        return [
            "port",
            "latency_ms",
            "timeout",
            "refused",
            "unreachable",
            "tls_error",
            "ok",
            "direct_failed",
            "socks_ok",
            "socks_latency_ms",
            "retry_count",
            "hour_of_day",
        ]


def from_probes(
    host: str,
    direct: ProbeResult,
    via_socks: ProbeResult | None = None,
    retry_count: int = 0,
) -> BlockFeatures:
    import datetime

    st = direct.state
    return BlockFeatures(
        host=host,
        port=direct.port,
        latency_ms=direct.latency_ms,
        state_onehot_timeout=int(st == ProbeState.TIMEOUT),
        state_onehot_refused=int(st == ProbeState.REFUSED),
        state_onehot_unreachable=int(st == ProbeState.UNREACHABLE),
        state_onehot_tls_error=int(st == ProbeState.TLS_ERROR),
        state_onehot_ok=int(st in (ProbeState.OK, ProbeState.TLS_OK, ProbeState.TCP_OK, ProbeState.HTTP_OK)),
        direct_failed=int(st not in (ProbeState.OK, ProbeState.TLS_OK, ProbeState.TCP_OK, ProbeState.HTTP_OK)),
        socks_ok=int(via_socks is not None and via_socks.state in (
            ProbeState.OK, ProbeState.TLS_OK, ProbeState.TCP_OK, ProbeState.HTTP_OK,
        )),
        socks_latency_ms=via_socks.latency_ms if via_socks else 0.0,
        retry_count=retry_count,
        hour_of_day=datetime.datetime.now().hour,
    )


def append_training_event(path: str, features: BlockFeatures, label: str, extra: dict[str, Any] | None = None) -> None:
    from pathlib import Path

    p = Path(path).expanduser()
    p.parent.mkdir(parents=True, exist_ok=True)
    row = {"features": asdict(features), "label": label}
    if extra:
        row["extra"] = extra
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, ensure_ascii=False) + "\n")
