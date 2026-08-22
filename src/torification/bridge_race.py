"""Parallel bridge race — pick fastest working Tor bridge for a target host."""

from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from torification.tcp_probe import ProbeResult, probe_via_socks


@dataclass
class Bridge:
    line: str  # full Bridge line for torrc
    transport: str  # obfs4, snowflake, …
    address: str


@dataclass
class RaceResult:
    bridge: Bridge
    latency_ms: float
    rank: int


def parse_bridges(torrc_path: str | Path) -> list[Bridge]:
    text = Path(torrc_path).expanduser().read_text(encoding="utf-8")
    bridges: list[Bridge] = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("Bridge "):
            continue
        rest = line[7:]
        transport = "vanilla"
        if rest.startswith("obfs4 ") or rest.startswith("snowflake ") or rest.startswith("meek "):
            transport, rest = rest.split(" ", 1)
        m = re.search(r"(\d+\.\d+\.\d+\.\d+|\[[0-9a-f:]+\]):(\d+)", rest)
        addr = m.group(0) if m else rest.split()[0]
        bridges.append(Bridge(line=line, transport=transport, address=addr))
    return bridges


def _write_minimal_torrc(
    bridge: Bridge,
    data_dir: Path,
    socks_port: int,
    control_port: int,
    exit_countries: str,
    log_path: Path,
) -> Path:
    data_dir.mkdir(parents=True, exist_ok=True)
    plugins = ""
    if "obfs4" in bridge.line:
        plugins = "ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy\n"
    elif "snowflake" in bridge.line:
        plugins = (
            "ClientTransportPlugin snowflake exec /usr/bin/snowflake-client "
            "-url https://1098762253.rsc.cdn77.org/ -front cdn.zk.mk\n"
        )
    body = f"""SocksPort 127.0.0.1:{socks_port}
ControlPort 127.0.0.1:{control_port}
DataDirectory {data_dir}
Log notice file {log_path}
UseBridges 1
{plugins}{bridge.line}
ExitNodes {exit_countries}
StrictNodes 1
"""
    rc = data_dir / "torrc"
    rc.write_text(body, encoding="utf-8")
    return rc


def _socks_ready(port: int, deadline: float) -> bool:
    """Port open is not enough — wait until Tor builds circuits."""
    while time.time() < deadline:
        r = probe_via_socks("www.gstatic.com", 443, "127.0.0.1", port, 8000)
        if r.state.value in ("ok", "tcp_ok", "tls_ok", "http_ok"):
            return True
        try:
            socket.create_connection(("127.0.0.1", port), timeout=1).close()
        except OSError:
            pass
        time.sleep(1)
    return False


def _test_bridge(
    bridge: Bridge,
    base_port: int,
    idx: int,
    target_host: str,
    target_port: int,
    exit_countries: str,
    bootstrap_timeout: float,
) -> RaceResult | None:
    socks = base_port + idx * 2
    ctrl = base_port + idx * 2 + 1
    tmp = Path(tempfile.mkdtemp(prefix=f"tor-race-{idx}-"))
    log = tmp / "tor.log"
    torrc = _write_minimal_torrc(bridge, tmp / "data", socks, ctrl, exit_countries, log)
    proc = subprocess.Popen(
        ["/usr/sbin/tor", "-f", str(torrc)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        if not _socks_ready(socks, time.time() + bootstrap_timeout):
            return None
        # bootstrap check via generate_204
        r: ProbeResult = probe_via_socks("www.gstatic.com", 443, "127.0.0.1", socks, int(bootstrap_timeout * 1000))
        if r.state.value not in ("ok", "tcp_ok", "tls_ok", "http_ok"):
            return None
        tr = probe_via_socks(target_host, target_port, "127.0.0.1", socks, 20000)
        if tr.state.value not in ("ok", "tcp_ok", "tls_ok", "http_ok"):
            return None
        return RaceResult(bridge=bridge, latency_ms=tr.latency_ms, rank=0)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        shutil.rmtree(tmp, ignore_errors=True)


def race_bridges(
    bridges: list[Bridge],
    target_host: str,
    target_port: int = 443,
    exit_countries: str = "{us},{de},{gb}",
    base_port: int = 19200,
    bootstrap_timeout: float = 120.0,
    max_workers: int = 4,
) -> list[RaceResult]:
    """Run bridges in parallel; return sorted by latency (fastest first)."""
    results: list[RaceResult] = []
    with ThreadPoolExecutor(max_workers=min(max_workers, len(bridges))) as ex:
        futs = {
            ex.submit(
                _test_bridge,
                b,
                base_port,
                i,
                target_host,
                target_port,
                exit_countries,
                bootstrap_timeout,
            ): b
            for i, b in enumerate(bridges)
        }
        for fut in as_completed(futs):
            res = fut.result()
            if res:
                results.append(res)
    results.sort(key=lambda x: x.latency_ms)
    for i, r in enumerate(results):
        r.rank = i + 1
    return results


def apply_winning_bridge(
    main_torrc: str | Path,
    bridges_file: str | Path,
    winner: Bridge,
    all_bridges: list[Bridge],
) -> None:
    """Put winning bridge first in torrc + save ordered list."""
    main = Path(main_torrc).expanduser()
    lines = main.read_text(encoding="utf-8").splitlines()
    ordered = [winner] + [b for b in all_bridges if b.line != winner.line]
    new_lines: list[str] = []
    bridge_set = {b.line for b in all_bridges}
    for line in lines:
        if line.strip() in bridge_set:
            continue
        new_lines.append(line)
    # insert after UseBridges / plugins block
    insert_at = 0
    for i, line in enumerate(new_lines):
        if line.strip().startswith("UseBridges"):
            insert_at = i + 1
            break
    for b in ordered:
        new_lines.insert(insert_at, b.line)
        insert_at += 1
    main.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
    Path(bridges_file).expanduser().write_text("\n".join(b.line for b in ordered) + "\n", encoding="utf-8")
