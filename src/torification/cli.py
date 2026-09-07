"""CLI utilities."""

from __future__ import annotations

import argparse
import logging
import os
import sys

from torification.bridge_race import parse_bridges, race_bridges, apply_winning_bridge, parse_transport_plugins
from torification.config import load_config
from torification.pac_generator import generate_pac, load_torified, write_pac
from torification.tcp_probe import probe_tcp, is_blocked


def probe_cmd() -> None:
    p = argparse.ArgumentParser(description="TCP probe a host (SYN handshake + TLS)")
    p.add_argument("host")
    p.add_argument("--port", type=int, default=443)
    p.add_argument("--timeout", type=int, default=5000)
    args = p.parse_args()
    r = probe_tcp(args.host, args.port, args.timeout)
    print(f"{args.host}:{args.port} → {r.state.value} ({r.latency_ms:.0f} ms) {r.detail}")
    sys.exit(1 if is_blocked(r) else 0)


def race_cmd() -> None:
    p = argparse.ArgumentParser(description="Race Tor bridges for a host")
    p.add_argument("host")
    p.add_argument("--torrc", default="~/.config/torification/torrc")
    args = p.parse_args()
    cfg = load_config()
    from pathlib import Path

    torrc = Path(args.torrc).expanduser()
    bridges = parse_bridges(torrc)
    results = race_bridges(
        bridges,
        args.host,
        exit_countries=cfg["tor"]["exit_countries"],
        plugins=parse_transport_plugins(torrc),
    )
    if not results:
        print("No working bridge found")
        sys.exit(1)
    for r in results:
        print(f"#{r.rank} {r.bridge.address} — {r.latency_ms:.0f} ms")
    apply_winning_bridge(torrc, cfg["tor"]["bridges_file"], results[0].bridge, bridges)
    print(f"Applied winner: {results[0].bridge.address}")


def pac_cmd() -> None:
    cfg = load_config()
    from pathlib import Path

    state = Path(cfg["general"]["state_dir"]).expanduser() / "torified-hosts.json"
    torified = load_torified(state)
    static = Path(cfg.get("pac", {}).get("static_rules", "~/.config/torification/static-rules.pac")).expanduser()
    if not static.is_file():
        static = Path(__file__).resolve().parents[2] / "config" / "static-rules.pac"
    content = generate_pac(
        torified,
        "127.0.0.1",
        int(cfg["tor"]["socks_port"]),
        static if static.is_file() else None,
    )
    out = Path(cfg["pac"]["output"]).expanduser()
    write_pac(out, content)
    print(f"Wrote {out} ({len(torified)} dynamic hosts, static={'yes' if static.is_file() else 'no'})")


def train_cmd() -> None:
    p = argparse.ArgumentParser(description="Train ML block classifier from JSONL")
    p.add_argument("--input", required=True)
    p.add_argument("--output", default="~/.local/state/torification/block_classifier.joblib")
    args = p.parse_args()
    from torification.ml.classifier import BlockClassifier

    clf = BlockClassifier()
    stats = clf.train_from_jsonl(args.input, args.output)
    print(stats)


def check_cmd() -> None:
    p = argparse.ArgumentParser(description="HTTP app-level probe (direct vs Tor)")
    p.add_argument("host")
    args = p.parse_args()
    cfg = load_config()
    ports = [int(cfg["tor"]["socks_port"])]
    fb = cfg.get("probe", {}).get("fallback_socks_port")
    if fb:
        ports.append(int(fb))
    from torification.app_probe import probe_site

    app = probe_site(args.host, socks_ports=ports)
    print(f"=== {args.host} ===")
    print(f"  direct: {app.direct.ok} ({app.direct.reason}, status={app.direct.status}, bytes={app.direct.bytes})")
    if app.via_socks:
        print(f"  socks:  {app.via_socks.ok} ({app.via_socks.reason})")
    print(f"  needs_torify={app.needs_torify} bridge_race={app.suggest_bridge_race}")
    sys.exit(0 if app.direct.ok else 1)


def status_cmd() -> None:
    cfg = load_config()
    from torification.site_health import run_all_checks

    print("=== Torification status ===")
    all_ok = True
    for st in run_all_checks(cfg):
        mark = "OK" if st.ok else "FAIL"
        print(f"  [{mark}] {st.name}: {st.detail}")
        if not st.ok:
            all_ok = False
    sys.exit(0 if all_ok else 1)


def fix_cmd() -> None:
    p = argparse.ArgumentParser(description="Force check and unblock a host")
    p.add_argument("host")
    args = p.parse_args()
    cfg = load_config()
    from pathlib import Path
    from torification.app_probe import probe_site
    from torification.daemon import TorificationDaemon

    d = TorificationDaemon(cfg)
    host = args.host.lower().strip()
    d.fix_host(host)
    app = probe_site(host, d._socks_ports)
    print(f"=== after fix: {host} ===")
    print(f"  direct: {app.direct.ok} ({app.direct.reason})")
    pac_path = Path(cfg["pac"]["output"]).expanduser()
    pac_text = pac_path.read_text(encoding="utf-8") if pac_path.is_file() else ""
    needle = f'host === "{host}"'
    print(f"  in_pac: {needle in pac_text}")
    meta = d.torified.get(host)
    if meta:
        print(f"  torified: port {meta.get('port', '?')}")


def main() -> None:
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) < 2:
        print("Usage: torification {probe|check|fix|race|pac|train|daemon|status|gui} ...")
        sys.exit(1)
    cmd = sys.argv[1]
    sys.argv = sys.argv[1:]
    if cmd == "probe":
        probe_cmd()
    elif cmd == "race":
        race_cmd()
    elif cmd == "pac":
        pac_cmd()
    elif cmd == "train":
        train_cmd()
    elif cmd == "fix":
        fix_cmd()
    elif cmd == "daemon":
        from torification.daemon import main as daemon_main

        daemon_main()
    elif cmd == "check":
        check_cmd()
    elif cmd == "status":
        status_cmd()
    elif cmd == "gui":
        from pathlib import Path

        script = Path(__file__).resolve().parents[2] / "scripts" / "torification-gui.py"
        os.execv(sys.executable, [sys.executable, str(script)])
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
