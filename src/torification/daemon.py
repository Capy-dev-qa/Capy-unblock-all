"""Torification daemon — watch browsers, HTTP probe, race bridges, update PAC."""

from __future__ import annotations

import fcntl
import logging
import os
import subprocess
import threading
import time
from pathlib import Path

from torification.app_probe import probe_site
from torification.bridge_race import apply_winning_bridge, parse_bridges, parse_transport_plugins, race_bridges
from torification.config import load_config, state_dir
from torification.adapt import classify_block
from torification.discover import discover_hosts
from torification.tor_health import ensure_torification_tor, signal_newnym
from torification.ignore import load_ignore
from torification.ml.classifier import BlockClassifier
from torification.ml.features import append_training_event, from_probes
from torification.netutil import (
    is_asset_cdn_host,
    is_telegram_dc_ip,
    is_valid_hostname,
    looks_like_ip,
    related_torify_hosts,
    registrable_domain,
    host_matches_active,
)
from torification.pac_generator import generate_pac, load_torified, save_torified, write_pac
from torification.tcp_probe import is_blocked, probe_tcp, probe_via_socks

log = logging.getLogger("torification")


class TorificationDaemon:
    def __init__(self, cfg: dict) -> None:
        self.cfg = cfg
        self.state = state_dir(cfg)
        self.torified_file = self.state / "torified-hosts.json"
        self.ignore = load_ignore(cfg["ignore"]["file"])
        self.torified = load_torified(self.torified_file)
        self._prune_torified()
        self._seen: dict[str, float] = {}
        self._fail_counts: dict[str, int] = {}
        self._dns_cache: dict[str, str] = {}
        self._history_since = time.time()
        ml_cfg = cfg.get("ml", {})
        self.classifier = BlockClassifier(ml_cfg.get("model_path")) if ml_cfg.get("enabled") else None
        self.ml_enabled = bool(ml_cfg.get("enabled"))
        self.ml_threshold = float(ml_cfg.get("confidence_threshold", 0.75))
        self.training_log = ml_cfg.get("training_log", "")
        self._lock = threading.Lock()
        self._race_lock_path = self.state / "bridge-race.lock"
        self._race_lock_fd = None
        self._race_thread: threading.Thread | None = None
        self._active_hosts: set[str] = set()
        self._race_cooldown: dict[str, float] = {}
        tor = cfg["tor"]
        self._socks_ports = [int(tor["socks_port"])]
        fb = cfg.get("probe", {}).get("fallback_socks_port")
        if fb and int(fb) not in self._socks_ports:
            self._socks_ports.append(int(fb))

    def _prune_torified(self) -> None:
        """Убрать мусор (CDN IP, *.1e100.net) из прошлых версий."""
        clean = {}
        for host, meta in self.torified.items():
            if self._should_skip(host) or is_asset_cdn_host(host) or looks_like_ip(host):
                continue
            clean[host] = meta
        if len(clean) != len(self.torified):
            log.info("Pruned torified hosts: %d → %d", len(self.torified), len(clean))
            self.torified = clean
            save_torified(self.torified_file, self.torified)

    def reload_ignore(self) -> None:
        self.ignore = load_ignore(self.cfg["ignore"]["file"])

    def _should_skip(self, host: str) -> bool:
        if looks_like_ip(host) or is_telegram_dc_ip(host):
            return True
        if is_asset_cdn_host(host):
            return True
        if not is_valid_hostname(host):
            return True
        if self.ignore.matches_host(host) or self.ignore.matches_ip(host):
            return True
        return False

    def _refresh_pac(self) -> None:
        tor = self.cfg["tor"]
        pac_cfg = self.cfg["pac"]
        static_path = Path(pac_cfg.get("static_rules", "~/.config/torification/static-rules.pac")).expanduser()
        if not static_path.is_file():
            fallback = Path(__file__).resolve().parents[2] / "config" / "static-rules.pac"
            static_path = fallback if fallback.is_file() else None
        content = generate_pac(
            self.torified,
            "127.0.0.1",
            int(tor["socks_port"]),
            static_path,
        )
        out = Path(pac_cfg["output"]).expanduser()
        write_pac(out, content)
        log.info("PAC updated: %s (%d torified hosts)", out, len(self.torified))

    def _notify(self, title: str, body: str) -> None:
        try:
            subprocess.run(
                ["notify-send", "--app-name=torification", "--expire-time=8000", title, body],
                check=False,
                timeout=3,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    def _torify_hosts(self, hosts: list[str], port: int, reason: str, latency_ms: float | None = None) -> None:
        now = time.time()
        added: list[str] = []
        with self._lock:
            for h in hosts:
                if self._should_skip(h) or looks_like_ip(h):
                    continue
                self.torified[h] = {
                    "since": now,
                    "port": port,
                    "reason": reason,
                    "bridge_latency_ms": latency_ms,
                }
                added.append(h)
            if not added:
                return
            save_torified(self.torified_file, self.torified)
            self._refresh_pac()
        root = added[0]
        self._notify(
            "Сайт разблокирован",
            f"{root} → Tor :{port}. Обнови вкладку: Ctrl+Shift+R",
        )
        log.info("Torified %s (port %s): %s", added, port, reason)

    def _untorify_hosts(self, hosts: list[str]) -> None:
        removed: list[str] = []
        with self._lock:
            for h in hosts:
                if h in self.torified:
                    del self.torified[h]
                    removed.append(h)
            if not removed:
                return
            save_torified(self.torified_file, self.torified)
            self._refresh_pac()
        log.info("Untorified %s — direct OK", removed)

    def _socks_port_from_probe(self, reason: str) -> int:
        if "@:" in reason:
            try:
                return int(reason.rsplit("@:", 1)[-1])
            except ValueError:
                pass
        return int(self.cfg["tor"]["socks_port"])

    def _try_acquire_race_lock(self) -> bool:
        fd = None
        try:
            self._race_lock_path.parent.mkdir(parents=True, exist_ok=True)
            fd = open(self._race_lock_path, "w", encoding="utf-8")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fd.write(str(os.getpid()))
            fd.flush()
            self._race_lock_fd = fd
            return True
        except OSError:
            if fd is not None:
                try:
                    fd.close()
                except OSError:
                    pass
            return False

    def _release_race_lock(self) -> None:
        fd = self._race_lock_fd
        self._race_lock_fd = None
        if fd is None:
            return
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        except OSError:
            pass
        try:
            fd.close()
        except OSError:
            pass

    def _race_and_torify(self, host: str) -> bool:
        if not is_valid_hostname(host) or looks_like_ip(host):
            return False
        if not host_matches_active(host, self._active_hosts):
            log.info("Skip bridge race for %s — not open in browser", host)
            return False
        cooldown = float(self.cfg.get("general", {}).get("bridge_race_cooldown_s", 3600))
        if cooldown and time.time() - self._race_cooldown.get(host, 0) < cooldown:
            log.info("Bridge race cooldown for %s (%.0fs left)", host, cooldown - (time.time() - self._race_cooldown[host]))
            return False
        if self._race_thread and self._race_thread.is_alive():
            log.info("Bridge race already running — skip %s", host)
            return False
        if not self._try_acquire_race_lock():
            log.info("Bridge race lock busy — skip %s", host)
            return False
        self._race_cooldown[host] = time.time()
        try:
            self._race_thread = threading.Thread(
                target=self._race_and_torify_locked,
                args=(host,),
                daemon=True,
                name=f"bridge-race-{host}",
            )
            self._race_thread.start()
        except Exception:
            self._release_race_lock()
            raise
        return True

    def _race_and_torify_locked(self, host: str) -> None:
        try:
            self._race_and_torify_body(host)
        finally:
            self._release_race_lock()

    def _race_and_torify_body(self, host: str) -> None:
        tor = self.cfg["tor"]
        torrc = Path(tor["torrc"]).expanduser()
        bridges = parse_bridges(torrc)
        if not bridges:
            log.error("No bridges in %s", torrc)
            return
        log.info("Bridge race for %s (%d bridges)...", host, len(bridges))
        self._notify("Гонка мостов", f"Подбираю мост для {host}…")
        results = race_bridges(
            bridges,
            host,
            exit_countries=tor.get("exit_countries", "{us},{de},{gb}"),
            plugins=parse_transport_plugins(torrc),
        )
        if not results:
            log.warning("No working bridge for %s", host)
            self._notify("Не удалось разблокировать", f"{host}: нет рабочего моста")
            return
        winner = results[0]
        log.info("Winner: %s @ %.0f ms (HTTP confirmed)", winner.bridge.address, winner.latency_ms)
        apply_winning_bridge(torrc, tor["bridges_file"], winner.bridge, bridges)
        subprocess.run(["systemctl", "--user", "restart", "torification-tor.service"], check=False)
        cookie = Path(tor["data_dir"]).expanduser() / "control_auth_cookie"
        if not ensure_torification_tor(int(tor["socks_port"]), int(tor["control_port"]), cookie):
            log.warning("Tor did not come back after bridge switch for %s", host)
            self._notify("Мост сменён, Tor не поднялся", host)
            return
        app = probe_site(host, self._socks_ports, timeout_s=20)
        if app.via_socks and app.via_socks.ok:
            port = self._socks_port_from_probe(app.via_socks.reason)
            self._torify_hosts(related_torify_hosts(host), port, "bridge_race", winner.latency_ms)
        else:
            log.warning("Bridge race done but %s still not OK via HTTP", host)

    def _evaluate_host(self, host: str, force: bool = False, allow_bridge_race: bool = True) -> None:
        if self._should_skip(host):
            return

        # Probe the opened host (chat.openai.com), not eTLD+1 (openai.com).
        check_host = host
        root = registrable_domain(host)

        now = time.time()
        last = self._seen.get(check_host, 0)
        if not force:
            meta = self.torified.get(check_host) or self.torified.get(root)
            if meta:
                interval = float(self.cfg["general"].get("retorify_interval", 3600))
                if interval and now - meta.get("since", 0) < interval:
                    return
            elif now - last < 15:
                return
        self._seen[check_host] = now

        tor = self.cfg["tor"]
        cookie = Path(tor["data_dir"]).expanduser() / "control_auth_cookie"
        if not ensure_torification_tor(int(tor["socks_port"]), int(tor["control_port"]), cookie):
            log.error("torification-tor not ready")
            self._notify("Tor не готов", "Перезапуск torification-tor…")
            return

        probe_cfg = self.cfg.get("probe", {})
        timeout = int(probe_cfg.get("http_timeout_s", 15))

        app = probe_site(check_host, socks_ports=self._socks_ports, timeout_s=timeout)
        direct_tcp = probe_tcp(check_host, 443, int(probe_cfg.get("connect_timeout_ms", 5000)))
        self._record_ml(check_host, app, direct_tcp)

        # DPI/ТСПУ: TCP ok, HTTP fail
        if not app.direct.ok and not is_blocked(direct_tcp) and app.needs_torify:
            log.info("DPI pattern on %s: tcp=%s http=%s", check_host, direct_tcp.state.value, app.direct.reason)

        log.info(
            "HTTP %s: direct=%s (%s) socks=%s",
            check_host,
            app.direct.ok,
            app.direct.reason,
            app.via_socks.reason if app.via_socks else "n/a",
        )

        if app.direct.ok:
            self._fail_counts[check_host] = 0
            self._untorify_hosts(related_torify_hosts(check_host))
            return

        plan = classify_block(app, direct_tcp)
        log.info("Adapt %s: kind=%s action=%s", check_host, plan.kind.value, plan.action)

        self._fail_counts[check_host] = self._fail_counts.get(check_host, 0) + 1
        threshold = 1 if force else int(probe_cfg.get("fail_threshold", 1))
        if self._fail_counts[check_host] < threshold:
            return

        self._auto_fix(check_host, app, direct_tcp, plan, allow_bridge_race=allow_bridge_race)

    def _record_ml(self, host: str, app, direct_tcp) -> None:
        if not self.training_log and not self.classifier:
            return
        try:
            from torification.tcp_probe import ProbeResult, ProbeState

            socks_probe = None
            if app.via_socks is not None:
                st = ProbeState.HTTP_OK if app.via_socks.ok else ProbeState.ERROR
                socks_probe = ProbeResult(
                    host, 443, st, app.via_socks.latency_ms, app.via_socks.reason,
                )
            feats = from_probes(host, direct_tcp, socks_probe, self._fail_counts.get(host, 0))
            if self.training_log:
                label = "ok" if app.direct.ok else "blocked"
                append_training_event(
                    self.training_log, feats, label, extra={"http": app.direct.reason},
                )
            if self.classifier:
                blocked, conf = self.classifier.predict_blocked(feats, self.ml_threshold)
                log.info("ML %s blocked=%s conf=%.2f", host, blocked, conf)
        except Exception:
            log.debug("ML record failed for %s", host, exc_info=True)

    def _auto_fix(self, check_host: str, app, direct_tcp, plan, allow_bridge_race: bool = True) -> None:
        """Автоматически применить fix — без команды пользователя."""
        tor = self.cfg["tor"]

        if plan.action == "torify" and plan.port:
            self._torify_hosts(
                related_torify_hosts(check_host),
                plan.port,
                plan.detail,
                app.via_socks.latency_ms if app.via_socks else None,
            )
            return

        if plan.action == "bridge_race":
            if not allow_bridge_race:
                log.info("Skip bridge race for %s — only search candidate, not open tab", check_host)
                if app.via_socks and app.via_socks.ok:
                    port = self._socks_port_from_probe(app.via_socks.reason)
                    self._torify_hosts(related_torify_hosts(check_host), port, plan.detail)
                return
            # Tor TCP ok → сначала torify (страница может пойти через PAC), гонку — в фоне
            socks = probe_via_socks(check_host, 443, "127.0.0.1", int(tor["socks_port"]), 20000)
            if app.via_socks and app.via_socks.ok:
                port = self._socks_port_from_probe(app.via_socks.reason)
                self._torify_hosts(related_torify_hosts(check_host), port, plan.detail)
                return
            if socks.state.value in ("ok", "tcp_ok", "tls_ok"):
                cookie = Path(tor["data_dir"]).expanduser() / "control_auth_cookie"
                signal_newnym(int(tor["control_port"]), cookie)
                time.sleep(6)
                app2 = probe_site(check_host, self._socks_ports, timeout_s=15)
                if app2.via_socks and app2.via_socks.ok:
                    port = self._socks_port_from_probe(app2.via_socks.reason)
                    self._torify_hosts(related_torify_hosts(check_host), port, plan.detail)
                    return
            self._race_and_torify(check_host)

    def poll_once(self) -> None:
        browsers = self.cfg["browsers"]
        names = browsers["process_names"]
        use_history = bool(browsers.get("use_history", True))
        discovery = discover_hosts(names, self._history_since, self._dns_cache, use_history=use_history)
        self._history_since = time.time()
        active = set(discovery.active)
        for h in list(active):
            active.add(registrable_domain(h))
        self._active_hosts = active

        for host in sorted(discovery.all_hosts):
            if self._should_skip(host):
                continue
            allow_race = host_matches_active(host, discovery.active)
            try:
                self._evaluate_host(host, allow_bridge_race=allow_race)
            except Exception:
                log.exception("evaluate %s", host)

        self._watchdog_torified()

    def _watchdog_torified(self) -> None:
        """Перепроверка torified-хостов. После PAC браузер ходит на :9054, ss больше не видит сайт."""
        if not self.torified:
            return
        now = time.time()
        with self._lock:
            items = list(self.torified.items())
        for host, meta in items:
            if now - meta.get("last_check", 0) < 300:
                continue
            with self._lock:
                if host in self.torified:
                    self.torified[host]["last_check"] = now
                    save_torified(self.torified_file, self.torified)
            self._active_hosts.add(host)
            self._active_hosts.add(registrable_domain(host))
            port = int(meta.get("port", self.cfg["tor"]["socks_port"]))
            app = probe_site(host, [port], timeout_s=12)
            if not app.via_socks or not app.via_socks.ok:
                log.warning("Torified %s failing via :%s — re-fix", host, port)
                self._evaluate_host(host, force=True, allow_bridge_race=True)

    def fix_host(self, host: str) -> None:
        """Принудительная проверка и разблокировка одного хоста."""
        host = host.lower().strip()
        self._active_hosts.add(host)
        self._active_hosts.add(registrable_domain(host))
        self._evaluate_host(host, force=True, allow_bridge_race=True)

    def run(self) -> None:
        interval = float(self.cfg["general"]["poll_interval"])
        self._refresh_pac()
        log.info("torificationd started (HTTP probe), poll=%.1fs", interval)
        while True:
            self.reload_ignore()
            self.poll_once()
            time.sleep(interval)


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    cfg = load_config()
    TorificationDaemon(cfg).run()


if __name__ == "__main__":
    main()
