"""TCP connectivity probe: verify SYN → SYN-ACK → ACK (via connect) + optional TLS."""

from __future__ import annotations

import socket
import ssl
import threading
import time
from dataclasses import dataclass
from enum import Enum


class ProbeState(str, Enum):
    OK = "ok"
    TCP_OK = "tcp_ok"  # handshake ok, TLS failed (non-443)
    TLS_OK = "tls_ok"
    HTTP_OK = "http_ok"
    TIMEOUT = "timeout"  # SYN or SYN-ACK timeout
    REFUSED = "refused"  # RST
    UNREACHABLE = "unreachable"
    TLS_ERROR = "tls_error"
    DNS_FAIL = "dns_fail"
    ERROR = "error"


@dataclass
class ProbeResult:
    host: str
    port: int
    state: ProbeState
    latency_ms: float
    detail: str = ""
    syn_rtt_ms: float | None = None  # best-effort; equals latency_ms for connect()


def _getaddrinfo(host: str, port: int, timeout: float):
    result: list = []
    err: list[BaseException] = []

    def _run() -> None:
        try:
            result.extend(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except OSError as e:
            err.append(e)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        raise socket.gaierror(socket.EAI_AGAIN, "dns timeout")
    if err:
        raise err[0]
    return result


def probe_tcp(
    host: str,
    port: int = 443,
    timeout_ms: int = 5000,
    verify_tls: bool = True,
) -> ProbeResult:
    """Full TCP handshake via connect(); for :443 optionally verify TLS."""
    host = host.lower().rstrip(".")
    timeout = timeout_ms / 1000.0
    t0 = time.perf_counter()

    try:
        infos = _getaddrinfo(host, port, timeout)
    except socket.gaierror as e:
        return ProbeResult(host, port, ProbeState.DNS_FAIL, 0, str(e))

    last_err = ""
    for family, socktype, proto, _canon, sockaddr in infos:
        s = socket.socket(family, socktype, proto)
        s.settimeout(timeout)
        try:
            s.connect(sockaddr)
            latency = (time.perf_counter() - t0) * 1000
            if port != 443 or not verify_tls:
                s.close()
                return ProbeResult(host, port, ProbeState.TCP_OK, latency, syn_rtt_ms=latency)

            ctx = ssl.create_default_context()
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
            with ctx.wrap_socket(s, server_hostname=host) as tls:
                tls.do_handshake()
            latency = (time.perf_counter() - t0) * 1000
            return ProbeResult(host, port, ProbeState.TLS_OK, latency, syn_rtt_ms=latency)
        except socket.timeout:
            last_err = "timeout"
        except ConnectionRefusedError:
            last_err = "refused"
        except ssl.SSLError as e:
            return ProbeResult(
                host,
                port,
                ProbeState.TLS_ERROR,
                (time.perf_counter() - t0) * 1000,
                str(e),
            )
        except OSError as e:
            last_err = str(e)
            if "No route" in str(e) or "Network is unreachable" in str(e):
                return ProbeResult(
                    host,
                    port,
                    ProbeState.UNREACHABLE,
                    (time.perf_counter() - t0) * 1000,
                    str(e),
                )
        finally:
            try:
                s.close()
            except OSError:
                pass

    if last_err == "timeout":
        st = ProbeState.TIMEOUT
    elif last_err == "refused":
        st = ProbeState.REFUSED
    else:
        st = ProbeState.ERROR
    return ProbeResult(host, port, st, (time.perf_counter() - t0) * 1000, last_err)


def probe_via_socks(
    host: str,
    port: int,
    socks_host: str,
    socks_port: int,
    timeout_ms: int = 15000,
) -> ProbeResult:
    """Probe through SOCKS5 (Tor): remote TCP handshake terminated at exit."""
    import struct

    host = host.lower().rstrip(".")
    timeout = timeout_ms / 1000.0
    t0 = time.perf_counter()
    s: socket.socket | None = None
    try:
        host_bytes = host.encode("idna")
        if len(host_bytes) > 255:
            return ProbeResult(host, port, ProbeState.ERROR, 0, "hostname too long")
        s = socket.create_connection((socks_host, socks_port), timeout=timeout)
        s.settimeout(timeout)
        s.sendall(b"\x05\x01\x00")
        if s.recv(2) != b"\x05\x00":
            return ProbeResult(host, port, ProbeState.ERROR, 0, "socks auth")
        req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + struct.pack("!H", port)
        s.sendall(req)
        hdr = s.recv(4)
        if len(hdr) < 4 or hdr[1] != 0:
            return ProbeResult(host, port, ProbeState.ERROR, (time.perf_counter() - t0) * 1000, f"socks {hdr!r}")
        atyp = hdr[3]
        if atyp == 1:
            rest = s.recv(6)
            if len(rest) < 6:
                return ProbeResult(host, port, ProbeState.ERROR, (time.perf_counter() - t0) * 1000, "socks truncated")
        elif atyp == 3:
            n = s.recv(1)
            if not n:
                return ProbeResult(host, port, ProbeState.ERROR, (time.perf_counter() - t0) * 1000, "socks truncated")
            rest = s.recv(n[0] + 2)
            if len(rest) < n[0] + 2:
                return ProbeResult(host, port, ProbeState.ERROR, (time.perf_counter() - t0) * 1000, "socks truncated")
        elif atyp == 4:
            rest = s.recv(18)
            if len(rest) < 18:
                return ProbeResult(host, port, ProbeState.ERROR, (time.perf_counter() - t0) * 1000, "socks truncated")
        else:
            return ProbeResult(host, port, ProbeState.ERROR, (time.perf_counter() - t0) * 1000, f"socks atyp {atyp}")
        return ProbeResult(host, port, ProbeState.OK, (time.perf_counter() - t0) * 1000, "via_socks")
    except socket.timeout:
        return ProbeResult(host, port, ProbeState.TIMEOUT, (time.perf_counter() - t0) * 1000, "socks timeout")
    except (OSError, UnicodeError) as e:
        return ProbeResult(host, port, ProbeState.ERROR, (time.perf_counter() - t0) * 1000, str(e))
    finally:
        if s is not None:
            try:
                s.close()
            except OSError:
                pass


def is_blocked(result: ProbeResult) -> bool:
    return result.state in (
        ProbeState.TIMEOUT,
        ProbeState.REFUSED,
        ProbeState.UNREACHABLE,
        ProbeState.DNS_FAIL,
        ProbeState.TLS_ERROR,
        ProbeState.ERROR,
    )


def probe_http_status(
    host: str,
    path: str = "/",
    timeout_ms: int = 10000,
    via_socks: tuple[str, int] | None = None,
) -> ProbeResult:
    """Lightweight HTTP GET for app-level block pages (like ytmusic music_ok)."""
    import urllib.error
    import urllib.request

    url = f"https://{host}{path}"
    t0 = time.perf_counter()
    if via_socks:
        return probe_via_socks(host, 443, via_socks[0], via_socks[1], timeout_ms)

    req = urllib.request.Request(url, headers={"User-Agent": "torification/0.1"})
    try:
        with urllib.request.urlopen(req, timeout=timeout_ms / 1000) as resp:
            body = resp.read(65536).decode("utf-8", errors="replace")
            latency = (time.perf_counter() - t0) * 1000
            if "not available in your" in body.lower():
                return ProbeResult(host, 443, ProbeState.ERROR, latency, "geo_block_body")
            return ProbeResult(host, 443, ProbeState.HTTP_OK, latency)
    except urllib.error.HTTPError as e:
        return ProbeResult(host, 443, ProbeState.HTTP_OK, (time.perf_counter() - t0) * 1000, f"http_{e.code}")
    except Exception as e:
        return ProbeResult(host, 443, ProbeState.ERROR, (time.perf_counter() - t0) * 1000, str(e))
