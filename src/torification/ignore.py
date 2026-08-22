"""Parse ~/.config/torification/torification-ignore."""

from __future__ import annotations

import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class IgnoreList:
    exact: set[str] = field(default_factory=set)
    suffixes: list[str] = field(default_factory=list)  # .example.com
    globs: list[str] = field(default_factory=list)
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)

    def matches_host(self, host: str) -> bool:
        if not host:
            return True
        h = host.lower().rstrip(".")
        if h in self.exact:
            return True
        for suf in self.suffixes:
            if h == suf[1:] or h.endswith(suf):
                return True
        for g in self.globs:
            if fnmatch.fnmatch(h, g):
                return True
        return False

    def matches_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(addr in net for net in self.networks)


def load_ignore(path: str | Path) -> IgnoreList:
    p = Path(path).expanduser()
    out = IgnoreList()
    if not p.is_file():
        return out
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "/" in line and _looks_like_cidr(line):
            try:
                out.networks.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                out.exact.add(line.lower())
            continue
        if line.startswith("."):
            out.suffixes.append(line.lower())
        elif "*" in line or "?" in line:
            out.globs.append(line.lower())
        else:
            out.exact.add(line.lower())
    return out


def _looks_like_cidr(s: str) -> bool:
    return bool(re.match(r"^[\d.a-fA-F:]+/\d+$", s))
