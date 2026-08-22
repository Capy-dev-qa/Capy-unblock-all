"""Shared IP / host helpers."""

from __future__ import annotations

import ipaddress
import re


# Telegram DC — PAC static-rules покрывает isInNet; daemon не должен probe/torify по IP
TELEGRAM_DC_NETS = [
    ipaddress.ip_network("149.154.160.0/20"),
    ipaddress.ip_network("91.108.4.0/22"),
    ipaddress.ip_network("91.108.8.0/22"),
    ipaddress.ip_network("91.108.12.0/22"),
    ipaddress.ip_network("91.108.16.0/22"),
    ipaddress.ip_network("91.108.20.0/22"),
    ipaddress.ip_network("91.108.56.0/21"),
    ipaddress.ip_network("95.161.64.0/20"),
]


def looks_like_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def is_telegram_dc_ip(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return any(addr in net for net in TELEGRAM_DC_NETS)


def is_valid_hostname(host: str) -> bool:
    """Reject garbage from ss (e.g. single digit '1', truncated IP '8.8')."""
    if not host or len(host) < 2:
        return False
    if host.isdigit():
        return False
    if looks_like_ip(host):
        return True
    if is_asset_cdn_host(host):
        return False
    # Real DNS names have at least one letter; "167.99" is a sliced IPv4.
    if not re.search(r"[a-zA-Z]", host):
        return False
    return bool(re.match(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$", host, re.I))


CDN_SUFFIXES = (
    ".1e100.net",
    ".googleusercontent.com",
    ".gstatic.com",
    ".googlevideo.com",
    ".ytimg.com",
    ".fbcdn.net",
    ".cloudfront.net",
    ".akamaized.net",
    ".akamaitechnologies.com",
    ".fastly.net",
    ".doubleclick.net",
    ".googlesyndication.com",
)

CDN_EXACT = frozenset({
    "storage.googleapis.com",
    "www.gstatic.com",
})

# Reverse DNS от ss (Tinkercad → ec2-*.compute.amazonaws.com) — не torify как «amazon»
# amazon.com (магазин) — отдельный домен, разблокируется нормально.
EC2_RDNS_SUFFIXES = (
    ".compute.amazonaws.com",
    ".compute-1.amazonaws.com",
)

CLOUD_INFRA_SUFFIXES = (
    ".amazonaws.com",  # S3/API; магазин amazon.com не входит
    ".azurewebsites.net",
    ".blob.core.windows.net",
    ".azureedge.net",
    ".cloudos.autodesk.com",
)

CLOUD_INFRA_EXACT = frozenset({
    "amazonaws.com",  # корень AWS API, не магазин
    "cloudfront.net",
})

EC2_RDNS_RE = re.compile(
    r"^ec2[--][0-9a-f-]+\.[a-z0-9-]+\.(compute(?:-\d+)?\.amazonaws\.com)$",
    re.I,
)


def is_ec2_reverse_dns(host: str) -> bool:
    """Имя вида ec2-12-34-56-78.us-west-2.compute.amazonaws.com из reverse DNS ss."""
    h = host.lower().rstrip(".")
    if h == "amazonaws.com":
        return True
    if EC2_RDNS_RE.match(h):
        return True
    return any(h.endswith(s) for s in EC2_RDNS_SUFFIXES)


def is_cloud_infra_host(host: str) -> bool:
    h = host.lower().rstrip(".")
    if is_ec2_reverse_dns(h):
        return True
    if h in CLOUD_INFRA_EXACT:
        return True
    return any(h.endswith(s) for s in CLOUD_INFRA_SUFFIXES)


def is_asset_cdn_host(host: str) -> bool:
    h = host.lower().rstrip(".")
    if h in CDN_EXACT:
        return True
    if is_cloud_infra_host(h):
        return True
    return any(h == s[1:] or h.endswith(s) for s in CDN_SUFFIXES)


MULTI_PART_SUFFIXES = frozenset({
    "co.uk", "com.cn", "co.jp", "com.au", "co.nz", "com.br", "co.kr", "com.tw",
    "org.uk", "ac.uk", "gov.uk", "net.au",
})


def registrable_domain(host: str) -> str:
    h = host.lower().rstrip(".")
    if looks_like_ip(h) or is_cloud_infra_host(h):
        return h
    parts = h.split(".")
    if len(parts) <= 2:
        return h
    suffix2 = ".".join(parts[-2:])
    if suffix2 in MULTI_PART_SUFFIXES and len(parts) >= 3:
        return ".".join(parts[-3:])
    return suffix2


def related_torify_hosts(host: str) -> list[str]:
    h = host.lower().rstrip(".")
    root = registrable_domain(h)
    groups: dict[str, list[str]] = {
        "openai.com": ["openai.com", "chatgpt.com", "oaistatic.com"],
        "chatgpt.com": ["openai.com", "chatgpt.com", "oaistatic.com"],
        "amazon.com": ["amazon.com", "media-amazon.com", "ssl-images-amazon.com"],
    }
    if root in groups:
        out = list(groups[root])
        if h not in out:
            out.append(h)
        return out
    return [root] if root == h else [root, h]


def host_matches_active(host: str, active: set[str]) -> bool:
    """True if this host (or its eTLD+1) is among live browser connections."""
    if not host or not active:
        return False
    h = host.lower().rstrip(".")
    if h in active:
        return True
    root = registrable_domain(h)
    if root in active:
        return True
    return any(registrable_domain(a) == root for a in active)
