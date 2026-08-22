"""Basic unit tests for torification."""

from __future__ import annotations

import time

from torification.netutil import is_telegram_dc_ip, is_valid_hostname, registrable_domain
from torification.discover import hosts_from_url, query_to_host_candidates
from torification.pac_generator import generate_pac
from torification.ignore import load_ignore


def test_chrome_history_timestamp_ordering():
    now = time.time()
    chrome_now = (now + 11644473600) * 1_000_000
    chrome_past = (now - 3600 + 11644473600) * 1_000_000
    assert chrome_now > chrome_past


def test_is_valid_hostname_rejects_garbage():
    assert not is_valid_hostname("1")
    assert not is_valid_hostname("")
    assert is_valid_hostname("cursor.com")
    assert is_valid_hostname("149.154.167.99")


def test_telegram_dc_ip():
    assert is_telegram_dc_ip("149.154.167.99")
    assert not is_telegram_dc_ip("8.8.8.8")


def test_google_search_query_candidates():
    assert "rule34video.com" in query_to_host_candidates("rule34vid")
    assert "gmail.org" not in query_to_host_candidates("gmail")
    assert not query_to_host_candidates("open ai")
    url = "https://www.google.com/search?q=rule34vid&oq=rule34vid"
    assert "rule34video.com" in hosts_from_url(url)
    assert "www.google.com" not in hosts_from_url(url)


def test_registrable_domain_multi_part_tld():
    assert registrable_domain("hub.vgnlab.com.cn") == "vgnlab.com.cn"


def test_discord_subdomains_ignored():
    ig = load_ignore("config/torification-ignore")
    for h in (
        "discord.com",
        "gateway.discord.gg",
        "cdn.discordapp.com",
        "discord.media",
        "discordserver.info",
    ):
        assert ig.matches_host(h), h


def test_discover_ss_only_without_browser(monkeypatch):
    from torification.discover import discover_hosts

    monkeypatch.setattr("torification.discover.read_ss_pending_hosts", lambda _names: [])
    monkeypatch.setattr("torification.discover.read_ss_active_ips", lambda _names: [])
    d = discover_hosts(["nonexistent-browser"], time.time(), {})
    assert d.active == set()
    assert d.search_candidates == set()


def test_on_search_engine():
    from torification.discover import _on_search_engine

    assert _on_search_engine({"www.google.com"})
    assert not _on_search_engine({"rule34video.com"})


def test_cloud_infra_not_torified():
    from torification.netutil import is_cloud_infra_host, is_ec2_reverse_dns, registrable_domain

    ec2 = "ec2-44-194-133-106.compute-1.amazonaws.com"
    assert is_ec2_reverse_dns(ec2)
    assert is_cloud_infra_host(ec2)
    assert registrable_domain(ec2) == ec2
    assert is_cloud_infra_host("amazonaws.com")
    assert not is_cloud_infra_host("amazon.com")
    assert not is_cloud_infra_host("www.amazon.com")
    assert registrable_domain("www.amazon.com") == "amazon.com"


def test_pac_injects_before_direct():
    static = 'function FindProxyForURL(url, host) {\n    if (host === "a.com") return "DIRECT";\n    return "DIRECT";\n}\n'
    from pathlib import Path
    import tempfile

    with tempfile.NamedTemporaryFile("w", suffix=".pac", delete=False) as f:
        f.write(static)
        path = Path(f.name)
    out = generate_pac({"blocked.com": {}}, "127.0.0.1", 9054, path)
    assert "blocked.com" in out
    assert out.index("blocked.com") < out.rindex('return "DIRECT"')
