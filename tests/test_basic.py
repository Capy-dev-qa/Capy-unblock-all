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
    assert not is_valid_hostname("8.8")
    assert not is_valid_hostname("167.99")
    assert is_valid_hostname("cursor.com")
    assert is_valid_hostname("149.154.167.99")


def test_registrable_domain_keeps_ip():
    assert registrable_domain("8.8.8.8") == "8.8.8.8"
    assert registrable_domain("149.154.167.99") == "149.154.167.99"


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

    monkeypatch.setattr("torification.discover.read_ss_connections", lambda _names: [])
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
    assert is_cloud_infra_host("s3.amazonaws.com")
    assert is_cloud_infra_host("s3.eu-west-1.amazonaws.com")
    assert not is_cloud_infra_host("amazon.com")
    assert not is_cloud_infra_host("www.amazon.com")
    assert registrable_domain("www.amazon.com") == "amazon.com"


def test_host_matches_active_subdomain():
    from torification.netutil import host_matches_active

    active = {"www.example.com", "chat.openai.com"}
    assert host_matches_active("example.com", active)
    assert host_matches_active("www.example.com", active)
    assert host_matches_active("api.example.com", active)
    assert host_matches_active("openai.com", active)
    assert not host_matches_active("other.org", active)


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


def test_pac_keeps_static_without_direct_return():
    from pathlib import Path
    import tempfile
    from torification.pac_generator import generate_pac

    static = 'function FindProxyForURL(url, host) {\n    if (host === "a.com") return "SOCKS5 127.0.0.1:9050";\n}\n'
    with tempfile.NamedTemporaryFile("w", suffix=".pac", delete=False) as f:
        f.write(static)
        path = Path(f.name)
    out = generate_pac({"blocked.com": {}}, "127.0.0.1", 9054, path)
    assert "a.com" in out
    assert "blocked.com" in out


def test_pac_empty_torified_keeps_static_without_direct():
    from pathlib import Path
    import tempfile

    static = 'function FindProxyForURL(url, host) {\n    if (host === "a.com") return "SOCKS5 127.0.0.1:9050";\n}\n'
    with tempfile.NamedTemporaryFile("w", suffix=".pac", delete=False) as f:
        f.write(static)
        path = Path(f.name)
    out = generate_pac({}, "127.0.0.1", 9054, path)
    assert "a.com" in out
    assert "FindProxyForURL" in out
    assert "torification dynamic" not in out


def test_search_candidates_when_google_only_in_ss(monkeypatch):
    from torification.discover import discover_hosts
    from torification.connection_watcher import BrowserEvent

    monkeypatch.setattr(
        "torification.discover.read_ss_connections",
        lambda _n: [BrowserEvent(host="www.google.com", source="ss", ts=0)],
    )
    monkeypatch.setattr(
        "torification.discover.read_urls_since",
        lambda _s, _l=10: ["https://www.google.com/search?q=rule34vid"],
    )
    d = discover_hosts(["chrome"], 0.0, {}, use_history=True)
    assert "www.google.com" not in d.active
    assert "rule34video.com" in d.search_candidates


def test_search_candidates_from_history_without_ss_google(monkeypatch):
    from torification.discover import discover_hosts

    monkeypatch.setattr("torification.discover.read_ss_connections", lambda _n: [])
    monkeypatch.setattr(
        "torification.discover.read_urls_since",
        lambda _s, _l=10: ["https://www.google.com/search?q=rule34vid"],
    )
    d = discover_hosts(["chrome"], 0.0, {}, use_history=True)
    assert "rule34video.com" in d.search_candidates
