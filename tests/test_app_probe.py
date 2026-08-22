"""Tests for app_probe classification."""

from torification.app_probe import _classify_http
from torification.netutil import is_asset_cdn_host, related_torify_hosts


def test_classify_403_blocked():
    r = _classify_http(403, 9000, "<html>cf-mitigated</html>", 100)
    assert not r.ok
    assert r.reason == "http_403"


def test_classify_200_ok():
    r = _classify_http(200, 5000, "<html><body>Hello</body></html>", 100)
    assert r.ok


def test_cdn_skipped():
    assert is_asset_cdn_host("lf-in-f94.1e100.net")
    assert not is_asset_cdn_host("chatgpt.com")


def test_openai_cluster():
    hosts = related_torify_hosts("chatgpt.com")
    assert "openai.com" in hosts
    assert "chatgpt.com" in hosts
