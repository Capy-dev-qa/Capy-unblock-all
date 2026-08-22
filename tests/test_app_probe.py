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


def test_classify_404_is_reachable():
    r = _classify_http(404, 200, "<html>not found</html>", 100)
    assert r.ok


def test_classify_401_is_reachable():
    r = _classify_http(401, 80, "auth", 50)
    assert r.ok


def test_classify_408_is_block():
    r = _classify_http(408, 0, "", 50)
    assert not r.ok
    assert r.reason == "http_408"


def test_cdn_skipped():
    assert is_asset_cdn_host("lf-in-f94.1e100.net")
    assert not is_asset_cdn_host("chatgpt.com")


def test_openai_cluster():
    hosts = related_torify_hosts("chatgpt.com")
    assert "openai.com" in hosts
    assert "chatgpt.com" in hosts
    assert "chat.openai.com" in related_torify_hosts("chat.openai.com")


def test_403_both_sides_no_race():
    from torification.adapt import classify_block, BlockKind
    from torification.app_probe import AppProbeResult, HttpProbeResult

    app = AppProbeResult(
        host="s3.example.com",
        direct=HttpProbeResult(False, 403, 100, "http_403"),
        via_socks=HttpProbeResult(False, 403, 80, "http_403"),
        needs_torify=False,
        tor_helps=False,
        suggest_bridge_race=True,
    )
    plan = classify_block(app)
    assert plan.kind == BlockKind.CF_CHALLENGE
    assert plan.action == "none"


def test_race_bridges_empty():
    from torification.bridge_race import race_bridges

    assert race_bridges([], "example.com") == []


def test_ml_socks_ok_counts_http_ok():
    from torification.ml.features import from_probes
    from torification.tcp_probe import ProbeResult, ProbeState

    direct = ProbeResult("ex.com", 443, ProbeState.TIMEOUT, 100)
    socks = ProbeResult("ex.com", 443, ProbeState.HTTP_OK, 80, "ok")
    feats = from_probes("ex.com", direct, socks)
    assert feats.socks_ok == 1
    assert feats.direct_failed == 1
