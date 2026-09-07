"""Tests for systemd --user control helpers."""

from subprocess import CompletedProcess

from torification.control import SERVICES, all_running, set_autostart, start_all, status_all


def test_status_all_uses_systemctl(monkeypatch):
    calls: list[tuple[str, ...]] = []

    def fake(*args, timeout=15):
        calls.append(args)
        unit = args[-1]
        if args[0] == "is-active":
            return CompletedProcess(args, 0 if unit == "torification-tor.service" else 1, "", "")
        return CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("torification.control._systemctl", fake)
    rows = status_all()
    assert [r.unit for r in rows] == list(SERVICES)
    assert rows[0].active is True
    assert rows[1].active is False
    assert all_running(rows) is False


def test_start_all_resets_failed_then_starts(monkeypatch):
    calls: list[tuple[str, ...]] = []

    def fake(*args, timeout=15):
        calls.append(args)
        return CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("torification.control._systemctl", fake)
    monkeypatch.setattr("torification.control._apply_cursor_proxy_safe", lambda: None)
    start_all()
    assert calls[0][0] == "reset-failed"
    assert calls[1][0] == "start"
    assert "torification-tor.service" in calls[1]


def test_start_all_passes_units(monkeypatch):
    seen = {}

    def fake(*args, timeout=15):
        seen["args"] = args
        return CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("torification.control._systemctl", fake)
    monkeypatch.setattr("torification.control._apply_cursor_proxy_safe", lambda: None)
    start_all()
    assert seen["args"][0] == "start"
    assert "torification.service" in seen["args"]
    assert "torification-cursor-proxy.service" in seen["args"]


def test_start_all_applies_cursor_proxy(monkeypatch):
    seen = {"apply": 0}

    def fake(*args, timeout=15):
        return CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("torification.control._systemctl", fake)
    monkeypatch.setattr(
        "torification.control._apply_cursor_proxy_safe",
        lambda: seen.__setitem__("apply", seen["apply"] + 1),
    )
    start_all()
    assert seen["apply"] == 1


def test_stop_all_restores_cursor_proxy(monkeypatch):
    seen = {"restore": 0}

    def fake(*args, timeout=15):
        return CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("torification.control._systemctl", fake)
    monkeypatch.setattr(
        "torification.control._restore_cursor_proxy_safe",
        lambda: seen.__setitem__("restore", seen["restore"] + 1),
    )
    from torification.control import stop_all

    stop_all()
    assert seen["restore"] == 1


def test_set_autostart_enable_disable(monkeypatch):
    seen = []

    def fake(*args, timeout=15):
        seen.append(args[0])
        return CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("torification.control._systemctl", fake)
    set_autostart(True)
    set_autostart(False)
    assert seen == ["enable", "disable"]
