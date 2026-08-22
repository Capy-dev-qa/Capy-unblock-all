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


def test_start_all_passes_units(monkeypatch):
    seen = {}

    def fake(*args, timeout=15):
        seen["args"] = args
        return CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("torification.control._systemctl", fake)
    start_all()
    assert seen["args"][0] == "start"
    assert "torification.service" in seen["args"]


def test_set_autostart_enable_disable(monkeypatch):
    seen = []

    def fake(*args, timeout=15):
        seen.append(args[0])
        return CompletedProcess(args, 0, "", "")

    monkeypatch.setattr("torification.control._systemctl", fake)
    set_autostart(True)
    set_autostart(False)
    assert seen == ["enable", "disable"]
