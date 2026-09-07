"""Cursor settings.json proxy apply/restore."""

from __future__ import annotations

import json

from torification.cursor_proxy import (
    TOR_PROXY_URL,
    apply_cursor_proxy,
    cursor_proxy_status,
    load_json_object,
    restore_cursor_proxy,
)


def test_load_json_fixes_missing_comma(tmp_path):
    p = tmp_path / "settings.json"
    p.write_text(
        '{\n  "window.commandCenter": true\n  "http.proxy": "http://127.0.0.1:8118"\n}\n',
        encoding="utf-8",
    )
    data = load_json_object(p)
    assert data["window.commandCenter"] is True
    assert data["http.proxy"] == "http://127.0.0.1:8118"


def test_apply_and_restore_cursor_proxy(tmp_path, monkeypatch):
    settings = tmp_path / "User" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(
        json.dumps(
            {
                "window.titleBarStyle": "native",
                "http.proxy": "http://127.0.0.1:8118",
                "http.proxySupport": "override",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    backup = tmp_path / "cursor-proxy-backup.json"
    argv = tmp_path / "argv.json"
    monkeypatch.setattr("torification.cursor_proxy._backup_path", lambda: backup)
    monkeypatch.setattr("torification.cursor_proxy.DEFAULT_ARGV", argv)

    st = apply_cursor_proxy(settings_file=settings)
    assert st.applied
    data = json.loads(settings.read_text(encoding="utf-8"))
    assert data["http.proxy"] == TOR_PROXY_URL
    assert data["window.titleBarStyle"] == "native"
    assert json.loads(argv.read_text(encoding="utf-8"))["proxy-server"].startswith("socks5://")
    assert cursor_proxy_status(settings).applied

    restore_cursor_proxy(settings_file=settings)
    restored = json.loads(settings.read_text(encoding="utf-8"))
    assert restored["http.proxy"] == "http://127.0.0.1:8118"
    assert restored["window.titleBarStyle"] == "native"
    assert not cursor_proxy_status(settings).applied
