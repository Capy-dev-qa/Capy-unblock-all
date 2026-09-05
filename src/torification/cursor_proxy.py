"""Route Cursor IDE through torification. Cursor ignores PAC; it honours http.proxy."""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

PROXY_KEYS = (
    "http.proxy",
    "http.proxySupport",
    "http.noProxy",
    "cursor.general.disableHttp2",
)

DEFAULT_SETTINGS = Path.home() / ".config/Cursor/User/settings.json"
DEFAULT_ARGV = Path.home() / ".config/Cursor/argv.json"
DEFAULT_BACKUP = Path.home() / ".local/state/torification/cursor-proxy-backup.json"
TOR_PROXY_URL = "http://127.0.0.1:18768"


@dataclass(frozen=True)
class CursorProxyState:
    applied: bool
    settings_file: Path
    proxy: str
    message: str = ""


def _missing_comma_fix(text: str) -> str:
    return re.sub(
        r'(true|false|null|-?\d+(?:\.\d+)?|"(?:[^"\\]|\\.)*")\s*\n(\s*")',
        r"\1,\n\2",
        text,
    )


def load_json_object(path: Path) -> dict:
    if not path.is_file():
        return {}
    text = path.read_text(encoding="utf-8")
    for candidate in (text, _missing_comma_fix(text)):
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if isinstance(data, dict):
            return data
    return {}


def _atomic_write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.replace(path)


def _backup_path() -> Path:
    try:
        from torification.config import load_config, state_dir

        return state_dir(load_config()) / "cursor-proxy-backup.json"
    except Exception:
        DEFAULT_BACKUP.parent.mkdir(parents=True, exist_ok=True)
        return DEFAULT_BACKUP


def desired_settings(listen_url: str = TOR_PROXY_URL) -> dict[str, object]:
    return {
        "http.proxy": listen_url,
        "http.proxySupport": "override",
        "http.noProxy": "localhost,127.0.0.1,::1",
        "cursor.general.disableHttp2": True,
    }


def apply_cursor_proxy(
    settings_file: Path | None = None,
    listen_url: str = TOR_PROXY_URL,
    proxy_server: str = "socks5://127.0.0.1:9054",
) -> CursorProxyState:
    path = settings_file or DEFAULT_SETTINGS
    data = load_json_object(path)
    backup_file = _backup_path()
    if str(data.get("http.proxy") or "") != listen_url:
        snapshot = {k: data[k] for k in PROXY_KEYS if k in data}
        snapshot["_had_file"] = path.is_file()
        snapshot["_settings_file"] = str(path)
        if path.is_file():
            try:
                shutil.copy2(path, backup_file.with_name("cursor-settings.json.bak"))
            except OSError:
                pass
        _atomic_write_json(backup_file, snapshot)
    data.update(desired_settings(listen_url))
    _atomic_write_json(path, data)
    argv = load_json_object(DEFAULT_ARGV)
    argv["proxy-server"] = proxy_server
    _atomic_write_json(DEFAULT_ARGV, argv)
    return CursorProxyState(True, path, listen_url, "Cursor http.proxy → Tor")


def restore_cursor_proxy(settings_file: Path | None = None) -> CursorProxyState:
    path = settings_file or DEFAULT_SETTINGS
    backup_file = _backup_path()
    data = load_json_object(path)
    snapshot: dict = {}
    if backup_file.is_file():
        try:
            loaded = json.loads(backup_file.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                snapshot = loaded
        except json.JSONDecodeError:
            snapshot = {}
    if snapshot.get("_settings_file") and not settings_file:
        path = Path(str(snapshot["_settings_file"]))
        data = load_json_object(path)
    for key in PROXY_KEYS:
        if key in snapshot:
            data[key] = snapshot[key]
        else:
            data.pop(key, None)
    if data:
        _atomic_write_json(path, data)
    argv = load_json_object(DEFAULT_ARGV)
    if "proxy-server" in argv:
        del argv["proxy-server"]
        if argv:
            _atomic_write_json(DEFAULT_ARGV, argv)
        else:
            try:
                DEFAULT_ARGV.unlink()
            except OSError:
                pass
    try:
        backup_file.unlink()
    except OSError:
        pass
    return CursorProxyState(False, path, str(data.get("http.proxy") or ""), "Cursor proxy restored")


def cursor_proxy_status(settings_file: Path | None = None) -> CursorProxyState:
    path = settings_file or DEFAULT_SETTINGS
    data = load_json_object(path)
    proxy = str(data.get("http.proxy") or "")
    applied = proxy == TOR_PROXY_URL
    msg = "Cursor → Tor" if applied else (f"Cursor proxy: {proxy}" if proxy else "Cursor: без torification")
    return CursorProxyState(applied, path, proxy, msg)
