"""Load torification.toml (stdlib tomllib or tomli fallback)."""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any


def _expand(path: str) -> str:
    return os.path.expanduser(path)


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    cfg_path = Path(path or os.environ.get("TORIFICATION_CONFIG", "~/.config/torification/torification.toml"))
    cfg_path = cfg_path.expanduser()
    if not cfg_path.is_file():
        raise FileNotFoundError(f"Config not found: {cfg_path} (copy from config/torification.toml.example)")

    raw = cfg_path.read_bytes()
    if sys.version_info >= (3, 11):
        import tomllib

        data = tomllib.loads(raw.decode())
    else:
        import tomli

        data = tomli.loads(raw.decode())

    for section in data.values():
        if isinstance(section, dict):
            for k, v in section.items():
                if isinstance(v, str) and v.startswith("~"):
                    section[k] = _expand(v)
    return data


def state_dir(cfg: dict[str, Any]) -> Path:
    p = Path(cfg["general"]["state_dir"]).expanduser()
    p.mkdir(parents=True, exist_ok=True)
    os.chmod(p, 0o700)
    return p
