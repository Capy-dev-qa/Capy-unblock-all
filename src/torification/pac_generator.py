"""Generate browser-agnostic PAC from static rules + dynamic torified hosts."""

from __future__ import annotations

import json
from pathlib import Path


PAC_HEADER = """function FindProxyForURL(url, host) {
    if (!host) return "DIRECT";
    host = host.toLowerCase();

    // --- torification dynamic (auto-torified blocked hosts) ---
"""

PAC_FOOTER = """
    // --- static fallback: everything else DIRECT ---
    return "DIRECT";
}
"""


def load_torified(state_file: Path) -> dict[str, dict]:
    if not state_file.is_file():
        return {}
    try:
        return json.loads(state_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def save_torified(state_file: Path, data: dict[str, dict]) -> None:
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def generate_pac(
    torified: dict[str, dict],
    socks_host: str,
    socks_port: int,
    static_pac_path: Path | None = None,
) -> str:
    dynamic_lines: list[str] = []
    for host, meta in sorted(torified.items()):
        h = host.lower().replace('"', "").replace("\\", "")
        if not h:
            continue
        port = int(meta.get("port", socks_port)) if isinstance(meta, dict) else socks_port
        dynamic_lines.append(
            f'    if (host === "{h}" || dnsDomainIs(host, ".{h}")) {{\n'
            f'        return "SOCKS5 {socks_host}:{port}";\n'
            f"    }}"
        )
    dynamic_block = "\n".join(dynamic_lines)

    if static_pac_path and static_pac_path.is_file():
        static = static_pac_path.read_text(encoding="utf-8")
        # inject dynamic block before final return DIRECT
        marker = "return \"DIRECT\";"
        idx = static.rfind(marker)
        if idx != -1:
            return static[:idx] + dynamic_block + "\n    " + static[idx:]
    return PAC_HEADER + dynamic_block + PAC_FOOTER


def write_pac(output: Path, content: str) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(content, encoding="utf-8")
