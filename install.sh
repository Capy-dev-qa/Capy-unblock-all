#!/usr/bin/env bash
# Install torification to ~/.config/torification
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
CFG="$HOME/.config/torification"
STATE="$HOME/.local/state/torification"

install -d -m 700 "$CFG" "$STATE" "$CFG/tor-data"

for f in torification.toml.example torification-ignore udp-policy.toml.example static-rules.pac; do
  src="$REPO/config/${f}"
  dst_name="${f%.example}"
  dst="$CFG/$dst_name"
  if [[ ! -f "$dst" ]]; then
    cp "$src" "$dst"
    echo "Installed $dst"
  else
    echo "Keep existing $dst"
  fi
done

# torrc from tor-us if present
if [[ ! -f "$CFG/torrc" ]]; then
  if [[ -f "$HOME/.config/tor-us/torrc" ]]; then
    sed "s|/tor-us/|/torification/|g; s|:9052|:9054|g; s|:9053|:9055|g" \
      "$HOME/.config/tor-us/torrc" > "$CFG/torrc"
  else
    cp "$REPO/config/torrc.example" "$CFG/torrc"
  fi
  echo "Installed $CFG/torrc"
fi

# Python: только venv (PEP 668 — system pip недоступен)
if [[ ! -d "$REPO/.venv" ]]; then
  python3 -m venv "$REPO/.venv"
fi
"$REPO/.venv/bin/pip" install -e "$REPO" -q
ln -sf "$REPO/.venv/bin/torification" "$HOME/.local/bin/torification"
ln -sf "$REPO/.venv/bin/torificationd" "$HOME/.local/bin/torificationd"
chmod +x "$REPO/scripts/chrome-torification"
ln -sf "$REPO/scripts/chrome-torification" "$HOME/.local/bin/chrome-torification"

mkdir -p "$HOME/.config/systemd/user"
cp "$REPO/systemd/"*.service "$HOME/.config/systemd/user/"
systemctl --user daemon-reload
systemctl --user enable torification-tor torification-pac torification 2>/dev/null || true

echo ""
echo "=== Автозапуск (один раз) ==="
echo "  systemctl --user enable --now torification-tor torification-pac torification"
echo "  sudo systemctl enable tor   # Telegram/OpenAI fallback :9050"
echo "=== Browser setup (any browser) ==="
echo "PAC URL: http://127.0.0.1:18767/proxy.pac"
echo ""
echo "Chrome:  Settings → System → Open proxy → Automatic / PAC"
echo "Firefox: Settings → Network → Automatic proxy configuration URL"
echo ""
echo "Start:   systemctl --user enable --now torification-pac torification-tor torification"
echo "Chrome:  chrome-torification https://example.com"
echo "         (GUI proxy в Chrome на Linux Mint не работает — только флаг --proxy-pac-url)"
echo "Ignore:  edit $CFG/torification-ignore"
