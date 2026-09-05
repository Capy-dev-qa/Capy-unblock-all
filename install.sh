#!/usr/bin/env bash
# Install torification. Works from any cwd: bash /path/to/install.sh
set -euo pipefail

REPO="$(cd "$(dirname "$0")" && pwd)"
CFG="$HOME/.config/torification"
STATE="$HOME/.local/state/torification"
LOCAL_BIN="$HOME/.local/bin"

if [[ ! -f "$REPO/pyproject.toml" || ! -d "$REPO/src/torification" ]]; then
  echo "install.sh must live in the torification directory (found: $REPO)" >&2
  echo "On Arch find it with:" >&2
  echo "  find /run/media /media /mnt /home -name install.sh 2>/dev/null | grep -i torif" >&2
  exit 1
fi

is_arch() { [[ -f /etc/arch-release ]]; }

find_bin() {
  local n
  for n in "$@"; do
    if command -v "$n" >/dev/null 2>&1; then
      command -v "$n"
      return 0
    fi
    for c in "/usr/bin/$n" "/usr/sbin/$n" "/usr/local/bin/$n"; do
      if [[ -x "$c" ]]; then
        echo "$c"
        return 0
      fi
    done
  done
  return 1
}

aur_hint() {
  echo ""
  echo "=== Arch: мосты Tor (AUR, не pacman) ==="
  echo "  obfs4proxy и snowflake НЕТ в официальных репах."
  echo "  sudo pacman -S --needed python python-pip python-gobject gtk3 tk tor libnotify git base-devel go"
  if command -v yay >/dev/null 2>&1; then
    echo "  yay -S --needed obfs4proxy snowflake-pt-client"
  elif command -v paru >/dev/null 2>&1; then
    echo "  paru -S --needed obfs4proxy snowflake-pt-client"
  else
    echo "  # yay нет — поставь AUR-пакеты так:"
    echo "  sudo pacman -S --needed base-devel git go"
    echo "  git clone https://aur.archlinux.org/obfs4proxy.git /tmp/obfs4proxy"
    echo "  (cd /tmp/obfs4proxy && makepkg -si --noconfirm)"
    echo "  git clone https://aur.archlinux.org/snowflake-pt-client.git /tmp/snowflake-pt-client"
    echo "  (cd /tmp/snowflake-pt-client && makepkg -si --noconfirm)"
  fi
  echo "  lyrebird тоже ок, если уже стоит (это новый obfs4proxy)."
}

comment_torrc() {
  local torrc="$1" pat="$2"
  sed -i -E "s/^($pat)/# \\1/" "$torrc"
}

uncomment_torrc() {
  local torrc="$1" pat="$2"
  sed -i -E "s/^#[[:space:]]*($pat)/\\1/" "$torrc"
}

patch_torrc_plugins() {
  local torrc="$1"
  [[ -f "$torrc" ]] || return 0
  local obfs snow
  obfs="$(find_bin lyrebird obfs4proxy || true)"
  snow="$(find_bin snowflake-client snowflake-pt-client snowflake || true)"
  if [[ -n "$obfs" ]]; then
    uncomment_torrc "$torrc" "ClientTransportPlugin obfs4 exec"
    uncomment_torrc "$torrc" "Bridge obfs4 "
    uncomment_torrc "$torrc" "UseBridges "
    sed -i -E "s|^(ClientTransportPlugin obfs4 exec)[[:space:]]+[^[:space:]]+|\\1 $obfs|" "$torrc"
    echo "obfs4 plugin: $obfs"
  else
    comment_torrc "$torrc" "ClientTransportPlugin obfs4 exec"
    comment_torrc "$torrc" "Bridge obfs4 "
    echo "WARNING: no lyrebird/obfs4proxy — obfs4 bridges disabled. Install AUR: yay -S obfs4proxy" >&2
  fi
  if [[ -n "$snow" ]]; then
    uncomment_torrc "$torrc" "ClientTransportPlugin snowflake exec"
    uncomment_torrc "$torrc" "Bridge snowflake "
    sed -i -E "s|^(ClientTransportPlugin snowflake exec)[[:space:]]+[^[:space:]]+|\\1 $snow|" "$torrc"
    echo "snowflake plugin: $snow"
  else
    comment_torrc "$torrc" "ClientTransportPlugin snowflake exec"
    comment_torrc "$torrc" "Bridge snowflake "
    echo "Note: snowflake-client not found — snowflake bridges disabled."
  fi
  if [[ -z "$obfs" && -z "$snow" ]]; then
    comment_torrc "$torrc" "UseBridges "
    echo "WARNING: no pluggable transports. Tor starts without bridges (may fail on censored ISP)." >&2
  fi
}

ensure_fish_path() {
  local conf="$HOME/.config/fish/conf.d/torification.fish"
  mkdir -p "$(dirname "$conf")"
  if [[ ! -f "$conf" ]] || ! grep -q 'local/bin' "$conf" 2>/dev/null; then
    printf 'fish_add_path -g %s\n' "$LOCAL_BIN" > "$conf"
    echo "fish PATH: $conf → $LOCAL_BIN"
  fi
}

install -d -m 700 "$CFG" "$STATE" "$CFG/tor-data" "$LOCAL_BIN"

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

if [[ ! -f "$CFG/torrc" ]]; then
  if [[ -f "$HOME/.config/tor-us/torrc" ]]; then
    sed "s|/tor-us/|/torification/|g; s|:9052|:9054|g; s|:9053|:9055|g" \
      "$HOME/.config/tor-us/torrc" > "$CFG/torrc"
  else
    sed "s|__HOME__|$HOME|g" "$REPO/config/torrc.example" > "$CFG/torrc"
  fi
  echo "Installed $CFG/torrc"
fi
patch_torrc_plugins "$CFG/torrc"

if [[ ! -d "$REPO/.venv" ]]; then
  python3 -m venv "$REPO/.venv"
fi
"$REPO/.venv/bin/pip" install -e "$REPO" -q
ln -sf "$REPO/.venv/bin/torification" "$LOCAL_BIN/torification"
ln -sf "$REPO/.venv/bin/torificationd" "$LOCAL_BIN/torificationd"
chmod +x "$REPO/scripts/chrome-torification" "$REPO/scripts/torification-gui.py"
ln -sf "$REPO/scripts/chrome-torification" "$LOCAL_BIN/chrome-torification"
ln -sf "$REPO/scripts/torification-gui.py" "$LOCAL_BIN/torification-gui"
ensure_fish_path

install -d "$HOME/.local/share/applications"
PY3="$(command -v python3 || echo /usr/bin/python3)"
sed -e "s|__TORIFICATION_ROOT__|$REPO|g" -e "s|/usr/bin/python3|$PY3|g" \
  "$REPO/scripts/torification-gui.desktop" \
  > "$HOME/.local/share/applications/torification-gui.desktop"
update-desktop-database "$HOME/.local/share/applications" 2>/dev/null || true

mkdir -p "$HOME/.config/systemd/user"
TOR_BIN="$(find_bin tor || true)"
TOR_BIN="${TOR_BIN:-/usr/bin/tor}"
for svc in "$REPO/systemd/"*.service; do
  sed -e "s|__TORIFICATION_ROOT__|$REPO|g" -e "s|__TOR_BIN__|$TOR_BIN|g" \
    "$svc" > "$HOME/.config/systemd/user/$(basename "$svc")"
done
systemctl --user daemon-reload 2>/dev/null || true
systemctl --user enable torification-tor torification-pac torification torification-cursor-proxy 2>/dev/null || true

if is_arch; then
  aur_hint
fi

echo ""
echo "=== Установлено из $REPO ==="
echo "  GUI:   $LOCAL_BIN/torification-gui     (не systemd-юнит!)"
echo "  Start: systemctl --user enable --now torification-tor torification-pac torification torification-cursor-proxy"
echo "  НЕ включай torification-gui через systemctl — это окно, не сервис."
echo "  fish:  exec fish    # подхватит ~/.local/bin"
echo "  Cursor при «Запустить» в GUI: http.proxy → :18768 → Tor :9054"
echo "  PAC:   http://127.0.0.1:18767/proxy.pac"
echo "  Ignore: $CFG/torification-ignore"
