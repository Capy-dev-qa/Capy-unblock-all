# Torification

Browser-agnostic система адаптивной маршрутизации: для каждого открытого сайта проверяет **TCP-handshake** (SYN → SYN-ACK → ACK + TLS на :443), при блокировке запускает **гонку мостов** (как `ytmusic-fix`) и добавляет хост в динамический PAC.

Работает с **любым браузером** через один PAC URL — Chrome, Firefox, Edge, Brave, Opera.

## Архитектура

```
Браузер (любой) ──PAC──► proxy.pac
       │
       ├── DIRECT (доступен)
       └── SOCKS5 :9054 (заблокирован → auto-torified)

torificationd
  ├── connection_watcher  — ss + History SQLite (browser-agnostic)
  ├── tcp_probe           — connect/TLS, не ICMP
  ├── bridge_race         — параллельная гонка мостов
  ├── pac_generator       — динамический PAC
  ├── torification-ignore — белый список «не трогать»
  └── ml/classifier       — опционально: классификатор блокировок
```

## Быстрый старт

```bash
cd ~/projects/torification
chmod +x install.sh
./install.sh

# В браузере укажи PAC:
# http://127.0.0.1:18767/proxy.pac

systemctl --user enable --now torification-tor torification-pac torification
```

## torification-ignore

Файл `~/.config/torification/torification-ignore` — сайты, с которыми daemon **вообще не взаимодействует**:

| Формат | Пример |
|--------|--------|
| Точный host | `discord.com` |
| Поддомены | `.google.com` |
| CIDR | `192.168.0.0/16` |
| Glob | `*localhost*` |

Discord, локальные сети и GCS уже добавлены по умолчанию.

## TCP-проверка

Не ping/ICMP — полный TCP:

1. DNS resolve
2. `connect()` → SYN / SYN-ACK / ACK
3. TLS handshake на :443
4. При 2 неудачах подряд → probe через Tor → при неудаче **гонка мостов**

```bash
torification probe example.com
torification race blocked-site.com
```

## UDP — варианты

Tor **не проксирует произвольный UDP**. Политика в `udp-policy.toml`:

| Режим | Когда использовать |
|-------|-------------------|
| **direct** | Обычный трафик, часто вместе с zapret на системе |
| **drop** | WebRTC/QUIC в браузере (`--disable-quic`, `disable_non_proxied_udp`) |
| **zapret** | Discord voice, игры (UDP 19294–19344, 50000–50100) — nfqws/winws |
| **socks5** | Приложения с SOCKS5 UDP ASSOCIATE (не браузеры) |
| **tproxy** | Прозрачный прокси + badvpn-udpgw для VoIP/desktop |

Рекомендуемая связка для вашей системы:

- **TCP заблокирован** → torification (Tor bridges)
- **UDP заблокирован (Discord)** → zapret (уже есть `zapret-discord-youtube-linux`)
- **Браузер QUIC/WebRTC** → drop через флаги Chrome/Firefox

## ML-классификатор

1. Daemon собирает события в `~/.local/state/torification/training/events.jsonl`
2. Разметка: `blocked` / `ok` (авто + ручная правка)
3. Обучение:

```bash
pip install -e ".[ml]"
torification train --input ~/.local/state/torification/training/events.jsonl
```

4. Включить в `torification.toml`: `[ml] enabled = true`

Эвристики работают без ML; модель добавляет устойчивость к «мягким» блокировкам (throttling, captcha, пустые RST).

## Интеграция с chrome-split-proxy

Можно постепенно мигрировать: статические правила из `~/.local/share/chrome-split-proxy/proxy.pac` копируются в `config/static-rules.pac`. Динамические хосты добавляет daemon.

## Связь с ytmusic-fix

| ytmusic-fix | torification |
|-------------|--------------|
| Только music.youtube.com | Любой host из браузера |
| Проверка HTML «not available…» | TCP + TLS + ML |
| Крутит ExitNodes | Гонка **мостов** + ExitNodes |
| Только Chrome PAC | Любой браузер с PAC |
