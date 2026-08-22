# Формат обучающих данных для ML-классификатора блокировок

Каждая строка — JSON object (JSONL):

```json
{
  "features": {
    "host": "example.com",
    "port": 443,
    "latency_ms": 5023.1,
    "state_onehot_timeout": 1,
    "state_onehot_refused": 0,
    "state_onehot_unreachable": 0,
    "state_onehot_tls_error": 0,
    "state_onehot_ok": 0,
    "direct_failed": 1,
    "socks_ok": 1,
    "socks_latency_ms": 890.2,
    "retry_count": 2,
    "hour_of_day": 14
  },
  "label": "blocked",
  "extra": {"direct": "timeout", "socks": "ok"}
}
```

## Метки

- `blocked` — сайт недоступен напрямую, через Tor работает → torify
- `ok` — доступен напрямую → DIRECT
- `false_positive` — можно использовать для hard-negative (ручная правка)

## Минимум для обучения

20+ размеченных samples. Рекомендуется 200+ с разными ISP/временем суток.

## Сбор

Daemon пишет в `training/events.jsonl` при `[ml] enabled = true`.
Пока ML выключен — можно собирать вручную через `torification probe` + разметку.
