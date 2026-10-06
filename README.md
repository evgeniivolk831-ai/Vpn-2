# GlobalPulse Subscription

Автоматически собираем VLESS-конфигурации из нескольких публичных источников, проверяем доступность TCP, ранжируем по задержке и публикуем одну общую подписку из 15 живых узлов.

## Что публикуется

- `output/GlobalPulse-Subscription.txt` — **единая подписка**: 15 VLESS URI.
- `output/GlobalPulse-Base64.txt` — Base64-вариант той же подписки.
- `output/GlobalPulse-AUTO.yaml` — Clash Meta-совместимая конфигурация с группой AUTO/url-test.
- `output/GlobalPulse-NORMAL.txt` — узлы с обычным TLS/transport.
- `output/GlobalPulse-RESILIENT.txt` — VLESS/Reality и другие конфигурации, классифицированные как более устойчивые к фильтрации.
- `output/stats.json` — статистика последнего обновления.

## Логика

1. Загружаются несколько публичных источников.
2. VLESS URI извлекаются из обычного текста или Base64.
3. Дубликаты удаляются.
4. Узлы делятся на NORMAL и RESILIENT по параметрам URI.
5. Выполняется TCP-проверка endpoint.
6. Живые узлы ранжируются по задержке.
7. Сначала выбираются до 10 RESILIENT и до 5 NORMAL, затем список добирается лучшими живыми узлами до 15.
8. Если живых узлов меньше 15, публикация не заменяется — остаётся предыдущий успешный набор.

> Статус RESILIENT — это классификация конфигурации, а не гарантия обхода блокировок. Работоспособность зависит от сети, провайдера, региона и времени.

## Автообновление

GitHub Actions запускает сборку каждый час и также поддерживает ручной запуск через **Run workflow**.

## Источники

- mehrtat/vless-collector
- Baarcuda/vpn-configs
- VovaplusEXP/p-configs
- Au1rxx/free-vpn-subscriptions
- morpheusadam/v2ray-config


E2E verifier enabled: Xray-based tunnel validation is run by GitHub Actions before publication.
