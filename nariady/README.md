# Заготовки нарядов (backlog)

**Источник истины это GitHub issues.** Наряд исполняется только тогда, когда он заведён аудитором как issue по шаблону методологии (цель, факт, запреты, перед началом, блоки задач, smoke-test, отчёт, чек-лист). Файлы в этом каталоге это заготовки: черновые описания будущих нарядов. Они не исполняются.

Порядок, статусы и шаги владельца ведёт диспатч: https://github.com/ShkodnikAI/NetAtlas/issues/2

Следующая заготовка превращается в issue после приёмки предыдущего наряда волны. При переносе аудитор переписывает её на проверенных фактах (файл:строка, вывод команды) и разбивает на атомарные задачи с проверками.

## Процесс (кратко)

Наряд → ветка → PR на зелёном CI → отчёт в issue → приёмка аудитором → smoke владельца. Сдано (мерж на зелёном CI) не означает принято (вердикт аудитора по коду и проду). Полный текст методологии у владельца.

## Классификация риска

| Риск | Что затрагивает |
|---|---|
| low | Документы, макеты, структура репозитория, CI |
| medium | Сканер, хранилище, правила, веб-интерфейс, измерения, чтение данных |
| high | Агент, авторизация, PKI и подписи, конвейер скриптов, сбор активности, отчёты для ИИ |

Любой наряд, затрагивающий неприкасаемую зону, считается high и требует явного подтверждения владельца.

## Неприкасаемые зоны

Менять можно только нарядом, который владеет зоной:

- `server/audit/`: журнал аудита (только добавление, без удаления и правки записей)
- `pipeline/gate/`: проверка статуса «протестирован» и подписи перед отправкой задания
- `agent/verify/`: проверка подписи задания на агенте
- `pki/` (код); закрытые ключи и сертификаты в репозиторий не попадают никогда
- `docs/DECISIONS.md`: инварианты

## Антипаттерны

- Выполнение действий на компьютерах без подписи и подтверждения
- Доступ ИИ-модуля к сети, агентам, ключам или репозиторию скриптов
- Секреты, токены и пароли в коде, логах, отчётах, issues и PR
- Сбор нажатий клавиш, содержимого переписки и скриншотов
- Мерж на красном CI, прямой push в `main`, force push
- Журнал аудита с возможностью удаления
- Сканирование за пределами заданных подсетей

## Индекс

| Наряд | Название | Риск | Статус |
|---|---|---|---|
| NR-001 | Скелет проекта и CI | low | принято, [#1](https://github.com/ShkodnikAI/NetAtlas/issues/1) |
| NR-002 | Основа сканера: модель, границы безопасности, ARP-таблица | medium | принято, [#6](https://github.com/ShkodnikAI/NetAtlas/issues/6) |
| NR-014 | Ping-sweep и имена | medium | принято, [#10](https://github.com/ShkodnikAI/NetAtlas/issues/10) |
| NR-018 | Запросы имён через Limiter | medium | принято, [#12](https://github.com/ShkodnikAI/NetAtlas/issues/12) |
| NR-015 | SNMP-сборщик (только чтение) | medium | принято, [#15](https://github.com/ShkodnikAI/NetAtlas/issues/15) |
| NR-020 | Тест CLI без сети | low | принято, [#17](https://github.com/ShkodnikAI/NetAtlas/issues/17) |
| NR-019 | Граф топологии | medium | принято, [#19](https://github.com/ShkodnikAI/NetAtlas/issues/19) |
| NR-016 | DHCP-аренды, Wi‑Fi, производитель по MAC | medium | принято, [#21](https://github.com/ShkodnikAI/NetAtlas/issues/21) |
| NR-021 | Точность топологии без LLDP | medium | в работе, [#23](https://github.com/ShkodnikAI/NetAtlas/issues/23) |
| NR-003 | Хранилище и журнал аудита | high | в очереди, [#24](https://github.com/ShkodnikAI/NetAtlas/issues/24) |
| NR-004 | Сервер и API карты сети | medium | в очереди, [#25](https://github.com/ShkodnikAI/NetAtlas/issues/25) |
| NR-022 | Веб-интерфейс «Карта сети» | medium | в очереди, [#26](https://github.com/ShkodnikAI/NetAtlas/issues/26) |
| NR-005 | Мастер сканирования и «Найденные устройства» | medium | в очереди, [#27](https://github.com/ShkodnikAI/NetAtlas/issues/27) |
| NR-023 | Хвосты волны 1 | medium | в работе, [#34](https://github.com/ShkodnikAI/NetAtlas/issues/34) |
| NR-007 | Центр сертификации и подпись заданий | high | в очереди, [#35](https://github.com/ShkodnikAI/NetAtlas/issues/35) |
| NR-024 | Агентский API сервера | high | в очереди, [#36](https://github.com/ShkodnikAI/NetAtlas/issues/36) |
| NR-006 | Агент Windows: инвентарь | high | в очереди, [#37](https://github.com/ShkodnikAI/NetAtlas/issues/37) |
| NR-009 | Правила, «Компьютеры» и «Диски» | medium | в очереди, [#38](https://github.com/ShkodnikAI/NetAtlas/issues/38) |
| NR-008 | Качество сети | medium | в очереди, [#39](https://github.com/ShkodnikAI/NetAtlas/issues/39) |
| NR-010 | Аудит безопасности | medium | в очереди, [#40](https://github.com/ShkodnikAI/NetAtlas/issues/40) |
| NR-011 | Конвейер скриптов и шлюз | high | в очереди, [#41](https://github.com/ShkodnikAI/NetAtlas/issues/41) |
| NR-025 | Исполнение заданий на агенте | high | в очереди, [#42](https://github.com/ShkodnikAI/NetAtlas/issues/42) |
| NR-026 | Стенд Hyper-V | medium | в очереди, [#43](https://github.com/ShkodnikAI/NetAtlas/issues/43) |
| NR-012 | Активность сотрудников | high | в очереди, [#44](https://github.com/ShkodnikAI/NetAtlas/issues/44) |
| NR-013 | Отчёты для ИИ | high | в очереди, [#45](https://github.com/ShkodnikAI/NetAtlas/issues/45) |
