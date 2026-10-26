-- nontransactional
-- Миграция 16 (NR-032): типы phone/iot/tv, автоматический тип
-- (kind_auto) с ручным перекрытием (kind_manual) и таблица позиций
-- узлов карты, сдвинутых владельцем. SQLite не умеет менять
-- ограничение CHECK на месте, поэтому devices пересоздаётся — тот же
-- приём, что в миграции 4; шаги повторяемы: сбой до DROP оставляет
-- devices целой, сбой между DROP и RENAME восстанавливается из
-- резервной копии (см. docs/BACKUP.md, версия 16).
PRAGMA foreign_keys = OFF;
DROP TABLE IF EXISTS devices_new;
CREATE TABLE devices_new (
    id          TEXT PRIMARY KEY NOT NULL,
    kind        TEXT NOT NULL DEFAULT 'device',
    kind_auto   TEXT NOT NULL DEFAULT '',
    kind_manual INTEGER NOT NULL DEFAULT 0,
    class       TEXT NOT NULL DEFAULT 'unknown',
    label       TEXT NOT NULL DEFAULT '',
    hostname    TEXT NOT NULL DEFAULT '',
    vendor      TEXT NOT NULL DEFAULT '',
    ssid        TEXT NOT NULL DEFAULT '',
    manual      INTEGER NOT NULL DEFAULT 0,
    verified    INTEGER NOT NULL DEFAULT 0,
    first_seen  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    CHECK (class IN ('managed', 'known_no_agent', 'guest', 'unknown')),
    CHECK (kind IN ('device', 'switch', 'cloud', 'unknown', 'internet',
                    'router', 'ap', 'server', 'laptop', 'printer',
                    'phone', 'iot', 'tv', 'host')),
    CHECK (kind_manual IN (0, 1)),
    CHECK (manual IN (0, 1)),
    CHECK (verified IN (0, 1))
);
INSERT INTO devices_new
    (id, kind, class, label, hostname, vendor, ssid, manual, verified, first_seen, last_seen)
SELECT id, kind, class, label, hostname, vendor, ssid, manual, verified, first_seen, last_seen
FROM devices;
DROP TABLE devices;
ALTER TABLE devices_new RENAME TO devices;
PRAGMA foreign_keys = ON;

-- Позиции узлов, сдвинутых владельцем (NR-032 п.4): детерминированная
-- раскладка их не трогает; кнопка «Выстроить сеткой» очищает таблицу.
CREATE TABLE IF NOT EXISTS node_positions (
    node_id    TEXT PRIMARY KEY REFERENCES devices(id) ON DELETE CASCADE,
    x          REAL NOT NULL,
    y          REAL NOT NULL,
    updated_at TEXT NOT NULL
);

-- Шлюзы по умолчанию, известные на момент скана (NR-032 п.2):
-- предполагаемые связи строятся при отдаче карты по последнему скану.
ALTER TABLE scans ADD COLUMN gateways TEXT NOT NULL DEFAULT '[]';
PRAGMA foreign_key_check;
