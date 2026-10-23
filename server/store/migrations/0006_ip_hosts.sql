-- nontransactional
-- Миграция 6 (NR-023): хосты без MAC. CHECK колонки kind расширяется
-- значением 'host' (ID «ip:»+адрес — ответил на ping, но нет записи
-- ARP); SQLite не умеет менять ограничение на месте, поэтому таблица
-- пересоздаётся. Файл исполняется вне транзакции (PRAGMA
-- foreign_keys — no-op внутри транзакции); шаги повторяемы: сбой до
-- DROP оставляет devices целой, сбой между DROP и RENAME
-- восстанавливается из резервной копии (см. docs/BACKUP.md, версия 6).
PRAGMA foreign_keys = OFF;
DROP TABLE IF EXISTS devices_new;
CREATE TABLE devices_new (
    id         TEXT PRIMARY KEY NOT NULL,
    kind       TEXT NOT NULL DEFAULT 'device',
    class      TEXT NOT NULL DEFAULT 'unknown',
    label      TEXT NOT NULL DEFAULT '',
    hostname   TEXT NOT NULL DEFAULT '',
    vendor     TEXT NOT NULL DEFAULT '',
    ssid       TEXT NOT NULL DEFAULT '',
    manual     INTEGER NOT NULL DEFAULT 0,
    verified   INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    CHECK (class IN ('managed', 'known_no_agent', 'guest', 'unknown')),
    CHECK (kind IN ('device', 'switch', 'cloud', 'unknown', 'internet',
                    'router', 'ap', 'server', 'laptop', 'printer', 'host')),
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
PRAGMA foreign_key_check;
