-- Миграция 5 (NR-005): оповещения о новых неизвестных устройствах.
-- Открытое оповещение одно на устройство (частичный уникальный
-- индекс); повторное сканирование не создаёт второе, смена класса
-- устройства или разбор владельцем закрывают оповещение.
CREATE TABLE alerts (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    created   TEXT NOT NULL,
    closed    TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_alerts_open ON alerts(device_id) WHERE closed = '';
CREATE INDEX IF NOT EXISTS idx_alerts_device ON alerts(device_id);
