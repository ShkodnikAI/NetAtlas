-- Миграция 17 (NR-033 п.4): отложенные сигналы внимания.
-- «Игнорировать на N дней» прячет сигнал устройства данного вида
-- до указанного срока; по истечении срока сигнал снова виден.
-- Решение владельца фиксируется в журнале аудита вызывающим кодом.
CREATE TABLE signal_snoozes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id  TEXT NOT NULL,
    kind       TEXT NOT NULL,
    until      TEXT NOT NULL,             -- RFC3339, до какого времени сигнал скрыт
    created_at TEXT NOT NULL,
    actor      TEXT NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX idx_signal_snoozes_pair ON signal_snoozes(device_id, kind);
