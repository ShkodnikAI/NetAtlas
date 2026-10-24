-- Миграция 9 (NR-009): дневные точки истории занятого места по
-- томам — вход прогноза заполнения (rules/forecast.go). Одна точка
-- на агент/том/день: последний отчёт дня побеждает (upsert).
CREATE TABLE disk_history (
    agent_id       TEXT NOT NULL,
    drive          TEXT NOT NULL,
    day            TEXT NOT NULL,           -- YYYY-MM-DD UTC
    used_bytes     INTEGER NOT NULL,
    capacity_bytes INTEGER NOT NULL,
    PRIMARY KEY (agent_id, drive, day)
);

CREATE INDEX idx_disk_history_agent ON disk_history(agent_id);
