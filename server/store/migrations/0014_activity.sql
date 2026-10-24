-- Миграция 14 (NR-012): активность сотрудников. Сбор по умолчанию
-- выключен: включение — запись с подтверждением владельца. Сырых
-- событий нет: только 5-минутные агрегаты от агентов.
CREATE TABLE activity_enabled (
    agent_id     TEXT PRIMARY KEY REFERENCES agents(id) ON DELETE CASCADE,
    confirmed_by TEXT NOT NULL,              -- актор подтверждения (owner)
    confirmed_at TEXT NOT NULL,
    note         TEXT NOT NULL DEFAULT ''    -- фиксация: сотрудники уведомлены
);

CREATE TABLE activity_reports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id      TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    account       TEXT NOT NULL,             -- учётная запись сотрудника
    window_start  TEXT NOT NULL,             -- начало 5-минутного окна (UTC)
    active_sec    INTEGER NOT NULL DEFAULT 0,
    idle_sec      INTEGER NOT NULL DEFAULT 0,
    apps          TEXT NOT NULL DEFAULT '{}', -- JSON {приложение: секунды}
    domains       TEXT NOT NULL DEFAULT '{}', -- JSON {домен: число запросов}
    collected_at  TEXT NOT NULL
);

CREATE INDEX idx_activity_agent_time ON activity_reports(agent_id, id);
CREATE INDEX idx_activity_collected ON activity_reports(collected_at);
