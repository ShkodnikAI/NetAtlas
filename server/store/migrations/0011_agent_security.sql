-- Миграция 11 (NR-010): отчёты проверок безопасности агентов.
-- Тело сохраняется как есть (конверт с results); журнал append-only.
CREATE TABLE agent_security (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id     TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    collected_at TEXT NOT NULL,
    schema_ver   INTEGER NOT NULL,
    json         TEXT NOT NULL
);

CREATE INDEX idx_agent_security_agent ON agent_security(agent_id, id);
