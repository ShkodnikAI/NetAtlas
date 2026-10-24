-- Миграция 8 (NR-024): агенты и их инвентарь. Токены регистрации
-- заведены миграцией 7 (enroll_tokens из NR-007), поэтому агенты —
-- версия 8 (в наряде пункт назывался «версией 7»: отклонение
-- зафиксировано в PR #49).
CREATE TABLE agents (
    id          TEXT PRIMARY KEY NOT NULL,   -- CN сертификата: agent:<uuid>
    hostname    TEXT NOT NULL DEFAULT '',
    enrolled_at TEXT NOT NULL,
    last_seen   TEXT NOT NULL DEFAULT '',
    cert_serial TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
    mac_list    TEXT NOT NULL DEFAULT '[]'   -- JSON-массив MAC
);

CREATE INDEX idx_agents_status ON agents(status);

CREATE TABLE agent_inventory (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id     TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    collected_at TEXT NOT NULL,
    kind         TEXT NOT NULL,
    json         TEXT NOT NULL,
    schema_ver   INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX idx_inventory_agent ON agent_inventory(agent_id);
