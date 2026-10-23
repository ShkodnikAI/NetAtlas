-- Миграция 1: базовая схема NR-003 — устройства, имена, IP,
-- наблюдения, связи, сканы и журнал аудита. Триггеры append-only для
-- журнала — отдельными миграциями (2 и 3), чтобы каждый файл был
-- одним statement.
CREATE TABLE IF NOT EXISTS schema_version (
    version    INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE devices (
    id         TEXT PRIMARY KEY NOT NULL,          -- MAC или manual:<uuid>
    kind       TEXT NOT NULL DEFAULT 'device',     -- model.NodeKind
    class      TEXT NOT NULL DEFAULT 'unknown',    -- model.Class
    label      TEXT NOT NULL DEFAULT '',           -- ручное имя
    hostname   TEXT NOT NULL DEFAULT '',
    vendor     TEXT NOT NULL DEFAULT '',
    ssid       TEXT NOT NULL DEFAULT '',
    manual     INTEGER NOT NULL DEFAULT 0,
    verified   INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL,
    last_seen  TEXT NOT NULL,
    CHECK (class IN ('managed', 'known_no_agent', 'guest', 'unknown')),
    CHECK (kind IN ('device', 'switch', 'cloud', 'unknown')),
    CHECK (manual IN (0, 1)),
    CHECK (verified IN (0, 1))
);

CREATE TABLE device_ips (
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    ip        TEXT NOT NULL,
    PRIMARY KEY (device_id, ip)
);

CREATE TABLE device_names (
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    source    TEXT NOT NULL,
    name      TEXT NOT NULL,
    seen      TEXT NOT NULL,
    PRIMARY KEY (device_id, source, name)
);

CREATE TABLE observations (
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    source    TEXT NOT NULL,
    seen      TEXT NOT NULL,
    PRIMARY KEY (device_id, source)
);

CREATE TABLE links (
    id       TEXT PRIMARY KEY NOT NULL,             -- SHA-256 концов или manual:<uuid>
    a        TEXT NOT NULL,
    a_port   TEXT NOT NULL DEFAULT '',
    b        TEXT NOT NULL,
    b_port   TEXT NOT NULL DEFAULT '',
    source   TEXT NOT NULL,                          -- lldp | fdb | inferred | manual
    manual   INTEGER NOT NULL DEFAULT 0,
    verified INTEGER NOT NULL DEFAULT 0,
    UNIQUE (a, a_port, b, b_port),
    CHECK (manual IN (0, 1)),
    CHECK (verified IN (0, 1))
);

CREATE INDEX idx_links_a ON links(a);
CREATE INDEX idx_links_b ON links(b);

CREATE TABLE scans (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    started  TEXT NOT NULL,
    finished TEXT NOT NULL,
    subnets  TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE audit_log (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    actor     TEXT NOT NULL,
    action    TEXT NOT NULL,
    target    TEXT NOT NULL,
    result    TEXT NOT NULL,
    detail    TEXT NOT NULL DEFAULT '',
    prev_hash TEXT NOT NULL,
    hash      TEXT NOT NULL
);
