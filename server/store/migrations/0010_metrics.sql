-- Миграция 10 (NR-008): метрики качества сети. Сырые значения
-- (48 часов), 5-минутные агрегаты (30 суток), часовые (1 год).
-- kind: latency | loss | dns | tcp | down_mbps | up_mbps |
-- bufferbloat | port_util | port_errors | port_discards.
CREATE TABLE metrics_raw (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_id TEXT NOT NULL,
    target   TEXT NOT NULL,
    kind     TEXT NOT NULL,
    value    REAL NOT NULL,
    at       TEXT NOT NULL
);

CREATE INDEX idx_metrics_raw ON metrics_raw(agent_id, target, kind, at);

CREATE TABLE metrics_agg_5m (
    agent_id   TEXT NOT NULL,
    target     TEXT NOT NULL,
    kind       TEXT NOT NULL,
    window     TEXT NOT NULL,          -- YYYY-MM-DDTHH:MM UTC
    avg        REAL NOT NULL,
    p95        REAL NOT NULL,
    max        REAL NOT NULL,
    loss_count INTEGER NOT NULL DEFAULT 0,
    n          INTEGER NOT NULL DEFAULT 1, -- точек в окне (для слияния)
    PRIMARY KEY (agent_id, target, kind, window)
);

CREATE TABLE metrics_agg_1h (
    agent_id   TEXT NOT NULL,
    target     TEXT NOT NULL,
    kind       TEXT NOT NULL,
    window     TEXT NOT NULL,          -- YYYY-MM-DDTHH UTC
    avg        REAL NOT NULL,
    p95        REAL NOT NULL,
    max        REAL NOT NULL,
    loss_count INTEGER NOT NULL DEFAULT 0,
    n          INTEGER NOT NULL DEFAULT 1, -- окон в часе (для слияния)
    PRIMARY KEY (agent_id, target, kind, window)
);

CREATE INDEX idx_metrics_agg_5m ON metrics_agg_5m(target, kind, window);
CREATE INDEX idx_metrics_agg_1h ON metrics_agg_1h(target, kind, window);
