-- Миграция 12 (NR-011): репозиторий скриптов, проверки, подписи
-- владельца, задания и цели. Содержимое скриптов хранится как есть;
-- подписи привязаны к хэшу содержимого версии.
CREATE TABLE scripts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    kind        TEXT NOT NULL CHECK (kind IN ('catalog', 'script')),
    category    TEXT NOT NULL DEFAULT 'general' CHECK (category IN ('general', 'driver', 'nic')),
    catalog_key TEXT NOT NULL DEFAULT '',
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);

CREATE TABLE script_versions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    script_id  INTEGER NOT NULL REFERENCES scripts(id) ON DELETE CASCADE,
    version    INTEGER NOT NULL,
    status     TEXT NOT NULL DEFAULT 'draft'
               CHECK (status IN ('draft', 'checked', 'tested', 'signed', 'pilot', 'released', 'rejected')),
    content    TEXT NOT NULL,
    sha256     TEXT NOT NULL,
    params     TEXT NOT NULL DEFAULT '{}',   -- JSON-карта параметров (для kind=catalog)
    pilot_ok   INTEGER NOT NULL DEFAULT 0,   -- пилот на одном ПК пройден (для driver|nic)
    created_at TEXT NOT NULL,
    UNIQUE (script_id, version)
);

CREATE INDEX idx_script_versions_script ON script_versions(script_id, version);

-- Результаты проверок и тестов: статпроверка (server/stand/manual)
-- и тест на ВМ со стенда Hyper-V (NR-026).
CREATE TABLE test_runs (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    script_version_id INTEGER NOT NULL REFERENCES script_versions(id) ON DELETE CASCADE,
    kind              TEXT NOT NULL CHECK (kind IN ('static', 'vm')),
    source            TEXT NOT NULL CHECK (source IN ('stand', 'server', 'manual')),
    result            TEXT NOT NULL CHECK (result IN ('pass', 'fail')),
    detail            TEXT NOT NULL DEFAULT '',
    comment           TEXT NOT NULL DEFAULT '',  -- обязателен для source=manual
    ran_at            TEXT NOT NULL,
    actor             TEXT NOT NULL
);

CREATE INDEX idx_test_runs_version ON test_runs(script_version_id, id);

-- Подписи владельца на хэш содержимого версии. Меняются только
-- добавлением новых записей: старая подпись остаётся в истории.
CREATE TABLE signatures (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    script_version_id INTEGER NOT NULL REFERENCES script_versions(id) ON DELETE CASCADE,
    sha256            TEXT NOT NULL,
    signed_by         TEXT NOT NULL,
    signed_at         TEXT NOT NULL,
    expires_at        TEXT NOT NULL,
    signature         TEXT NOT NULL             -- base64 ed25519
);

CREATE INDEX idx_signatures_version ON signatures(script_version_id, id);

CREATE TABLE jobs (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    script_version_id INTEGER NOT NULL REFERENCES script_versions(id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    kind              TEXT NOT NULL CHECK (kind IN ('catalog', 'script')),
    status            TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'running', 'done', 'stopped')),
    pilot             INTEGER NOT NULL DEFAULT 0,
    window_start      TEXT NOT NULL DEFAULT '',
    window_end        TEXT NOT NULL DEFAULT '',
    deadline          TEXT NOT NULL DEFAULT '',
    metric_threshold  REAL NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL,
    created_by        TEXT NOT NULL
);

CREATE INDEX idx_jobs_version ON jobs(script_version_id, id);

-- Состояние задания по агентам; очередь для выключенных машин —
-- состояние queued до следующего checkin.
CREATE TABLE job_targets (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id        INTEGER NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
    agent_id      TEXT NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    state         TEXT NOT NULL DEFAULT 'queued'
                  CHECK (state IN ('queued', 'sent', 'done', 'failed', 'expired', 'stopped')),
    result        TEXT NOT NULL DEFAULT '',
    error         TEXT NOT NULL DEFAULT '',
    envelope      TEXT NOT NULL DEFAULT '',    -- выданный конверт задания (JSON)
    sent_at       TEXT NOT NULL DEFAULT '',
    metric_before REAL,
    metric_after  REAL,
    updated_at    TEXT NOT NULL,
    UNIQUE (job_id, agent_id)
);

CREATE INDEX idx_job_targets_agent ON job_targets(agent_id, state);
