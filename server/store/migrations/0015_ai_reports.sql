-- Миграция 15 (NR-013): отчёты для ИИ. Таблица соответствий —
-- отдельная таблица, отдаётся только владельцу маршрутом с аудитом.
CREATE TABLE ai_reports (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    topic        TEXT NOT NULL,
    created_at   TEXT NOT NULL,
    cleaned_text TEXT NOT NULL,          -- очищенный текст отчёта (без таблицы)
    answer       TEXT NOT NULL DEFAULT '', -- ответ ИИ (текст-предложение)
    status       TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'answered', 'drafted'))
);

CREATE TABLE ai_report_mappings (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    report_id INTEGER NOT NULL REFERENCES ai_reports(id) ON DELETE CASCADE,
    alias     TEXT NOT NULL,
    kind      TEXT NOT NULL,
    value     TEXT NOT NULL
);

CREATE INDEX idx_ai_report_mappings ON ai_report_mappings(report_id, id);
