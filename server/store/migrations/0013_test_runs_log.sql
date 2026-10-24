-- Миграция 13 (NR-026): журнал теста со стенда Hyper-V. Лог —
-- недоверенный текст (вывод с целевой машины), до 256 КБ.
ALTER TABLE test_runs ADD COLUMN log TEXT NOT NULL DEFAULT '';
