-- Миграция 3: из журнала аудита нельзя удалять.
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete
BEFORE DELETE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log: удаление из журнала запрещено');
END;
