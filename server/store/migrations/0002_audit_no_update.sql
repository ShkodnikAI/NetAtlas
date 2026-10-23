-- Миграция 2: журнал аудита нельзя править.
CREATE TRIGGER IF NOT EXISTS audit_log_no_update
BEFORE UPDATE ON audit_log
BEGIN
    SELECT RAISE(ABORT, 'audit_log: правка журнала запрещена');
END;
