-- Миграция 7 (NR-007): PKI — список отзыва сертификатов и токены
-- регистрации агентов. Хэши и серийные номера — не секреты; исходные
-- токены и закрытые ключи в базе не хранятся.
CREATE TABLE revoked_certs (
    serial     TEXT PRIMARY KEY NOT NULL,   -- серийный номер (десятичная строка)
    revoked_at TEXT NOT NULL,
    actor      TEXT NOT NULL DEFAULT 'pki'
);

CREATE TABLE enroll_tokens (
    hash     TEXT PRIMARY KEY NOT NULL,     -- SHA-256 токена (hex); сам токен не хранится
    created  TEXT NOT NULL,
    expires  TEXT NOT NULL,                 -- срок жизни 1 час
    used_at  TEXT NOT NULL DEFAULT ''       -- одноразовые: пусто — не использован
);
