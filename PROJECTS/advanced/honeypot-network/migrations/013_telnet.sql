-- ©AngelaMos | 2026
-- 013_telnet.sql

-- +goose NO TRANSACTION
-- +goose Up
ALTER TYPE service_type ADD VALUE IF NOT EXISTS 'telnet';

-- +goose Down
-- Postgres doesn't support removing enum values; this migration
-- is intentionally one-way.
SELECT 1;