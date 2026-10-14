-- ©AngelaMos | 2026
-- 015_smtp_enum.sql

-- +goose Up
-- +goose NO TRANSACTION
ALTER TYPE service_type ADD VALUE IF NOT EXISTS 'smtp';

-- +goose Down
-- Postgres does not support removing enum values without
-- rebuilding the type; treated as a no-op on rollback.