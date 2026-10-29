-- ©AngelaMos | 2026
-- 016_sensor_heartbeat.sql

-- +goose Up
ALTER TABLE sensors
    ADD COLUMN IF NOT EXISTS last_heartbeat  TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS active_sessions INTEGER NOT NULL DEFAULT 0;

-- +goose Down
ALTER TABLE sensors
    DROP COLUMN IF EXISTS active_sessions,
    DROP COLUMN IF EXISTS last_heartbeat;