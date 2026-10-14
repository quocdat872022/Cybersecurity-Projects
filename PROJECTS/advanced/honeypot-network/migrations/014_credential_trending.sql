-- ©AngelaMos | 2026
-- 012_credential_trending.sql

-- +goose Up
CREATE INDEX idx_creds_user_pass_ts
    ON credentials (username, password, timestamp DESC);

-- +goose Down
DROP INDEX IF EXISTS idx_creds_user_pass_ts;