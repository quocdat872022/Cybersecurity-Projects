-- ©AngelaMos | 2026
-- 012_seed_sensors.sql
-- Seeds a default sensor row so the FK constraint on sessions is satisfied
-- during development. In production, the sensor registers itself on startup.

-- +goose Up
INSERT INTO sensors (id, hostname, region, services, status)
VALUES (
    'hive-dev',
    'ubuntu-server',
    'local',
    ARRAY['ssh','http','ftp','smb','mysql','redis'],
    'active'
) ON CONFLICT (id) DO NOTHING;

-- +goose Down
DELETE FROM sensors WHERE id = 'hive-dev';
