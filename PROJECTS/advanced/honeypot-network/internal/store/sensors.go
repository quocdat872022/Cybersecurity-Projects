/*
©AngelaMos | 2026
sensors.go

Sensor registry persistence for multi-sensor deployments
*/

package store

import (
	"context"
	"fmt"
	"time"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

type SensorRepository interface {
	UpsertSensor(ctx context.Context, s *types.Sensor) error
	TouchSensor(
		ctx context.Context, id string, active int, at time.Time,
	) error
	ListSensors(ctx context.Context) ([]*types.Sensor, error)
}

func (s *PgxStore) UpsertSensor(
	ctx context.Context, sn *types.Sensor,
) error {
	services := sn.Services
	if services == nil {
		services = []string{}
	}
	var publicIP *string
	if sn.PublicIP != "" {
		publicIP = &sn.PublicIP
	}

	_, err := s.pool.Exec(ctx, `
		INSERT INTO sensors (
			id, hostname, region, public_ip, services,
			started_at, status, last_heartbeat, active_sessions
		) VALUES ($1, $2, $3, $4, $5, $6, 'active', NOW(), 0)
		ON CONFLICT (id) DO UPDATE SET
			hostname = EXCLUDED.hostname,
			region = EXCLUDED.region,
			public_ip = COALESCE(EXCLUDED.public_ip, sensors.public_ip),
			services = EXCLUDED.services,
			started_at = EXCLUDED.started_at,
			status = 'active',
			last_heartbeat = NOW()`,
		sn.ID, sn.Hostname, sn.Region, publicIP,
		services, sn.StartedAt,
	)
	if err != nil {
		return fmt.Errorf("upserting sensor: %w", err)
	}
	return nil
}

func (s *PgxStore) TouchSensor(
	ctx context.Context, id string, active int, at time.Time,
) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE sensors
		SET last_heartbeat = $2, active_sessions = $3,
			status = 'active'
		WHERE id = $1`,
		id, at, active,
	)
	if err != nil {
		return fmt.Errorf("touching sensor: %w", err)
	}
	return nil
}

func (s *PgxStore) ListSensors(
	ctx context.Context,
) ([]*types.Sensor, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, hostname, region, COALESCE(public_ip, ''),
			services, started_at, status,
			last_heartbeat, active_sessions
		FROM sensors
		ORDER BY id`,
	)
	if err != nil {
		return nil, fmt.Errorf("listing sensors: %w", err)
	}
	defer rows.Close()

	var out []*types.Sensor
	for rows.Next() {
		var sn types.Sensor
		if err := rows.Scan(
			&sn.ID, &sn.Hostname, &sn.Region, &sn.PublicIP,
			&sn.Services, &sn.StartedAt, &sn.Status,
			&sn.LastHeartbeat, &sn.ActiveSessions,
		); err != nil {
			return nil, fmt.Errorf("scanning sensor: %w", err)
		}
		out = append(out, &sn)
	}
	return out, rows.Err()
}