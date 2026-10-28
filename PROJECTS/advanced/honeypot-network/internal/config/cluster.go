/*
©AngelaMos | 2026
cluster.go

Multi-sensor deployment settings

A single binary runs in one of three roles: standalone (the
original single-node mode), agent (honeypots only, forwards to a
central hub over gRPC) or central (hub, storage, API, dashboard).
*/

package config

import (
	"os"
	"time"
)

const (
	RoleStandalone = "standalone"
	RoleCentral    = "central"
	RoleAgent      = "agent"

	DefaultGRPCPort          = 9090
	DefaultHeartbeatInterval = 10 * time.Second
	DefaultCorrelationWindow = 10 * time.Minute
)

type ClusterConfig struct {
	Role              string        `yaml:"role"`
	CentralAddr       string        `yaml:"central_addr"`
	GRPCPort          int           `yaml:"grpc_port"`
	Token             string        `yaml:"token"`
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	CorrelationWindow time.Duration `yaml:"correlation_window"`
}

func DefaultCluster() ClusterConfig {
	return ClusterConfig{
		Role:              RoleStandalone,
		GRPCPort:          DefaultGRPCPort,
		HeartbeatInterval: DefaultHeartbeatInterval,
		CorrelationWindow: DefaultCorrelationWindow,
	}
}

func applyClusterEnv(cfg *Config) {
	if v := os.Getenv("HIVE_CENTRAL_ADDR"); v != "" {
		cfg.Cluster.CentralAddr = v
	}
	if v := os.Getenv("HIVE_CLUSTER_TOKEN"); v != "" {
		cfg.Cluster.Token = v
	}
	if v := os.Getenv("HIVE_HEARTBEAT_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.Cluster.HeartbeatInterval = d
		}
	}
	if v := os.Getenv("HIVE_CORRELATION_WINDOW"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.Cluster.CorrelationWindow = d
		}
	}
	applyPortOverride("HIVE_GRPC_PORT", &cfg.Cluster.GRPCPort)
}