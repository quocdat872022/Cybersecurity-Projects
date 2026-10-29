/*
©AngelaMos | 2026
agent.go

The agent subcommand runs honeypots and forwards to a central hub

An agent has no database, Redis, GeoIP or dashboard. It runs the
enabled honeypot services, and the sensorrpc agent streams every
event, session and SSH/Telnet recording to the hub for enrichment
and storage.
*/

package cli

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"golang.org/x/time/rate"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/event"
	"github.com/CarterPerez-dev/hive/internal/ratelimit"
	"github.com/CarterPerez-dev/hive/internal/sensorrpc"
	"github.com/CarterPerez-dev/hive/internal/session"
	"github.com/CarterPerez-dev/hive/internal/ui"
)

func newAgentCmd() *cobra.Command {
	var central string

	cmd := &cobra.Command{
		Use:   "agent",
		Short: "Run honeypots and forward traffic to a central hub",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAgent(cmd.Context(), central)
		},
	}

	cmd.Flags().StringVar(
		&central, "central", "",
		"central hub address host:port (overrides config)",
	)
	return cmd
}

func runAgent(ctx context.Context, central string) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	cfg.Cluster.Role = config.RoleAgent
	if central != "" {
		cfg.Cluster.CentralAddr = central
	}
	if cfg.Cluster.CentralAddr == "" {
		return errors.New(
			"central address required: --central or HIVE_CENTRAL_ADDR",
		)
	}

	logger := buildLogger(cfg)
	ui.PrintBanner()

	bus := event.NewBus()
	defer bus.Shutdown()

	tracker := session.NewTracker()
	limiter := ratelimit.NewIPLimiter(
		rate.Every(config.DefaultRateLimitInterval),
		config.DefaultRateLimitBurst,
	)
	defer limiter.Stop()

	services := buildServices(cfg, bus, &logger, tracker, limiter)

	names := make([]string, 0, len(services))
	for _, svc := range services {
		names = append(names, svc.Name())
	}

	agent := sensorrpc.NewAgent(cfg, bus, &logger, tracker, names)

	logger.Info().
		Str("sensor", cfg.Sensor.ID).
		Str("central", cfg.Cluster.CentralAddr).
		Strs("services", names).
		Msg("starting sensor agent")

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return agent.Start(ctx) })
	for _, svc := range services {
		g.Go(func() error { return svc.Start(ctx) })
	}
	return g.Wait()
}