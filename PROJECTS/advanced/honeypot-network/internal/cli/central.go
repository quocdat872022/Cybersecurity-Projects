/*
©AngelaMos | 2026
central.go

The central subcommand runs the hub, storage pipeline and dashboard

Central accepts sensor streams over gRPC and feeds them through the
same processor pipeline used in standalone mode. It runs no
honeypots of its own; start agents (or a standalone node) elsewhere.
*/

package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/CarterPerez-dev/hive/internal/api"
	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/event"
	"github.com/CarterPerez-dev/hive/internal/fleet"
	"github.com/CarterPerez-dev/hive/internal/geo"
	"github.com/CarterPerez-dev/hive/internal/mitre"
	"github.com/CarterPerez-dev/hive/internal/sensorrpc"
	"github.com/CarterPerez-dev/hive/internal/session"
	"github.com/CarterPerez-dev/hive/internal/store"
	"github.com/CarterPerez-dev/hive/internal/ui"
	"github.com/CarterPerez-dev/hive/pkg/types"
	"github.com/CarterPerez-dev/hive/internal/alert"
)

func newCentralCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "central",
		Short: "Run the central hub, storage and dashboard API",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCentral(cmd.Context())
		},
	}
}

func runCentral(ctx context.Context) error {
	cfg, err := loadConfig()
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}
	cfg.Cluster.Role = config.RoleCentral

	logger := buildLogger(cfg)
	ui.PrintBanner()

	bus := event.NewBus()
	defer bus.Shutdown()

	tracker := session.NewTracker()
	detector := mitre.NewDetector()

	pgStore, err := store.NewPgxStore(ctx, cfg.Database.DSN)
	if err != nil {
		return fmt.Errorf("connecting to database: %w", err)
	}
	defer pgStore.Close()

	if err := pgStore.EnsurePartitions(ctx); err != nil {
		return fmt.Errorf("creating table partitions: %w", err)
	}

	redisStreamer, err := store.NewRedisStreamer(
		cfg.Stream.URL, cfg.Stream.Password,
	)
	if err != nil {
		return fmt.Errorf("connecting to redis stream: %w", err)
	}
	defer func() { _ = redisStreamer.Close() }()

	geoLookup, err := geo.NewLookup(cfg.GeoIP.DBPath, cfg.GeoIP.ASNDBPath)
	if err != nil {
		return fmt.Errorf("loading geoip database: %w", err)
	}
	defer func() { _ = geoLookup.Close() }()

	tracker.SetOnStart(func(sess *types.Session) {
		if err := pgStore.InsertSession(ctx, sess); err != nil {
			logger.Error().Err(err).
				Str("session_id", sess.ID).
				Msg("failed to persist session start")
		}
	})
	tracker.SetOnEnd(func(sess *types.Session) {
		if err := pgStore.UpdateSession(ctx, sess); err != nil {
			logger.Error().Err(err).
				Str("session_id", sess.ID).
				Msg("failed to persist session end")
		}
	})

	proc := event.NewProcessor(
		config.DefaultProcessorWorkers, bus, pgStore,
		redisStreamer, geoLookup, detector, tracker, logger,
	)

	corr := fleet.NewCorrelator(cfg.Cluster.CorrelationWindow)
	hub := sensorrpc.NewHub(
		cfg, bus, pgStore, tracker, corr, &logger,
	)

	alertStore := alert.NewStore(config.DefaultAlertHistory)
	
	apiSvc := api.New(
		pgStore, bus, detector.Index(), tracker, cfg, &logger, alertStore,
	)
	apiSvc.SetCorrelator(corr)

	logger.Info().
		Int("grpc_port", cfg.Cluster.GRPCPort).
		Msg("starting central hub")

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error { return proc.Start(ctx) })
	g.Go(func() error { return hub.Start(ctx) })
	g.Go(func() error { return apiSvc.Start(ctx) })
	return g.Wait()
}