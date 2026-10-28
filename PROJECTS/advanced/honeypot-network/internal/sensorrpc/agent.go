/*
©AngelaMos | 2026
agent.go

Sensor-side forwarder that ships honeypot traffic to the central hub

Runs alongside the honeypot services in "hive agent" mode. It
subscribes to the local event bus, mirrors session start/end from
the tracker, and streams everything to the hub over a bidirectional
gRPC stream. Every envelope carries a sequence number and stays in
an in-memory unacked table until the hub acks it; after a reconnect
the unacked set is resent (at-least-once, hub de-duplicates).
*/

package sensorrpc

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/event"
	"github.com/CarterPerez-dev/hive/internal/session"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

const (
	recordingDelay = 2 * time.Second
	maxBackoff     = 30 * time.Second
	rpcTimeout     = 10 * time.Second
)

type tokenAuth struct{ token string }

func (t tokenAuth) GetRequestMetadata(
	context.Context, ...string,
) (map[string]string, error) {
	return map[string]string{
		"authorization": "Bearer " + t.token,
	}, nil
}

func (t tokenAuth) RequireTransportSecurity() bool { return false }

type Agent struct {
	cfg       *config.Config
	logger    zerolog.Logger
	tracker   *session.Tracker
	services  []string
	startedAt time.Time

	events  <-chan *types.Event
	outbox  chan *Envelope
	seq     atomic.Uint64
	dropped atomic.Uint64

	mu      sync.Mutex
	unacked map[uint64]*Envelope
}

// NewAgent subscribes to the bus and installs tracker hooks
// immediately so nothing published before Start is missed. Call it
// before starting the honeypot services.
func NewAgent(
	cfg *config.Config,
	bus *event.Bus,
	logger *zerolog.Logger,
	tracker *session.Tracker,
	services []string,
) *Agent {
	a := &Agent{
		cfg:       cfg,
		logger:    logger.With().Str("service", "agent").Logger(),
		tracker:   tracker,
		services:  services,
		startedAt: time.Now().UTC(),
		events: bus.Subscribe(
			config.DefaultEventBusBuffer, config.TopicAll,
		),
		outbox:  make(chan *Envelope, config.DefaultEventBusBuffer),
		unacked: make(map[uint64]*Envelope),
	}

	tracker.SetOnStart(func(s *types.Session) {
		cp := *s
		a.enqueue(&Envelope{Kind: KindSessionStart, Session: &cp})
	})
	tracker.SetOnEnd(func(s *types.Session) {
		cp := *s
		a.enqueue(&Envelope{Kind: KindSessionEnd, Session: &cp})
		time.AfterFunc(recordingDelay, func() {
			a.sendRecording(cp.ID)
		})
	})

	return a
}

func (a *Agent) Name() string { return "agent" }

func (a *Agent) Start(ctx context.Context) error {
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	}
	if a.cfg.Cluster.Token != "" {
		opts = append(opts, grpc.WithPerRPCCredentials(
			tokenAuth{token: a.cfg.Cluster.Token},
		))
	}

	conn, err := grpc.NewClient(a.cfg.Cluster.CentralAddr, opts...)
	if err != nil {
		return fmt.Errorf("dialing central: %w", err)
	}
	defer func() { _ = conn.Close() }()

	client := NewClient(conn)
	go a.forward(ctx)

	backoff := time.Second
	for ctx.Err() == nil {
		start := time.Now()
		err := a.runSession(ctx, client)
		if ctx.Err() != nil {
			break
		}

		a.logger.Warn().Err(err).
			Dur("retry_in", backoff).
			Msg("central connection lost")

		if time.Since(start) > 30*time.Second {
			backoff = time.Second
		}
		select {
		case <-ctx.Done():
		case <-time.After(backoff):
		}
		backoff = min(backoff*2, maxBackoff)
	}
	return nil
}

func (a *Agent) forward(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-a.events:
			if !ok {
				return
			}
			a.enqueue(&Envelope{Kind: KindEvent, Event: ev})
		}
	}
}

func (a *Agent) enqueue(env *Envelope) {
	env.Seq = a.seq.Add(1)
	env.SensorID = a.cfg.Sensor.ID

	a.mu.Lock()
	a.unacked[env.Seq] = env
	a.mu.Unlock()

	select {
	case a.outbox <- env:
	default:
		a.mu.Lock()
		delete(a.unacked, env.Seq)
		a.mu.Unlock()
		if n := a.dropped.Add(1); n%1000 == 1 {
			a.logger.Warn().Uint64("dropped_total", n).
				Msg("outbox full, dropping envelopes")
		}
	}
}

func (a *Agent) runSession(
	ctx context.Context, c *Client,
) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	rctx, rcancel := context.WithTimeout(ctx, rpcTimeout)
	resp, err := c.Register(
		rctx, &RegisterRequest{Sensor: a.sensorInfo()},
	)
	rcancel()
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	if !resp.Accepted {
		return fmt.Errorf("registration rejected: %s", resp.Message)
	}

	interval := time.Duration(resp.HeartbeatSeconds) * time.Second
	if interval <= 0 {
		interval = a.cfg.Cluster.HeartbeatInterval
	}

	stream, err := c.StreamEvents(ctx)
	if err != nil {
		return fmt.Errorf("opening stream: %w", err)
	}

	a.logger.Info().
		Str("central", a.cfg.Cluster.CentralAddr).
		Msg("connected to central")

	errCh := make(chan error, 2)
	go func() { errCh <- a.recvAcks(stream) }()
	go func() { errCh <- a.heartbeats(ctx, c, interval) }()

	// Everything still in the outbox is also in unacked, so drop the
	// queue and resend from the table to avoid sending twice.
	a.drainOutbox()
	if err := a.resendUnacked(stream); err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errCh:
			return err
		case env := <-a.outbox:
			if err := stream.Send(env); err != nil {
				return fmt.Errorf("send: %w", err)
			}
		}
	}
}

func (a *Agent) drainOutbox() {
	for {
		select {
		case <-a.outbox:
		default:
			return
		}
	}
}

func (a *Agent) resendUnacked(stream *ClientStream) error {
	a.mu.Lock()
	pending := make([]*Envelope, 0, len(a.unacked))
	for _, env := range a.unacked {
		pending = append(pending, env)
	}
	a.mu.Unlock()

	sort.Slice(pending, func(i, j int) bool {
		return pending[i].Seq < pending[j].Seq
	})

	for _, env := range pending {
		if err := stream.Send(env); err != nil {
			return fmt.Errorf("resend: %w", err)
		}
	}
	if len(pending) > 0 {
		a.logger.Info().Int("count", len(pending)).
			Msg("resent unacked envelopes")
	}
	return nil
}

func (a *Agent) recvAcks(stream *ClientStream) error {
	for {
		ack, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("recv ack: %w", err)
		}
		a.mu.Lock()
		delete(a.unacked, ack.Seq)
		a.mu.Unlock()
	}
}

func (a *Agent) heartbeats(
	ctx context.Context, c *Client, interval time.Duration,
) error {
	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			hctx, cancel := context.WithTimeout(ctx, rpcTimeout)
			_, err := c.Heartbeat(hctx, &HeartbeatRequest{
				SensorID:       a.cfg.Sensor.ID,
				ActiveSessions: a.tracker.Count(),
				SentAt:         time.Now().UTC(),
			})
			cancel()
			if err != nil {
				return fmt.Errorf("heartbeat: %w", err)
			}
		}
	}
}

func (a *Agent) sensorInfo() types.Sensor {
	return types.Sensor{
		ID:        a.cfg.Sensor.ID,
		Hostname:  a.cfg.Sensor.Hostname,
		Region:    a.cfg.Sensor.Region,
		Services:  a.services,
		StartedAt: a.startedAt,
		Status:    "active",
	}
}

func (a *Agent) sendRecording(sessionID string) {
	path := filepath.Join(a.cfg.Log.ReplayDir, sessionID+".cast")
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 || len(data) > maxRecordingBytes {
		return
	}
	a.enqueue(&Envelope{
		Kind:      KindRecording,
		SessionID: sessionID,
		Recording: data,
	})
}