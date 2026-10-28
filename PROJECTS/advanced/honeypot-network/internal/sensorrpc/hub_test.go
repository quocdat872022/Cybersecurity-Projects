/*
©AngelaMos | 2026
hub_test.go
*/

package sensorrpc

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/event"
	"github.com/CarterPerez-dev/hive/internal/fleet"
	"github.com/CarterPerez-dev/hive/internal/session"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

type fakeSensorStore struct {
	mu      sync.Mutex
	sensors map[string]types.Sensor
}

func (f *fakeSensorStore) UpsertSensor(
	_ context.Context, s *types.Sensor,
) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sensors[s.ID] = *s
	return nil
}

func (f *fakeSensorStore) TouchSensor(
	context.Context, string, int, time.Time,
) error {
	return nil
}

func TestHubRegisterStreamAndDedup(t *testing.T) {
	cfg := config.Default()
	bus := event.NewBus()
	defer bus.Shutdown()
	events := bus.Subscribe(16, config.TopicAll)

	store := &fakeSensorStore{sensors: map[string]types.Sensor{}}
	logger := zerolog.Nop()
	hub := NewHub(
		cfg, bus, store, session.NewTracker(),
		fleet.NewCorrelator(time.Minute), &logger,
	)

	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	RegisterHubServer(srv, hub)
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(
			func(ctx context.Context, _ string) (net.Conn, error) {
				return lis.DialContext(ctx)
			}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(
		context.Background(), 5*time.Second,
	)
	defer cancel()

	c := NewClient(conn)
	resp, err := c.Register(ctx, &RegisterRequest{
		Sensor: types.Sensor{ID: "edge-1", Region: "eu"},
	})
	require.NoError(t, err)
	assert.True(t, resp.Accepted)
	assert.Contains(t, store.sensors, "edge-1")

	stream, err := c.StreamEvents(ctx)
	require.NoError(t, err)

	ev := &types.Event{
		ID:          "ev-1",
		SessionID:   "sess-1",
		SourceIP:    "203.0.113.9",
		ServiceType: types.ServiceSSH,
		EventType:   types.EventConnect,
		Protocol:    types.ProtocolTCP,
		Timestamp:   time.Now().UTC(),
	}

	// Same event delivered twice (e.g. a resend after reconnect).
	for seq := uint64(1); seq <= 2; seq++ {
		require.NoError(t, stream.Send(&Envelope{
			Seq: seq, SensorID: "edge-1",
			Kind: KindEvent, Event: ev,
		}))
		ack, err := stream.Recv()
		require.NoError(t, err)
		assert.Equal(t, seq, ack.Seq)
	}

	select {
	case got := <-events:
		assert.Equal(t, "ev-1", got.ID)
		assert.Equal(t, "edge-1", got.SensorID)
		assert.Equal(t, types.ServiceSSH, got.ServiceType)
	case <-time.After(time.Second):
		t.Fatal("event not published to bus")
	}

	select {
	case <-events:
		t.Fatal("duplicate event was republished")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestDedupSetEvictsOldest(t *testing.T) {
	d := newDedupSet(2)
	assert.False(t, d.seen("a"))
	assert.False(t, d.seen("b"))
	assert.True(t, d.seen("a"))
	assert.False(t, d.seen("c")) // evicts "a"
	assert.False(t, d.seen("a"))
}