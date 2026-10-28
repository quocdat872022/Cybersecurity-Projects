/*
©AngelaMos | 2026
hub.go

Central-side gRPC hub that receives sensor traffic

Sensors register, heartbeat, and stream envelopes. Events are
republished on the central event bus so the existing processor
pipeline (GeoIP, MITRE, scoring, PostgreSQL, Redis) handles remote
traffic exactly like local traffic. Delivery is at-least-once from
the sensor; the hub de-duplicates by event / session ID.
*/

package sensorrpc

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/event"
	"github.com/CarterPerez-dev/hive/internal/fleet"
	"github.com/CarterPerez-dev/hive/internal/session"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

const (
	dedupCapacity     = 100000
	finalizeDelay     = 3 * time.Second
	maxRecvMsgBytes   = 16 << 20
	maxRecordingBytes = 8 << 20
	centralSensorID   = "central"
)

var sessionIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

type SensorStore interface {
	UpsertSensor(ctx context.Context, s *types.Sensor) error
	TouchSensor(
		ctx context.Context, id string, active int, at time.Time,
	) error
}

type Hub struct {
	cfg     *config.Config
	bus     *event.Bus
	store   SensorStore
	tracker *session.Tracker
	corr    *fleet.Correlator
	logger  zerolog.Logger
	dedup   *dedupSet
}

func NewHub(
	cfg *config.Config,
	bus *event.Bus,
	store SensorStore,
	tracker *session.Tracker,
	corr *fleet.Correlator,
	logger *zerolog.Logger,
) *Hub {
	return &Hub{
		cfg:     cfg,
		bus:     bus,
		store:   store,
		tracker: tracker,
		corr:    corr,
		logger:  logger.With().Str("service", "hub").Logger(),
		dedup:   newDedupSet(dedupCapacity),
	}
}

func (h *Hub) Name() string { return "hub" }

func (h *Hub) Start(ctx context.Context) error {
	addr := h.cfg.Addr(h.cfg.Cluster.GRPCPort)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("hub listen %s: %w", addr, err)
	}

	if h.cfg.Cluster.Token == "" {
		h.logger.Warn().
			Msg("HIVE_CLUSTER_TOKEN is empty: hub accepts any sensor")
	}

	srv := grpc.NewServer(
		grpc.UnaryInterceptor(h.unaryAuth),
		grpc.StreamInterceptor(h.streamAuth),
		grpc.MaxRecvMsgSize(maxRecvMsgBytes),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    30 * time.Second,
			Timeout: 10 * time.Second,
		}),
	)
	RegisterHubServer(srv, h)

	go func() {
		<-ctx.Done()
		srv.Stop()
	}()

	h.logger.Info().Str("addr", addr).Msg("sensor hub listening")

	if err := srv.Serve(lis); err != nil &&
		!errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("hub serve: %w", err)
	}
	return nil
}

// ---- auth ----

func (h *Hub) authorize(ctx context.Context) error {
	token := h.cfg.Cluster.Token
	if token == "" {
		return nil
	}
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing metadata")
	}
	want := []byte("Bearer " + token)
	for _, v := range md.Get("authorization") {
		if subtle.ConstantTimeCompare([]byte(v), want) == 1 {
			return nil
		}
	}
	return status.Error(codes.Unauthenticated, "invalid token")
}

func (h *Hub) unaryAuth(
	ctx context.Context, req any,
	_ *grpc.UnaryServerInfo, next grpc.UnaryHandler,
) (any, error) {
	if err := h.authorize(ctx); err != nil {
		return nil, err
	}
	return next(ctx, req)
}

func (h *Hub) streamAuth(
	srv any, ss grpc.ServerStream,
	_ *grpc.StreamServerInfo, next grpc.StreamHandler,
) error {
	if err := h.authorize(ss.Context()); err != nil {
		return err
	}
	return next(srv, ss)
}

// ---- RPCs ----

func (h *Hub) Register(
	ctx context.Context, req *RegisterRequest,
) (*RegisterResponse, error) {
	sn := req.Sensor
	if sn.ID == "" {
		return nil, status.Error(
			codes.InvalidArgument, "sensor id required",
		)
	}
	if sn.StartedAt.IsZero() {
		sn.StartedAt = time.Now().UTC()
	}
	sn.Status = "active"

	if err := h.store.UpsertSensor(ctx, &sn); err != nil {
		h.logger.Error().Err(err).Str("sensor", sn.ID).
			Msg("sensor registration failed")
		return nil, status.Error(codes.Internal, "registration failed")
	}

	h.logger.Info().
		Str("sensor", sn.ID).
		Str("region", sn.Region).
		Strs("services", sn.Services).
		Msg("sensor registered")

	return &RegisterResponse{
		Accepted:   true,
		ServerTime: time.Now().UTC(),
		HeartbeatSeconds: int(
			h.cfg.Cluster.HeartbeatInterval / time.Second,
		),
	}, nil
}

func (h *Hub) Heartbeat(
	ctx context.Context, req *HeartbeatRequest,
) (*HeartbeatResponse, error) {
	now := time.Now().UTC()
	if err := h.store.TouchSensor(
		ctx, req.SensorID, req.ActiveSessions, now,
	); err != nil {
		return nil, status.Error(codes.Internal, "heartbeat failed")
	}
	return &HeartbeatResponse{ServerTime: now}, nil
}

func (h *Hub) StreamEvents(stream EventStream) error {
	for {
		env, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) ||
				status.Code(err) == codes.Canceled {
				return nil
			}
			return err
		}

		h.handle(env)

		if err := stream.Send(&Ack{Seq: env.Seq}); err != nil {
			return err
		}
	}
}

// ---- envelope handling ----

func (h *Hub) handle(env *Envelope) {
	switch env.Kind {
	case KindEvent:
		h.handleEvent(env)
	case KindSessionStart:
		h.handleSessionStart(env)
	case KindSessionEnd:
		h.handleSessionEnd(env)
	case KindRecording:
		h.handleRecording(env)
	default:
		h.logger.Debug().Str("kind", env.Kind).
			Msg("unknown envelope kind")
	}
}

func (h *Hub) handleEvent(env *Envelope) {
	ev := env.Event
	if ev == nil || h.dedup.seen("e:"+ev.ID) {
		return
	}
	ev.SensorID = env.SensorID

	if c := h.corr.Observe(
		ev.SourceIP, env.SensorID, time.Now().UTC(),
	); c != nil {
		h.publishCorrelation(ev, c)
	}

	h.bus.Publish(topicFor(ev.EventType), ev)
}

func (h *Hub) handleSessionStart(env *Envelope) {
	sess := env.Session
	if sess == nil || h.dedup.seen("s:"+sess.ID) {
		return
	}
	sess.SensorID = env.SensorID
	h.tracker.Adopt(sess)
}

// The processor consumes bus events asynchronously, so give any
// in-flight events for this session a moment to be scored before the
// session is persisted as ended.
func (h *Hub) handleSessionEnd(env *Envelope) {
	sess := env.Session
	if sess == nil || h.dedup.seen("x:"+sess.ID) {
		return
	}
	time.AfterFunc(finalizeDelay, func() {
		h.tracker.Finalize(sess)
	})
}

func (h *Hub) handleRecording(env *Envelope) {
	if !sessionIDPattern.MatchString(env.SessionID) ||
		len(env.Recording) == 0 ||
		len(env.Recording) > maxRecordingBytes ||
		h.dedup.seen("r:"+env.SessionID) {
		return
	}

	dir := h.cfg.Log.ReplayDir
	if err := os.MkdirAll(dir, 0o755); err != nil {
		h.logger.Error().Err(err).Msg("creating replay dir")
		return
	}
	path := filepath.Join(dir, env.SessionID+".cast")
	if err := os.WriteFile(path, env.Recording, 0o644); err != nil {
		h.logger.Error().Err(err).
			Str("session_id", env.SessionID).
			Msg("saving remote recording")
	}
}

func (h *Hub) publishCorrelation(
	src *types.Event, c *fleet.Correlation,
) {
	data, _ := json.Marshal(map[string]any{
		"sensors":        c.Sensors,
		"first_seen":     c.FirstSeen,
		"window_seconds": int(h.cfg.Cluster.CorrelationWindow.Seconds()),
	})

	h.bus.Publish(config.TopicScan, &types.Event{
		ID:            uuid.Must(uuid.NewV7()).String(),
		SessionID:     src.SessionID,
		SensorID:      centralSensorID,
		Timestamp:     time.Now().UTC(),
		ServiceType:   src.ServiceType,
		EventType:     types.EventScan,
		SourceIP:      src.SourceIP,
		Protocol:      types.ProtocolTCP,
		SchemaVersion: config.SchemaVersion,
		Tags:          []string{"multi-sensor", "correlated-activity"},
		ServiceData:   data,
	})
}

func topicFor(et types.EventType) string {
	switch et {
	case types.EventConnect:
		return config.TopicConnect
	case types.EventDisconnect:
		return config.TopicDisconnect
	case types.EventLoginSuccess, types.EventLoginFailed:
		return config.TopicAuth
	case types.EventFileUpload, types.EventFileDownload:
		return config.TopicFile
	case types.EventExploit:
		return config.TopicExploit
	case types.EventScan:
		return config.TopicScan
	default:
		return config.TopicCommand
	}
}

// ---- bounded de-duplication ----

type dedupSet struct {
	mu   sync.Mutex
	set  map[string]struct{}
	ring []string
	pos  int
	max  int
}

func newDedupSet(capacity int) *dedupSet {
	return &dedupSet{
		set: make(map[string]struct{}, capacity),
		max: capacity,
	}
}

// seen reports whether key was already recorded; if not it records it,
// evicting the oldest key once capacity is reached.
func (d *dedupSet) seen(key string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if _, ok := d.set[key]; ok {
		return true
	}
	if len(d.ring) < d.max {
		d.ring = append(d.ring, key)
	} else {
		delete(d.set, d.ring[d.pos])
		d.ring[d.pos] = key
		d.pos = (d.pos + 1) % d.max
	}
	d.set[key] = struct{}{}
	return false
}