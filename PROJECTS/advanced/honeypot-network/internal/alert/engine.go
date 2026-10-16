/*
©AngelaMos | 2026
engine.go

Alert engine: event bus subscriber that evaluates rules and notifies

Subscribes to the event bus with topic filters, runs events through
its own MITRE detector instance (so per-IP state is independent of
the processor), evaluates alert rules, deduplicates by rule + key
within a cooldown, records the alert for the dashboard, and hands
it to the webhook sender. Implements types.Service.
*/

package alert

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/event"
	"github.com/CarterPerez-dev/hive/internal/mitre"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

var subscribeTopics = []string{
	config.TopicAuth,
	config.TopicCommand,
	config.TopicConnect,
	config.TopicScan,
	config.TopicExploit,
	config.TopicFile,
}

type Detector interface {
	Detect(ev *types.Event) []*types.MITREDetection
}

type TechniqueLookup interface {
	Get(id string) *mitre.Technique
}

type SessionSource interface {
	Snapshot(sessionID string) *types.Session
}

// Deduper suppresses repeat alerts for the same key during cooldown.
type Deduper struct {
	mu       sync.Mutex
	cooldown time.Duration
	last     map[string]time.Time
}

func NewDeduper(cooldown time.Duration) *Deduper {
	return &Deduper{
		cooldown: cooldown,
		last:     make(map[string]time.Time),
	}
}

func (d *Deduper) Allow(key string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if t, ok := d.last[key]; ok && now.Sub(t) < d.cooldown {
		return false
	}
	d.last[key] = now
	return true
}

func (d *Deduper) Prune(now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	for k, t := range d.last {
		if now.Sub(t) >= d.cooldown {
			delete(d.last, k)
		}
	}
}

type Engine struct {
	sensorID string
	minScore int
	bus      *event.Bus
	detector Detector
	lookup   TechniqueLookup
	sessions SessionSource
	rules    []Rule
	dedupe   *Deduper
	store    *Store
	sender   *Sender
	seen     map[string]bool
	logger   zerolog.Logger
	now      func() time.Time
}

func New(
	cfg *config.Config,
	bus *event.Bus,
	det Detector,
	lookup TechniqueLookup,
	sessions SessionSource,
	store *Store,
	logger *zerolog.Logger,
) (*Engine, error) {
	rules, err := SelectRules(cfg.Alert.Rules)
	if err != nil {
		return nil, err
	}

	log := logger.With().Str("service", "alert").Logger()

	e := &Engine{
		sensorID: cfg.Sensor.ID,
		minScore: cfg.Alert.MinScore,
		bus:      bus,
		detector: det,
		lookup:   lookup,
		sessions: sessions,
		rules:    rules,
		dedupe:   NewDeduper(cfg.Alert.Cooldown),
		store:    store,
		seen:     make(map[string]bool),
		logger:   log,
		now:      func() time.Time { return time.Now().UTC() },
	}

	if cfg.Alert.WebhookURL != "" {
		if err := ValidateWebhookURL(
			cfg.Alert.WebhookURL,
		); err != nil {
			return nil, err
		}
		e.sender = NewSender(
			cfg.Alert.WebhookURL, cfg.Alert.Secret, log,
		)
		e.sender.SetOnResult(e.recordResult)
	}

	return e, nil
}

func (e *Engine) Name() string { return "alert" }

func (e *Engine) Start(ctx context.Context) error {
	ch := e.bus.Subscribe(
		config.DefaultEventBusBuffer, subscribeTopics...,
	)
	defer e.bus.Unsubscribe(ch)

	var wg sync.WaitGroup
	if e.sender != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e.sender.Run(ctx)
		}()
	}

	e.logger.Info().
		Int("rules", len(e.rules)).
		Bool("webhook", e.sender != nil).
		Msg("alert engine running")

	prune := time.NewTicker(time.Minute)
	defer prune.Stop()

	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return nil

		case <-prune.C:
			e.dedupe.Prune(e.now())

		case ev, ok := <-ch:
			if !ok {
				return nil
			}
			e.handle(ev)
		}
	}
}

func (e *Engine) handle(ev *types.Event) {
	now := e.now()
	dets := e.detector.Detect(ev)

	ec := &EvalContext{
		Event:         ev,
		Detections:    dets,
		NewDetections: e.collectNew(dets),
		Session:       e.sessions.Snapshot(ev.SessionID),
		MinScore:      e.minScore,
	}

	for _, rule := range e.rules {
		for _, f := range rule.Evaluate(ec) {
			if !e.dedupe.Allow(f.Rule+"|"+f.Key, now) {
				continue
			}
			e.emit(f, ec, now)
		}
	}
}

// collectNew returns detections whose technique has not been seen
// since startup. Only the engine goroutine touches e.seen.
func (e *Engine) collectNew(
	dets []*types.MITREDetection,
) []*types.MITREDetection {
	var fresh []*types.MITREDetection
	for _, d := range dets {
		if e.seen[d.TechniqueID] {
			continue
		}
		e.seen[d.TechniqueID] = true
		fresh = append(fresh, d)
	}
	return fresh
}

func (e *Engine) emit(f Finding, ec *EvalContext, now time.Time) {
	ev := cloneEvent(ec.Event)

	p := Payload{
		ID:          uuid.NewString(),
		Rule:        f.Rule,
		Severity:    f.Severity,
		Summary:     f.Summary,
		TriggeredAt: now,
		SensorID:    e.sensorID,
		SourceIP:    ev.SourceIP,
		ServiceType: ev.ServiceType.String(),
		Event:       ev,
		Session:     toSessionContext(ec.Session),
		MITRE:       e.mappings(ec.Detections, ec.Session),
	}

	e.logger.Info().
		Str("alert_id", p.ID).
		Str("rule", p.Rule).
		Str("severity", p.Severity).
		Str("source_ip", p.SourceIP).
		Msg(p.Summary)

	if e.sender == nil {
		e.store.Add(p, StatusLocal)
		return
	}

	e.store.Add(p, StatusPending)
	if !e.sender.Enqueue(p) {
		e.store.SetResult(
			p.ID, StatusDropped, 0,
			fmt.Errorf("webhook queue full"),
		)
	}
}

func (e *Engine) recordResult(
	id string, attempts int, err error,
) {
	status := StatusDelivered
	if err != nil {
		status = StatusFailed
	}
	e.store.SetResult(id, status, attempts, err)
}

func (e *Engine) mappings(
	dets []*types.MITREDetection, sess *types.Session,
) []MITREMapping {
	var ids []string
	seen := make(map[string]bool)
	add := func(id string) {
		if id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
	}

	for _, d := range dets {
		add(d.TechniqueID)
	}
	if sess != nil {
		for _, id := range sess.MITRETechniques {
			add(id)
		}
	}

	out := make([]MITREMapping, 0, len(ids))
	for _, id := range ids {
		m := MITREMapping{TechniqueID: id}
		if e.lookup != nil {
			if t := e.lookup.Get(id); t != nil {
				m.Name = t.Name
				m.Tactic = t.Tactic
			}
		}
		out = append(out, m)
	}
	return out
}

func cloneEvent(ev *types.Event) *types.Event {
	cp := *ev
	cp.Tags = append([]string(nil), ev.Tags...)
	return &cp
}

func toSessionContext(s *types.Session) *SessionContext {
	if s == nil {
		return nil
	}
	return &SessionContext{
		ID:              s.ID,
		ServiceType:     s.ServiceType.String(),
		SourceIP:        s.SourceIP,
		Username:        s.Username,
		LoginSuccess:    s.LoginSuccess,
		StartedAt:       s.StartedAt,
		CommandCount:    s.CommandCount,
		ThreatScore:     s.ThreatScore,
		MITRETechniques: s.MITRETechniques,
	}
}

var _ types.Service = (*Engine)(nil)