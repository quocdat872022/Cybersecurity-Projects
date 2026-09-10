/*
©AngelaMos | 2026
tracker.go

Thread-safe active session tracker

Manages the lifecycle of honeypot sessions from connect to
disconnect. Each connection gets a unique session ID (UUID v7)
and is tracked in an in-memory map. Session metadata accumulates
as the attacker interacts: command counts, login status, MITRE
technique tags, and threat scores.
*/

package session

import (
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/CarterPerez-dev/hive/internal/scoring"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

type Tracker struct {
	mu       sync.RWMutex
	sessions map[string]*types.Session
	onStart  func(*types.Session)
	onEnd    func(*types.Session)
}

func NewTracker() *Tracker {
	return &Tracker{
		sessions: make(map[string]*types.Session),
	}
}

func (t *Tracker) SetOnStart(fn func(*types.Session)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onStart = fn
}

func (t *Tracker) Start(
	sensorID string,
	serviceType types.ServiceType,
	sourceIP string,
	sourcePort int,
	destPort int,
) *types.Session {
	sess := &types.Session{
		ID:          uuid.Must(uuid.NewV7()).String(),
		SensorID:    sensorID,
		StartedAt:   time.Now().UTC(),
		ServiceType: serviceType,
		SourceIP:    sourceIP,
		SourcePort:  sourcePort,
		DestPort:    destPort,
	}

	t.mu.Lock()
	t.sessions[sess.ID] = sess
	onStart := t.onStart
	t.mu.Unlock()

	if onStart != nil {
		onStart(sess)
	}

	return sess
}

func (t *Tracker) SetOnEnd(fn func(*types.Session)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.onEnd = fn
}

func (t *Tracker) End(sessionID string) *types.Session {
	t.mu.Lock()
	sess, exists := t.sessions[sessionID]
	if !exists {
		t.mu.Unlock()
		return nil
	}

	now := time.Now().UTC()
	sess.EndedAt = &now

	if now.Sub(sess.StartedAt) > scoring.LongSessionThreshold {
		sess.ThreatScore = scoring.Cap(
			sess.ThreatScore + scoring.WeightLongSession,
		)
	}

	delete(t.sessions, sessionID)
	onEnd := t.onEnd
	t.mu.Unlock()

	if onEnd != nil {
		onEnd(sess)
	}

	return sess
}

func (t *Tracker) Get(sessionID string) *types.Session {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.sessions[sessionID]
}

func (t *Tracker) Active() []*types.Session {
	t.mu.RLock()
	defer t.mu.RUnlock()

	result := make([]*types.Session, 0, len(t.sessions))
	for _, sess := range t.sessions {
		result = append(result, sess)
	}
	return result
}

func (t *Tracker) IncrCommandCount(sessionID string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if sess, exists := t.sessions[sessionID]; exists {
		sess.CommandCount++
	}
}

func (t *Tracker) SetLogin(
	sessionID string,
	success bool,
	username string,
	clientVersion string,
) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if sess, exists := t.sessions[sessionID]; exists {
		sess.LoginSuccess = success
		sess.Username = username
		sess.ClientVersion = clientVersion
	}
}

// AddTechnique records a MITRE technique on the session if it hasn't
// already been seen, awarding threat-score points for the first
// sighting of each unique technique. Returns true if this was a new
// technique for the session.
func (t *Tracker) AddTechnique(
	sessionID, techniqueID string,
) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	sess, exists := t.sessions[sessionID]
	if !exists {
		return false
	}

	for _, tid := range sess.MITRETechniques {
		if tid == techniqueID {
			return false
		}
	}

	sess.MITRETechniques = append(
		sess.MITRETechniques, techniqueID,
	)
	sess.ThreatScore = scoring.Cap(
		sess.ThreatScore + scoring.WeightMITRETechnique,
	)
	return true
}

// AddScore adds points to the session's threat score, clamping the
// result to [0, scoring.MaxScore].
func (t *Tracker) AddScore(sessionID string, points int) {
	if points == 0 {
		return
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	sess, exists := t.sessions[sessionID]
	if !exists {
		return
	}

	sess.ThreatScore = scoring.Cap(sess.ThreatScore + points)
}

func (t *Tracker) Count() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.sessions)
}
