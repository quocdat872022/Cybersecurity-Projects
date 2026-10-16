/*
©AngelaMos | 2026
store.go

In-memory ring of recent alerts for the dashboard API

Keeps the most recent alerts along with their webhook delivery
status so GET /api/alerts can show what fired and whether the
notification reached its destination.
*/

package alert

import (
	"sync"

	"github.com/CarterPerez-dev/hive/internal/config"
)

const (
	StatusLocal     = "local"
	StatusPending   = "pending"
	StatusDelivered = "delivered"
	StatusFailed    = "failed"
	StatusDropped   = "dropped"
)

type Record struct {
	Payload
	Delivery      string `json:"delivery"`
	Attempts      int    `json:"attempts"`
	DeliveryError string `json:"delivery_error,omitempty"`
}

type Store struct {
	mu       sync.RWMutex
	capacity int
	records  []*Record
}

func NewStore(capacity int) *Store {
	if capacity <= 0 {
		capacity = config.DefaultAlertHistory
	}
	return &Store{capacity: capacity}
}

func (s *Store) Add(p Payload, status string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.records = append(
		s.records, &Record{Payload: p, Delivery: status},
	)
	if len(s.records) > s.capacity {
		s.records = append(
			[]*Record(nil),
			s.records[len(s.records)-s.capacity:]...,
		)
	}
}

func (s *Store) SetResult(
	id, status string, attempts int, err error,
) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := len(s.records) - 1; i >= 0; i-- {
		r := s.records[i]
		if r.ID != id {
			continue
		}
		r.Delivery = status
		r.Attempts = attempts
		if err != nil {
			r.DeliveryError = err.Error()
		}
		return
	}
}

// Recent returns up to limit records, newest first. limit <= 0
// returns everything.
func (s *Store) Recent(limit int) []Record {
	s.mu.RLock()
	defer s.mu.RUnlock()

	n := len(s.records)
	if limit <= 0 || limit > n {
		limit = n
	}

	out := make([]Record, 0, limit)
	for i := n - 1; i >= n-limit; i-- {
		out = append(out, *s.records[i])
	}
	return out
}