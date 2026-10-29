/*
©AngelaMos | 2026
correlator.go

Cross-sensor attacker correlation

Tracks which sensors each source IP has touched inside a sliding
window. The first time an IP is seen on a second (or third, ...)
sensor within the window a Correlation is returned so the caller
can raise a "multi-sensor" event and the dashboard can show one
attacker timeline spanning the fleet.
*/

package fleet

import (
	"sort"
	"sync"
	"time"
)

type Correlation struct {
	IP         string    `json:"ip"`
	Sensors    []string  `json:"sensors"`
	FirstSeen  time.Time `json:"first_seen"`
	DetectedAt time.Time `json:"detected_at"`
}

type Correlator struct {
	mu        sync.Mutex
	window    time.Duration
	seen      map[string]map[string]time.Time
	reported  map[string]int
	recent    []Correlation
	maxRecent int
	ops       uint64
}

func NewCorrelator(window time.Duration) *Correlator {
	return &Correlator{
		window:    window,
		seen:      make(map[string]map[string]time.Time),
		reported:  make(map[string]int),
		maxRecent: 100,
	}
}

// Observe records a sighting and returns a Correlation only when the
// number of distinct sensors that saw ip inside the window grew.
func (c *Correlator) Observe(
	ip, sensorID string, now time.Time,
) *Correlation {
	if ip == "" || sensorID == "" {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.ops++
	if c.ops%1024 == 0 {
		c.sweep(now)
	}

	sensors := c.seen[ip]
	if sensors == nil {
		sensors = make(map[string]time.Time)
		c.seen[ip] = sensors
	}
	c.prune(sensors, now)
	sensors[sensorID] = now

	if len(sensors) < 2 {
		delete(c.reported, ip)
		return nil
	}
	if len(sensors) <= c.reported[ip] {
		return nil
	}
	c.reported[ip] = len(sensors)

	ids := make([]string, 0, len(sensors))
	first := now
	for id, ts := range sensors {
		ids = append(ids, id)
		if ts.Before(first) {
			first = ts
		}
	}
	sort.Strings(ids)

	corr := Correlation{
		IP: ip, Sensors: ids,
		FirstSeen: first, DetectedAt: now,
	}
	c.recent = append(c.recent, corr)
	if len(c.recent) > c.maxRecent {
		c.recent = c.recent[len(c.recent)-c.maxRecent:]
	}
	return &corr
}

// Recent returns up to limit correlations, newest first.
func (c *Correlator) Recent(limit int) []Correlation {
	c.mu.Lock()
	defer c.mu.Unlock()

	n := len(c.recent)
	if limit <= 0 || limit > n {
		limit = n
	}
	out := make([]Correlation, 0, limit)
	for i := n - 1; i >= n-limit; i-- {
		out = append(out, c.recent[i])
	}
	return out
}

func (c *Correlator) prune(
	sensors map[string]time.Time, now time.Time,
) {
	for id, ts := range sensors {
		if now.Sub(ts) > c.window {
			delete(sensors, id)
		}
	}
}

func (c *Correlator) sweep(now time.Time) {
	for ip, sensors := range c.seen {
		c.prune(sensors, now)
		if len(sensors) == 0 {
			delete(c.seen, ip)
			delete(c.reported, ip)
		}
	}
}