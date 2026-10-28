/*
©AngelaMos | 2026
messages.go

Wire messages for the sensor <-> central protocol
*/

package sensorrpc

import (
	"time"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

const (
	KindEvent        = "event"
	KindSessionStart = "session_start"
	KindSessionEnd   = "session_end"
	KindRecording    = "recording"
)

type RegisterRequest struct {
	Sensor types.Sensor `json:"sensor"`
}

type RegisterResponse struct {
	Accepted         bool      `json:"accepted"`
	Message          string    `json:"message,omitempty"`
	ServerTime       time.Time `json:"server_time"`
	HeartbeatSeconds int       `json:"heartbeat_seconds"`
}

type HeartbeatRequest struct {
	SensorID       string    `json:"sensor_id"`
	ActiveSessions int       `json:"active_sessions"`
	SentAt         time.Time `json:"sent_at"`
}

type HeartbeatResponse struct {
	ServerTime time.Time `json:"server_time"`
}

// Envelope is the unit of delivery. Seq is per-sensor and monotonic;
// the hub acks every seq it has handled (including duplicates), and
// the sensor resends anything unacked after a reconnect.
type Envelope struct {
	Seq       uint64         `json:"seq"`
	SensorID  string         `json:"sensor_id"`
	Kind      string         `json:"kind"`
	Event     *types.Event   `json:"event,omitempty"`
	Session   *types.Session `json:"session,omitempty"`
	SessionID string         `json:"session_id,omitempty"`
	Recording []byte         `json:"recording,omitempty"`
}

type Ack struct {
	Seq uint64 `json:"seq"`
}