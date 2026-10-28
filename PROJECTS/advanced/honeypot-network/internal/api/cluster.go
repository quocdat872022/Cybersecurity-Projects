/*
©AngelaMos | 2026
cluster.go

Fleet-aware API handlers for central deployments

Sensor liveness is derived from the last heartbeat: a sensor that
has not checked in for three heartbeat intervals is reported as
offline. Correlations expose attackers seen on more than one sensor.
*/

package api

import (
	"net/http"
	"time"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/fleet"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

type clusterSensorInfo struct {
	sensorInfo
	LastHeartbeat  *time.Time `json:"last_heartbeat,omitempty"`
	ActiveSessions int        `json:"active_sessions"`
}

func (s *Server) SetCorrelator(c *fleet.Correlator) {
	s.corr = c
}

func (s *Server) isCentral() bool {
	return s.cfg.Cluster.Role == config.RoleCentral
}

func (s *Server) sensorOnline(sn *types.Sensor) bool {
	if sn.LastHeartbeat == nil {
		return false
	}
	limit := 3 * s.cfg.Cluster.HeartbeatInterval
	return time.Since(*sn.LastHeartbeat) <= limit
}

func (s *Server) handleClusterSensors(
	w http.ResponseWriter, r *http.Request,
) {
	sensors, err := s.store.ListSensors(r.Context())
	if err != nil {
		s.writeError(
			w, http.StatusInternalServerError,
			"failed to list sensors",
		)
		return
	}

	out := make([]clusterSensorInfo, 0, len(sensors))
	for _, sn := range sensors {
		state := "offline"
		active := 0
		if s.sensorOnline(sn) {
			state = "active"
			active = sn.ActiveSessions
		}
		out = append(out, clusterSensorInfo{
			sensorInfo: sensorInfo{
				ID:        sn.ID,
				Hostname:  sn.Hostname,
				Region:    sn.Region,
				Services:  sn.Services,
				StartedAt: sn.StartedAt,
				Status:    state,
			},
			LastHeartbeat:  sn.LastHeartbeat,
			ActiveSessions: active,
		})
	}

	s.writeJSON(w, http.StatusOK, apiResponse{Data: out})
}

// remoteActiveSessions sums live sessions reported by online sensors.
func (s *Server) remoteActiveSessions(r *http.Request) int {
	if !s.isCentral() {
		return 0
	}
	sensors, err := s.store.ListSensors(r.Context())
	if err != nil {
		return 0
	}
	total := 0
	for _, sn := range sensors {
		if s.sensorOnline(sn) {
			total += sn.ActiveSessions
		}
	}
	return total
}

func (s *Server) handleCorrelations(
	w http.ResponseWriter, r *http.Request,
) {
	limit, _ := parsePagination(r)

	data := []fleet.Correlation{}
	if s.corr != nil {
		data = s.corr.Recent(limit)
	}
	s.writeJSON(w, http.StatusOK, apiResponse{Data: data})
}