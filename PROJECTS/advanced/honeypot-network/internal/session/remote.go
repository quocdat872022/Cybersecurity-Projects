/*
©AngelaMos | 2026
remote.go

Tracker support for sessions that originate on remote sensors

The central hub mirrors each sensor's sessions into its own tracker
so the event processor can keep scoring them and the existing
SetOnStart / SetOnEnd persistence wiring works unchanged.
*/

package session

import "github.com/CarterPerez-dev/hive/pkg/types"

// Adopt registers a session created elsewhere. It returns false (and
// fires no callback) if the session is already tracked, which makes
// at-least-once redelivery harmless.
func (t *Tracker) Adopt(sess *types.Session) bool {
	t.mu.Lock()
	if _, exists := t.sessions[sess.ID]; exists {
		t.mu.Unlock()
		return false
	}
	t.sessions[sess.ID] = sess
	onStart := t.onStart
	t.mu.Unlock()

	if onStart != nil {
		onStart(sess)
	}
	return true
}

// Finalize copies the sensor-side counters (which only the sensor
// knows) onto the adopted session, keeping the score and techniques
// accumulated locally, then ends it.
func (t *Tracker) Finalize(remote *types.Session) *types.Session {
	t.mu.Lock()
	local, exists := t.sessions[remote.ID]
	if !exists {
		t.mu.Unlock()
		return nil
	}
	local.CommandCount = remote.CommandCount
	local.LoginSuccess = remote.LoginSuccess
	local.Username = remote.Username
	local.ClientVersion = remote.ClientVersion
	t.mu.Unlock()

	return t.End(remote.ID)
}