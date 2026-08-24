// internal/event/processor_test.go
package event

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/hive/pkg/types"
	"github.com/rs/zerolog"
)

type fakeStore struct {
	iocs []*types.IOC
}

func (f *fakeStore) InsertEvent(context.Context, *types.Event) error              { return nil }
func (f *fakeStore) InsertCredential(context.Context, *types.Credential) error    { return nil }
func (f *fakeStore) InsertDetection(context.Context, *types.MITREDetection) error { return nil }
func (f *fakeStore) UpsertAttacker(context.Context, *types.Attacker) error        { return nil }
func (f *fakeStore) UpsertIOC(_ context.Context, ioc *types.IOC) error {
	f.iocs = append(f.iocs, ioc)
	return nil
}

func TestProcessorExtractsIOCsFromSMTPBody(t *testing.T) {
	store := &fakeStore{}
	p := NewProcessor(1, NewBus(), store, nil, nil, nil, testLogger())

	ev := &types.Event{
		ID:          "ev-1",
		SourceIP:    "203.0.113.5",
		EventType:   types.EventFileUpload,
		ServiceType: types.ServiceSMTP,
		Timestamp:   time.Now().UTC(),
		ServiceData: json.RawMessage(`{"body":"http://evil.com/miner.sh"}`),
	}

	p.persist(context.Background(), ev, nil)

	require.NotEmpty(t, store.iocs)

	var found bool
	for _, ioc := range store.iocs {
		if ioc.Type == types.IOCURL && ioc.Value == "http://evil.com/miner.sh" {
			found = true
		}
	}
	assert.True(t, found, "expected URL IOC to be persisted via store.UpsertIOC")
}

func testLogger() zerolog.Logger {
	return zerolog.Nop()
}
