/*
©AngelaMos | 2026
webhook.go

Webhook payloads and delivery with HMAC signing and retries

Alerts are queued on a buffered channel and delivered by a small
worker pool, the same pattern as the event processor. Each POST is
signed with HMAC-SHA256 in the X-Hive-Signature header (same scheme
as GitHub webhooks) and retried 3 times with 1s, 4s, 16s backoff.
*/

package alert

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/rs/zerolog"

	"github.com/CarterPerez-dev/hive/internal/config"
	"github.com/CarterPerez-dev/hive/pkg/types"
)

const (
	HeaderSignature = "X-Hive-Signature"
	HeaderDelivery  = "X-Hive-Delivery"
	HeaderEvent     = "X-Hive-Event"
)

type SessionContext struct {
	ID              string    `json:"id"`
	ServiceType     string    `json:"service_type"`
	SourceIP        string    `json:"source_ip"`
	Username        string    `json:"username,omitempty"`
	LoginSuccess    bool      `json:"login_success"`
	StartedAt       time.Time `json:"started_at"`
	CommandCount    int       `json:"command_count"`
	ThreatScore     int       `json:"threat_score"`
	MITRETechniques []string  `json:"mitre_techniques,omitempty"`
}

type MITREMapping struct {
	TechniqueID string `json:"technique_id"`
	Name        string `json:"name,omitempty"`
	Tactic      string `json:"tactic,omitempty"`
}

type Payload struct {
	ID          string          `json:"id"`
	Rule        string          `json:"rule"`
	Severity    string          `json:"severity"`
	Summary     string          `json:"summary"`
	TriggeredAt time.Time       `json:"triggered_at"`
	SensorID    string          `json:"sensor_id"`
	SourceIP    string          `json:"source_ip"`
	ServiceType string          `json:"service_type"`
	Event       *types.Event    `json:"event,omitempty"`
	Session     *SessionContext `json:"session,omitempty"`
	MITRE       []MITREMapping  `json:"mitre,omitempty"`
}

// ResultFunc is invoked after a delivery finishes (or is abandoned).
type ResultFunc func(id string, attempts int, err error)

type Sender struct {
	url      string
	secret   string
	client   *http.Client
	backoffs []time.Duration
	queue    chan Payload
	workers  int
	onResult ResultFunc
	logger   zerolog.Logger
}

func ValidateWebhookURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid webhook url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf(
			"webhook url must be http or https, got %q", u.Scheme,
		)
	}
	if u.Host == "" {
		return fmt.Errorf("webhook url has no host")
	}
	return nil
}

func NewSender(
	webhookURL, secret string, logger zerolog.Logger,
) *Sender {
	return &Sender{
		url:    webhookURL,
		secret: secret,
		client: &http.Client{
			Timeout: config.DefaultAlertTimeout,
			CheckRedirect: func(
				*http.Request, []*http.Request,
			) error {
				return http.ErrUseLastResponse
			},
		},
		backoffs: []time.Duration{
			1 * time.Second,
			4 * time.Second,
			16 * time.Second,
		},
		queue:   make(chan Payload, config.DefaultAlertQueueSize),
		workers: config.DefaultAlertWorkers,
		logger:  logger,
	}
}

func (s *Sender) SetOnResult(fn ResultFunc) { s.onResult = fn }

// Enqueue never blocks; it reports false when the queue is full.
func (s *Sender) Enqueue(p Payload) bool {
	select {
	case s.queue <- p:
		return true
	default:
		return false
	}
}

func (s *Sender) Run(ctx context.Context) {
	var wg sync.WaitGroup
	for range s.workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.work(ctx)
		}()
	}
	wg.Wait()
}

func (s *Sender) work(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-s.queue:
			attempts, err := s.deliver(ctx, p)
			if err != nil {
				s.logger.Warn().Err(err).
					Str("alert_id", p.ID).
					Str("rule", p.Rule).
					Int("attempts", attempts).
					Msg("webhook delivery failed")
			}
			if s.onResult != nil {
				s.onResult(p.ID, attempts, err)
			}
		}
	}
}

func (s *Sender) deliver(
	ctx context.Context, p Payload,
) (int, error) {
	body, err := json.Marshal(p)
	if err != nil {
		return 0, fmt.Errorf("marshaling alert: %w", err)
	}

	for attempt := 0; ; attempt++ {
		retry, postErr := s.post(ctx, p.ID, body)
		if postErr == nil {
			return attempt + 1, nil
		}
		if !retry || attempt >= len(s.backoffs) {
			return attempt + 1, postErr
		}

		select {
		case <-ctx.Done():
			return attempt + 1, ctx.Err()
		case <-time.After(s.backoffs[attempt]):
		}
	}
}

// post sends one request and reports whether a failure is retryable.
func (s *Sender) post(
	ctx context.Context, id string, body []byte,
) (bool, error) {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, s.url, bytes.NewReader(body),
	)
	if err != nil {
		return false, fmt.Errorf("building request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "hive-alert/"+config.ToolVersion)
	req.Header.Set(HeaderEvent, "alert")
	req.Header.Set(HeaderDelivery, id)
	if s.secret != "" {
		req.Header.Set(HeaderSignature, Sign(s.secret, body))
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return true, fmt.Errorf("sending webhook: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	code := resp.StatusCode
	if code >= 200 && code < 300 {
		return false, nil
	}

	retry := code >= 500 ||
		code == http.StatusTooManyRequests ||
		code == http.StatusRequestTimeout
	return retry, fmt.Errorf("webhook returned status %d", code)
}

// Sign returns "sha256=<hex hmac>" of body, matching GitHub's format.
func Sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}