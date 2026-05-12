// ©AngelaMos | 2026
// generator.go

package webbug

import (
	"context"
	"net/http"
	"strings"

	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/event"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators"
	"github.com/CarterPerez-dev/cybersecurity-projects/canary-token-generator/backend/internal/token/generators/pixel"
)

const (
	headerCFConnectingIP = "CF-Connecting-IP"
	headerXForwardedFor  = "X-Forwarded-For"
	headerXRealIP        = "X-Real-IP"
	headerReferer        = "Referer"
	headerCacheControl   = "Cache-Control"
	headerPragma         = "Pragma"

	cacheControlNoStore = "no-store, no-cache, must-revalidate, max-age=0"
	pragmaNoCache       = "no-cache"

	triggerPathPrefix = "/c/"
)

type Generator struct{}

func New() *Generator { return &Generator{} }

func (g *Generator) Type() token.Type { return token.TypeWebbug }

func (g *Generator) Generate(_ context.Context, t *token.Token, baseURL string) (generators.Artifact, error) {
	return generators.Artifact{
		Kind: generators.KindURL,
		URL:  strings.TrimRight(baseURL, "/") + triggerPathPrefix + t.ID,
	}, nil
}

func (g *Generator) Trigger(_ context.Context, t *token.Token, r *http.Request) (*event.Event, *generators.TriggerResponse, error) {
	tokenID := ""
	if t != nil {
		tokenID = t.ID
	}
	evt := &event.Event{
		TokenID:   tokenID,
		SourceIP:  realIP(r),
		UserAgent: optionalHeader(r.UserAgent()),
		Referer:   optionalHeader(r.Header.Get(headerReferer)),
	}
	resp := &generators.TriggerResponse{
		StatusCode:  http.StatusOK,
		ContentType: pixel.ContentType,
		Body:        pixel.TransparentGIF,
		ExtraHeaders: map[string]string{
			headerCacheControl: cacheControlNoStore,
			headerPragma:       pragmaNoCache,
		},
	}
	return evt, resp, nil
}

func optionalHeader(v string) *string {
	v = strings.TrimSpace(v)
	if v == "" {
		return nil
	}
	return &v
}

func realIP(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get(headerCFConnectingIP)); v != "" {
		return v
	}
	if v := r.Header.Get(headerXForwardedFor); v != "" {
		parts := strings.Split(v, ",")
		return strings.TrimSpace(parts[len(parts)-1])
	}
	if v := strings.TrimSpace(r.Header.Get(headerXRealIP)); v != "" {
		return v
	}
	return r.RemoteAddr
}
