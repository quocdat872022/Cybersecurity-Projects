# Challenge 6 integration: webhook alerting

New files (already in `internal/alert/`): `rules.go`, `webhook.go`, `engine.go`, `store.go`, `alert_test.go`.
Apply the edits below to existing files.

## 1. `internal/config/constants.go`

```go
const (
	DefaultAlertCooldown  = 5 * time.Minute
	DefaultAlertMinScore  = 60
	DefaultAlertQueueSize = 256
	DefaultAlertWorkers   = 2
	DefaultAlertTimeout   = 10 * time.Second
	DefaultAlertHistory   = 500
)
```

## 2. `internal/config/config.go`

Add to `Config`:

```go
Alert    AlertConfig    `yaml:"alert"`
```

Add the type:

```go
type AlertConfig struct {
	Enabled    bool          `yaml:"enabled"`
	WebhookURL string        `yaml:"webhook_url"`
	Secret     string        `yaml:"secret"`
	Rules      []string      `yaml:"rules"`
	Cooldown   time.Duration `yaml:"cooldown"`
	MinScore   int           `yaml:"min_score"`
}
```

In `Default()`:

```go
Alert: AlertConfig{
	Enabled:  true,
	Cooldown: DefaultAlertCooldown,
	MinScore: DefaultAlertMinScore,
},
```

At the end of `applyEnvOverrides`, add `applyAlertOverrides(cfg)` and:

```go
func applyAlertOverrides(cfg *Config) {
	applyBoolOverride("HIVE_ALERT_ENABLED", &cfg.Alert.Enabled)
	if v := os.Getenv("HIVE_ALERT_WEBHOOK_URL"); v != "" {
		cfg.Alert.WebhookURL = v
	}
	if v := os.Getenv("HIVE_ALERT_WEBHOOK_SECRET"); v != "" {
		cfg.Alert.Secret = v
	}
	if v := os.Getenv("HIVE_ALERT_RULES"); v != "" {
		cfg.Alert.Rules = strings.Split(v, ",")
	}
	if v := os.Getenv("HIVE_ALERT_COOLDOWN"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Alert.Cooldown = d
		}
	}
	applyPortOverride("HIVE_ALERT_MIN_SCORE", &cfg.Alert.MinScore)
}
```

(`applyPortOverride` is just an int parser.)

## 3. `internal/session/tracker.go`

```go
// Snapshot returns a copy of an active session, or nil.
func (t *Tracker) Snapshot(sessionID string) *types.Session {
	t.mu.RLock()
	defer t.mu.RUnlock()

	sess, ok := t.sessions[sessionID]
	if !ok {
		return nil
	}
	cp := *sess
	cp.MITRETechniques = append([]string(nil), sess.MITRETechniques...)
	cp.Tags = append([]string(nil), sess.Tags...)
	return &cp
}
```

## 4. `internal/api/router.go`

Import `github.com/CarterPerez-dev/hive/internal/alert`, add `alerts *alert.Store` to `Server`, add it as the last parameter of `New(...)`, set `alerts: alerts` in the struct literal, and register in `/api`:

```go
r.Get("/alerts", s.handleAlerts)
```

## 5. `internal/api/handlers.go`

Import `internal/alert`, then:

```go
func (s *Server) handleAlerts(
	w http.ResponseWriter, r *http.Request,
) {
	limit, _ := parsePagination(r)

	records := []alert.Record{}
	if s.alerts != nil {
		records = s.alerts.Recent(limit)
	}

	s.writeJSON(w, http.StatusOK, apiResponse{Data: records})
}
```

## 6. `internal/cli/serve.go`

Import `internal/alert`. Replace the `api.New(...)` block:

```go
alertStore := alert.NewStore(config.DefaultAlertHistory)

apiSvc := api.New(
	pgStore, bus, detector.Index(),
	tracker, cfg, &logger, alertStore,
)
services = append(services, apiSvc)

if cfg.Alert.Enabled {
	alertDetector := mitre.NewDetector()
	alertSvc, err := alert.New(
		cfg, bus, alertDetector, alertDetector.Index(),
		tracker, alertStore, &logger,
	)
	if err != nil {
		return fmt.Errorf("configuring alerting: %w", err)
	}
	services = append(services, alertSvc)
}
```

## 7. Deployment config

`compose.yml` (backend `environment`) and `.env.example`:

```
HIVE_ALERT_ENABLED=true
HIVE_ALERT_WEBHOOK_URL=
HIVE_ALERT_WEBHOOK_SECRET=
HIVE_ALERT_RULES=            # empty = all: brute_force,tool_transfer,high_threat,new_technique
HIVE_ALERT_COOLDOWN=5m
HIVE_ALERT_MIN_SCORE=60
```

In `compose.yml` use `HIVE_ALERT_WEBHOOK_URL: ${HIVE_ALERT_WEBHOOK_URL:-}` style entries.

## 8. Frontend

`config.ts`:

```ts
// API_ENDPOINTS
ALERTS: { LIST: '/alerts' },
// QUERY_KEYS
ALERTS: {
  ALL: ['alerts'] as const,
  LIST: (limit: number) => [...QUERY_KEYS.ALERTS.ALL, 'list', { limit }] as const,
},
```

`src/api/types/alert.types.ts` (and `export * from './alert.types'` in `types/index.ts`):

```ts
import { z } from 'zod'

export const alertSchema = z.object({
  id: z.string(),
  rule: z.string(),
  severity: z.string(),
  summary: z.string(),
  triggered_at: z.string(),
  sensor_id: z.string(),
  source_ip: z.string(),
  service_type: z.string(),
  delivery: z.string(),
  attempts: z.number(),
  delivery_error: z.string().optional(),
  mitre: z
    .array(
      z.object({
        technique_id: z.string(),
        name: z.string().optional(),
        tactic: z.string().optional(),
      })
    )
    .optional(),
})

export type Alert = z.infer<typeof alertSchema>
```

`src/api/hooks/useAlerts.ts` (and `export * from './useAlerts'` in `hooks/index.ts`):

```ts
import type { UseQueryResult } from '@tanstack/react-query'
import { useQuery } from '@tanstack/react-query'
import type { Alert, ApiResponse } from '@/api/types'
import { API_ENDPOINTS, QUERY_KEYS } from '@/config'
import { apiClient, QUERY_STRATEGIES } from '@/core/api'

export const useAlerts = (limit = 10): UseQueryResult<Alert[], Error> => {
  return useQuery({
    queryKey: QUERY_KEYS.ALERTS.LIST(limit),
    queryFn: async () => {
      const response = await apiClient.get<ApiResponse<Alert[]>>(
        API_ENDPOINTS.ALERTS.LIST,
        { params: { limit } }
      )
      return response.data.data
    },
    ...QUERY_STRATEGIES.live,
  })
}
```

`pages/dashboard/index.tsx`: add `useAlerts` to the hooks import, `const { data: alerts } = useAlerts()`, and a panel at the end of the page:

```tsx
{alerts && alerts.length > 0 && (
  <div className={styles.row}>
    <section className={styles.panel}>
      <h2 className={styles.panelLabel}>Recent Alerts</h2>
      <div className={styles.list}>
        {alerts.map((a) => (
          <div key={a.id} className={styles.listRow}>
            <span className={styles.listLabel}>
              [{a.severity.toUpperCase()}] {a.summary}
            </span>
            <span className={styles.listValue}>{a.delivery}</span>
          </div>
        ))}
      </div>
    </section>
  </div>
)}
```

## 9. Docs

- `learn/04-CHALLENGES.md`: change `- [ ] Intermediate 6: Webhook Alerting` to `- [x] Intermediate 6: Webhook Alerting`.
- `README.md`: add `GET /api/alerts` to the API table and the `HIVE_ALERT_*` variables to the configuration table.

## Behavior summary

| Item | Behavior |
|---|---|
| Rules | `brute_force` (T1110), `tool_transfer` (T1105, SMTP bodies excluded), `high_threat` (session score >= `min_score`), `new_technique` (first sighting since startup) |
| Dedupe | One alert per rule + key within `cooldown` (key: source IP, session ID, or technique ID depending on rule) |
| Delivery | Buffered queue, 2 workers, POST JSON with event, session context and MITRE mappings |
| Signature | `X-Hive-Signature: sha256=<hmac>` (only when a secret is set) |
| Retries | 3 retries at 1s, 4s, 16s on network errors, 5xx, 408 and 429; other 4xx fail immediately |
| No webhook URL | Alerts are still recorded and shown on `/api/alerts` with delivery `local` |

## Verify

```bash
go test -race ./internal/alert/... ./internal/session/...
# receiver: python3 -m http.server won't accept POST; use e.g. https://webhook.site
HIVE_ALERT_WEBHOOK_URL=https://webhook.site/<id> HIVE_ALERT_WEBHOOK_SECRET=test just dev-serve
hydra -l root -P passwords.txt ssh://localhost:2222   # triggers brute_force
```