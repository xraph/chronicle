package extension

import (
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/xraph/forge"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/internal/telemetry"
	"github.com/xraph/chronicle/internal/telemetrytest"
	"github.com/xraph/chronicle/keys"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/scope"
	memorystore "github.com/xraph/chronicle/store/memory"
)

// signingKeys vends one ed25519 key for checkpoint signing.
type signingKeys struct{ priv ed25519.PrivateKey }

func (k signingKeys) Current(context.Context, keys.Use) ([]byte, string, error) {
	return k.priv, "ckpt-1", nil
}

func (k signingKeys) ByID(context.Context, string) ([]byte, error) { return k.priv, nil }

// scrape reads the app's Prometheus exposition, the body /_/metrics serves.
func scrape(t *testing.T, app forge.App) string {
	t.Helper()
	p, ok := app.Metrics().(interface{ PrometheusHandler() http.Handler })
	if !ok {
		t.Fatalf("app metrics %T have no Prometheus handler", app.Metrics())
	}
	rr := httptest.NewRecorder()
	p.PrometheusHandler().ServeHTTP(rr, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/_/metrics", nil))
	body, err := io.ReadAll(rr.Body)
	if err != nil {
		t.Fatalf("read scrape: %v", err)
	}
	return string(body)
}

// sample returns the value of the first scrape line for name carrying every
// one of labels, or "" when there is none.
func sample(body, name string, labels ...string) string {
	for line := range strings.SplitSeq(body, "\n") {
		if !strings.HasPrefix(line, name+"{") && !strings.HasPrefix(line, name+" ") {
			continue
		}
		matched := true
		for _, l := range labels {
			if !strings.Contains(line, l) {
				matched = false
				break
			}
		}
		if matched {
			return line[strings.LastIndex(line, " ")+1:]
		}
	}
	return ""
}

// TestSchedulerTelemetry runs one retention run and two checkpoint ticks
// through a real forge app, under a ctx carrying a stand-in for forge's boot
// span, the way Start's ctx does. Each run with work must be a root span of
// its own, an idle tick must start none, and the metrics must reach the
// app's scrape under their forge_ names.
func TestSchedulerTelemetry(t *testing.T) {
	prevTP, prevProp := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	t.Cleanup(func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	})

	app := forge.New(forge.WithAppName("chronicle-telemetry-test"), forge.WithAppLogger(forge.NewNoopLogger()))
	rec := tracetest.NewSpanRecorder()
	if err := forge.RegisterSpanProcessor(app, rec); err != nil {
		t.Fatalf("RegisterSpanProcessor: %v", err)
	}

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	e := New(
		WithStore(memorystore.New()),
		WithUnauthenticatedAPI(),
		WithDisableRoutes(),
		WithKeyProvider(signingKeys{priv}),
		WithCheckpoints(CheckpointConfig{Enabled: true, EveryInterval: time.Hour, EveryEvents: 1}),
	)
	if err := e.Register(app); err != nil {
		t.Fatalf("Register: %v", err)
	}

	ctx := scope.WithTenantID(scope.WithAppID(t.Context(), "tel-app"), "tel-tenant")
	for _, age := range []time.Duration{48 * time.Hour, 0} {
		ev := &audit.Event{
			Action: "login", Resource: "session", Category: "auth", UserID: "alice@example.com",
			Timestamp: time.Now().Add(-age).UTC(),
		}
		if err := e.Chronicle().Record(ctx, ev); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	policy := &retention.Policy{
		ID: id.NewPolicyID(), Category: "auth", Duration: 24 * time.Hour,
		AppID: "tel-app", TenantID: "tel-tenant",
	}
	policy.CreatedAt, policy.UpdatedAt = time.Now(), time.Now()
	if err := e.store.SavePolicy(ctx, policy); err != nil {
		t.Fatalf("SavePolicy: %v", err)
	}

	bootCtx, boot := forge.StartSpan(t.Context(), "start chronicle")
	e.enforceRetention(bootCtx)
	e.checkpointAllStreams(bootCtx) // the stream is due: never checkpointed
	e.checkpointAllStreams(bootCtx) // idle: nothing new since that checkpoint
	boot.End()

	spans := map[string][]string{}
	byName := map[string]int{}
	for _, s := range rec.Ended() {
		if s.InstrumentationScope().Name != telemetry.InstrumentationName {
			continue
		}
		byName[s.Name()]++
		spans[s.Name()] = append(spans[s.Name()], s.SpanContext().SpanID().String())
		switch s.Name() {
		case telemetry.SpanEnforceRetention, telemetry.SpanCheckpointStreams:
			if s.Parent().IsValid() {
				t.Errorf("%s has a parent; a scheduled run must be a root span", s.Name())
			}
			if s.SpanContext().TraceID() == boot.SpanContext().TraceID() {
				t.Errorf("%s joined the boot trace", s.Name())
			}
		}
	}
	for name, want := range map[string]int{
		telemetry.SpanEnforceRetention:  1,
		telemetry.SpanEnforcePolicy:     1,
		telemetry.SpanCheckpointStreams: 1, // the idle tick started none
		telemetry.SpanTakeCheckpoint:    1,
	} {
		if byName[name] != want {
			t.Errorf("%s spans = %d, want %d", name, byName[name], want)
		}
	}
	for _, s := range rec.Ended() {
		parent := s.Parent().SpanID().String()
		switch s.Name() {
		case telemetry.SpanEnforcePolicy:
			if len(spans[telemetry.SpanEnforceRetention]) == 0 || parent != spans[telemetry.SpanEnforceRetention][0] {
				t.Error("the policy span is not a child of the retention run")
			}
		case telemetry.SpanTakeCheckpoint:
			if len(spans[telemetry.SpanCheckpointStreams]) == 0 || parent != spans[telemetry.SpanCheckpointStreams][0] {
				t.Error("the checkpoint span is not a child of the checkpoint run")
			}
		}
	}
	if leaks := telemetrytest.Leaks(rec, "alice"); len(leaks) > 0 {
		t.Errorf("personal data on spans: %s", strings.Join(leaks, "; "))
	}

	body := scrape(t, app)
	for _, tc := range []struct {
		name   string
		labels []string
		want   string
	}{
		{"forge_chronicle_events_recorded_total", []string{`operation="record"`, `result="ok"`}, "2"},
		{"forge_chronicle_events_recorded_total", []string{`operation="record_once"`, `result="error"`}, "0"},
		{"forge_chronicle_record_duration_seconds_count", []string{`operation="record"`, `result="ok"`}, "2"},
		{"forge_chronicle_events_purged_total", nil, "1"},
		{"forge_chronicle_events_archived_total", nil, "0"},
		{"forge_chronicle_checkpoints_attempted_total", []string{`result="ok"`}, "1"},
		{"forge_chronicle_checkpoints_attempted_total", []string{`result="nothing_new"`}, "0"},
		{"forge_chronicle_scheduler_run_duration_seconds_count", []string{`job="retention"`, `result="ok"`}, "1"},
		{"forge_chronicle_scheduler_run_duration_seconds_count", []string{`job="checkpoint"`, `result="ok"`}, "2"},
	} {
		if got := sample(body, tc.name, tc.labels...); got != tc.want {
			t.Errorf("%s%v = %q, want %q", tc.name, tc.labels, got, tc.want)
		}
	}
	if strings.Contains(body, "alice") || strings.Contains(body, "tel-app") || strings.Contains(body, "stream_") {
		t.Error("an ID or personal value reached a metric label")
	}
}
