package extension

import (
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/xraph/forge"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/checkpoint"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/internal/telemetry"
	"github.com/xraph/chronicle/internal/telemetrytest"
	"github.com/xraph/chronicle/keys"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/store"
	memorystore "github.com/xraph/chronicle/store/memory"
	"github.com/xraph/chronicle/stream"
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

// spanProbeStore records the span context the schedulers' queries run under.
// scans holds what ListStreams and LatestCheckpoint saw, which on an idle
// checkpoint tick is every query the tick makes; policies holds what the
// retention run's ListPolicies saw.
type spanProbeStore struct {
	store.Store

	mu       sync.Mutex
	armed    bool // scans are only recorded once the test arms the probe
	scans    []trace.SpanContext
	policies []trace.SpanContext

	scanned, ruled         chan struct{}
	scannedOnce, ruledOnce sync.Once
}

func newSpanProbeStore() *spanProbeStore {
	return &spanProbeStore{Store: memorystore.New(), scanned: make(chan struct{}), ruled: make(chan struct{})}
}

// arm starts recording scans.
func (s *spanProbeStore) arm() {
	s.mu.Lock()
	s.armed = true
	s.mu.Unlock()
}

// noteScan records ctx's span context if the probe is armed, and reports
// whether it did.
func (s *spanProbeStore) noteScan(ctx context.Context) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.armed {
		s.scans = append(s.scans, trace.SpanContextFromContext(ctx))
	}
	return s.armed
}

func (s *spanProbeStore) ListStreams(ctx context.Context, opts stream.ListOpts) ([]*stream.Stream, error) {
	s.noteScan(ctx)
	return s.Store.ListStreams(ctx, opts)
}

func (s *spanProbeStore) LatestCheckpoint(ctx context.Context, streamID id.ID) (*checkpoint.Checkpoint, error) {
	// id.Nil is Register's capability probe, not a scan.
	if !streamID.IsNil() && s.noteScan(ctx) {
		defer s.scannedOnce.Do(func() { close(s.scanned) })
	}
	return s.Store.LatestCheckpoint(ctx, streamID)
}

func (s *spanProbeStore) ListPolicies(ctx context.Context, opts retention.ListPoliciesOpts) ([]*retention.Policy, error) {
	s.mu.Lock()
	s.policies = append(s.policies, trace.SpanContextFromContext(ctx))
	s.mu.Unlock()
	defer s.ruledOnce.Do(func() { close(s.ruled) })
	return s.Store.ListPolicies(ctx, opts)
}

// TestSchedulersDropTheStartSpan runs the real schedulers from Start under a
// ctx carrying a span, the way forge calls Start inside "start chronicle".
// An idle checkpoint tick's scan queries must see no span at all: grove
// opens a db.client span under any valid span context, ended or not, so a
// scan that kept Start's span would file a query into the boot trace on
// every tick, forever. The retention run's queries belong to its own root.
func TestSchedulersDropTheStartSpan(t *testing.T) {
	prevTP, prevProp := otel.GetTracerProvider(), otel.GetTextMapPropagator()
	t.Cleanup(func() {
		otel.SetTracerProvider(prevTP)
		otel.SetTextMapPropagator(prevProp)
	})

	app := forge.New(forge.WithAppName("chronicle-start-span-test"), forge.WithAppLogger(forge.NewNoopLogger()))
	if err := forge.RegisterSpanProcessor(app, tracetest.NewSpanRecorder()); err != nil {
		t.Fatalf("RegisterSpanProcessor: %v", err)
	}

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	probe := newSpanProbeStore()
	e := New(
		WithStore(probe),
		WithUnauthenticatedAPI(),
		WithDisableRoutes(),
		WithKeyProvider(signingKeys{priv}),
		WithRetentionInterval(20*time.Millisecond),
		// A 12s interval polls every second (the floor), and a stream
		// checkpointed just now is not due again for 12s or 1000 events, so
		// the first tick is idle: nothing but the scan.
		WithCheckpoints(CheckpointConfig{Enabled: true, EveryInterval: 12 * time.Second, EveryEvents: 1000}),
	)
	if regErr := e.Register(app); regErr != nil {
		t.Fatalf("Register: %v", regErr)
	}

	ctx := scope.WithAppID(t.Context(), "tel-app")
	ev := &audit.Event{Action: "login", Resource: "session", Category: "auth"}
	if recErr := e.Chronicle().Record(ctx, ev); recErr != nil {
		t.Fatalf("Record: %v", recErr)
	}
	st, err := probe.GetStream(ctx, ev.StreamID)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if _, cpErr := e.checkpointer.CheckpointStream(ctx, checkpoint.StreamHead{
		ID: st.ID, AppID: st.AppID, TenantID: st.TenantID, HeadSeq: st.HeadSeq, HeadHash: st.HeadHash,
	}); cpErr != nil {
		t.Fatalf("CheckpointStream: %v", cpErr)
	}
	probe.arm() // the checkpoint above read its predecessor; only ticks count

	bootCtx, boot := forge.StartSpan(t.Context(), "start chronicle")
	if !boot.SpanContext().IsValid() {
		t.Fatal("the stand-in boot span has no valid span context, so this test would prove nothing")
	}
	if startErr := e.Start(bootCtx); startErr != nil {
		t.Fatalf("Start: %v", startErr)
	}
	boot.End()
	t.Cleanup(func() {
		if stopErr := e.Stop(context.Background()); stopErr != nil {
			t.Errorf("Stop: %v", stopErr)
		}
	})

	for name, ch := range map[string]chan struct{}{"checkpoint scan": probe.scanned, "retention run": probe.ruled} {
		select {
		case <-ch:
		case <-time.After(10 * time.Second):
			t.Fatalf("no %s within 10s", name)
		}
	}

	probe.mu.Lock()
	defer probe.mu.Unlock()
	if len(probe.scans) < 2 {
		t.Fatalf("scan queries = %d, want ListStreams and LatestCheckpoint", len(probe.scans))
	}
	for i, sc := range probe.scans {
		if sc.IsValid() {
			t.Errorf("scan query %d ran under span %s of trace %s; an idle tick must carry no span "+
				"(boot trace is %s)", i, sc.SpanID(), sc.TraceID(), boot.SpanContext().TraceID())
		}
	}
	for _, sc := range probe.policies {
		if !sc.IsValid() || sc.TraceID() == boot.SpanContext().TraceID() {
			t.Errorf("a retention query ran under %v; it belongs to the run's own root span", sc)
		}
	}
}
