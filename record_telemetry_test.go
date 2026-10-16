package chronicle_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/acceptance"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/internal/telemetry"
	"github.com/xraph/chronicle/internal/telemetrytest"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
)

// personal is the value fed through every field a person could be named in.
// It must never come out the other side on a span.
const personal = "alice@example.com"

const (
	telApp    = "tel-app"
	telTenant = "tel-tenant"
)

// chronicleSpans returns the ended spans Chronicle started, by name.
func chronicleSpans(t *testing.T, all []sdktrace.ReadOnlySpan) map[string][]sdktrace.ReadOnlySpan {
	t.Helper()
	out := make(map[string][]sdktrace.ReadOnlySpan)
	for _, s := range all {
		if s.InstrumentationScope().Name != telemetry.InstrumentationName {
			continue
		}
		if s.SpanKind() != trace.SpanKindInternal {
			t.Errorf("%s: kind %v, want internal", s.Name(), s.SpanKind())
		}
		out[s.Name()] = append(out[s.Name()], s)
	}
	return out
}

func attr(t *testing.T, s sdktrace.ReadOnlySpan, key attribute.Key) string {
	t.Helper()
	v, ok := telemetrytest.Attr(s, string(key))
	if !ok {
		t.Errorf("%s: no %s attribute", s.Name(), key)
	}
	return v
}

// TestRecordTelemetry covers the path herald and authsome take: Record and
// RecordOnce through the Emitter, with a sink from WithMetrics.
func TestRecordTelemetry(t *testing.T) {
	rec := telemetrytest.Spans(t)
	sink := telemetrytest.NewSink()

	c, err := chronicle.New(
		chronicle.WithStore(store.NewAdapter(memory.New())),
		chronicle.WithMetrics(sink),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, parent := otel.Tracer("test").Start(t.Context(), "handle request")
	good := &audit.Event{AppID: telApp, Action: "login", Resource: "session", Category: "auth", UserID: personal}
	if err := c.Record(ctx, good); err != nil {
		t.Fatalf("Record: %v", err)
	}
	bad := &audit.Event{AppID: telApp, Resource: "session", Category: "auth", UserID: personal}
	if err := c.Record(ctx, bad); !errors.Is(err, chronicle.ErrInvalidQuery) {
		t.Fatalf("Record without an action: %v, want ErrInvalidQuery", err)
	}
	if _, err := c.RecordOnce(ctx, acceptance.Request{
		Producer: "dispatch", Installation: "host-a", SourceKey: "delivery-1", SourceFingerprint: "source-sha",
		Event: &audit.Event{
			AppID: telApp, Action: "run.completed", Resource: "run", Category: "workflow",
			UserID: personal, Timestamp: time.Now().UTC(),
		},
	}); err != nil {
		t.Fatalf("RecordOnce: %v", err)
	}
	parent.End()

	spans := chronicleSpans(t, rec.Ended())
	records := spans[telemetry.SpanRecordEvent]
	if len(records) != 2 {
		t.Fatalf("record event spans = %d, want 2", len(records))
	}
	for _, s := range records {
		if s.Parent().SpanID() != parent.SpanContext().SpanID() {
			t.Errorf("record event is not a child of the caller's span")
		}
		if got := attr(t, s, telemetry.AttrHashScheme); got != "chronicle/v4" {
			t.Errorf("hash scheme = %q, want chronicle/v4", got)
		}
	}
	ok, failed := records[0], records[1]
	if got := attr(t, ok, telemetry.AttrStreamID); !strings.HasPrefix(got, "stream_") || got != good.StreamID.String() {
		t.Errorf("stream id = %q, want the event's stream %s", got, good.StreamID)
	}
	if got := attr(t, ok, telemetry.AttrSealed); got != "false" {
		t.Errorf("sealed = %q on a Chronicle with no sealer", got)
	}
	if ok.Status().Code != codes.Unset {
		t.Errorf("a recorded event has status %+v", ok.Status())
	}
	if failed.Status().Code != codes.Error || failed.Status().Description != "chronicle.ErrInvalidQuery" {
		t.Errorf("a rejected event has status %+v, want the sentinel's name", failed.Status())
	}

	accepts := spans[telemetry.SpanAcceptEvent]
	if len(accepts) != 1 || accepts[0].Parent().SpanID() != parent.SpanContext().SpanID() {
		t.Fatalf("accept event spans = %d, want 1 under the caller's span", len(accepts))
	}
	if _, has := telemetrytest.Attr(accepts[0], string(telemetry.AttrStreamID)); !has {
		t.Error("accept event has no stream id")
	}

	for _, tc := range []struct {
		op, result string
		want       float64
	}{
		{telemetry.OperationRecord, telemetry.ResultOK, 1},
		{telemetry.OperationRecord, telemetry.ResultError, 1},
		{telemetry.OperationRecordOnce, telemetry.ResultOK, 1},
		{telemetry.OperationRecordOnce, telemetry.ResultError, 0},
	} {
		labels := []string{telemetry.LabelOperation, tc.op, telemetry.LabelResult, tc.result}
		counter := sink.Get(telemetry.MetricEventsRecorded, labels...)
		hist := sink.Get(telemetry.MetricRecordDuration, labels...)
		if counter == nil || hist == nil {
			t.Fatalf("no series for %s/%s", tc.op, tc.result)
		}
		if counter.Value() != tc.want || hist.Value() != tc.want {
			t.Errorf("%s/%s: counter %v, histogram count %v, want %v", tc.op, tc.result, counter.Value(), hist.Value(), tc.want)
		}
	}

	if leaks := telemetrytest.Leaks(rec, personal); len(leaks) > 0 {
		t.Errorf("personal data on spans: %s", strings.Join(leaks, "; "))
	}
}
