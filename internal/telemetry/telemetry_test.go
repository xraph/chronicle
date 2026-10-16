package telemetry_test

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/xraph/chronicle/internal/telemetry"
	"github.com/xraph/chronicle/internal/telemetrytest"
)

var errSentinel = errors.New("sentinel: something specific")

type typedError struct{ msg string }

func (e *typedError) Error() string { return e.msg }

func TestClass(t *testing.T) {
	known := []telemetry.Sentinel{{Err: errSentinel, Name: "pkg.ErrSentinel"}}

	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"a known sentinel by name, through wrapping", fmt.Errorf("outer: %w", errSentinel), "pkg.ErrSentinel"},
		{"a deadline by its package name", fmt.Errorf("query: %w", context.DeadlineExceeded), "context.DeadlineExceeded"},
		{"a cancellation by its package name", context.Canceled, "context.Canceled"},
		{"anything else by its innermost type", fmt.Errorf("a: %w", fmt.Errorf("b: %w", &typedError{"x"})), "*telemetry_test.typedError"},
		{"a joined error by its first member", fmt.Errorf("a: %w", errors.Join(&typedError{"x"}, errors.New("y"))), "*telemetry_test.typedError"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := telemetry.Class(tc.err, known...); got != tc.want {
				t.Errorf("Class = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestFailNeverRecordsTheMessage pins the one rule that matters most: an
// error's text can quote what it was given (a key ID built from a subject, a
// duplicate value), so only its class reaches the span.
func TestFailNeverRecordsTheMessage(t *testing.T) {
	rec := telemetrytest.Spans(t)

	_, span := telemetry.Start(t.Context(), "do work")
	telemetry.Fail(span, fmt.Errorf("delete key for subject %q: %w", "alice@example.com", &typedError{"alice@example.com"}))
	span.End()

	got := rec.Ended()
	if len(got) != 1 {
		t.Fatalf("spans = %d, want 1", len(got))
	}
	s := got[0]
	if s.SpanKind() != trace.SpanKindInternal {
		t.Errorf("kind = %v, want internal", s.SpanKind())
	}
	if s.Status().Code != codes.Error || s.Status().Description != "*telemetry_test.typedError" {
		t.Errorf("status = %+v, want an error described by its type", s.Status())
	}
	if len(s.Events()) != 1 || s.Events()[0].Name != "exception" {
		t.Fatalf("events = %+v, want one exception event", s.Events())
	}
	for _, kv := range s.Events()[0].Attributes {
		if kv.Key != "exception.type" {
			t.Errorf("exception event carries %s; only exception.type is allowed", kv.Key)
		}
	}
	if leaks := telemetrytest.Leaks(rec, "alice"); len(leaks) > 0 {
		t.Errorf("the error's text reached the span: %s", strings.Join(leaks, "; "))
	}
}

func TestFailIgnoresNil(t *testing.T) {
	rec := telemetrytest.Spans(t)
	_, span := telemetry.Start(t.Context(), "do work")
	telemetry.Fail(span, nil)
	span.End()
	if s := rec.Ended()[0]; s.Status().Code != codes.Unset || len(s.Events()) != 0 {
		t.Errorf("a nil error marked the span: %+v %+v", s.Status(), s.Events())
	}
}

// TestNilMetricsRecordNothing pins that every recorder is safe to call when
// no sink was given, which is the default for a library user.
func TestNilMetricsRecordNothing(_ *testing.T) {
	telemetry.NewRecordMetrics(nil).Observe(telemetry.OperationRecord, nil, time.Millisecond)
	telemetry.NewRetentionMetrics(nil).Add(1, 1)
	telemetry.NewCheckpointMetrics(nil).Inc(telemetry.ResultOK)
	telemetry.NewSchedulerMetrics(nil).Observe(telemetry.JobRetention, nil, time.Second)
}

// TestSeriesAreRegisteredUpFront pins that every label combination exists
// before the first call, so a call never registers a series and every series
// under one name carries the same label keys.
func TestSeriesAreRegisteredUpFront(t *testing.T) {
	sink := telemetrytest.NewSink()
	telemetry.NewRecordMetrics(sink)
	telemetry.NewRetentionMetrics(sink)
	telemetry.NewCheckpointMetrics(sink)
	telemetry.NewSchedulerMetrics(sink)

	want := map[string]struct {
		count int
		keys  string
	}{
		telemetry.MetricEventsRecorded:       {4, "operation,result"},
		telemetry.MetricRecordDuration:       {4, "operation,result"},
		telemetry.MetricEventsArchived:       {1, ""},
		telemetry.MetricEventsPurged:         {1, ""},
		telemetry.MetricCheckpointsAttempted: {4, "result"},
		telemetry.MetricSchedulerRunDuration: {4, "job,result"},
	}
	if got := strings.Join(sink.Names(), " "); len(sink.Names()) != len(want) {
		t.Fatalf("metric names = %s, want %d of them", got, len(want))
	}
	for name, w := range want {
		all := sink.All(name)
		if len(all) != w.count {
			t.Errorf("%s: %d series, want %d", name, len(all), w.count)
		}
		for _, sr := range all {
			if keys := labelKeys(sr.Labels); keys != w.keys {
				t.Errorf("%s: label keys %q, want %q", name, keys, w.keys)
			}
			if sr.Kind == "histogram" && sr.Unit != "s" {
				t.Errorf("%s: unit %q, want s", name, sr.Unit)
			}
		}
	}
}

func labelKeys(l map[string]string) string {
	return strings.Join(slices.Sorted(maps.Keys(l)), ",")
}
