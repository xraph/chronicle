// Package telemetry is the tracing and metrics plumbing Chronicle's packages
// share: the tracer every span comes from, the attribute keys spans carry,
// how a failed span is marked, and the metric series each component records.
//
// Spans go to the global OpenTelemetry tracer provider, which forge.New
// installs. Metrics go to a go-utils metrics sink the caller hands in (in a
// Forge app, app.Metrics()), because forge installs no global MeterProvider
// and anything recorded through otel.Meter is never exported.
//
// Nothing here ever puts personal data, secrets, payloads or error text on a
// span or a metric. Attributes are counts, booleans, enum strings and opaque
// stream IDs. Metric labels are fixed enums.
package telemetry

import (
	"context"
	"errors"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	semconv "go.opentelemetry.io/otel/semconv/v1.43.0"
	"go.opentelemetry.io/otel/trace"
)

// InstrumentationName is the tracer name on every span Chronicle starts.
const InstrumentationName = "github.com/xraph/chronicle"

// Span names. Each is a verb and an object, with no IDs in it.
const (
	SpanRecordEvent       = "record event"
	SpanAcceptEvent       = "accept event"
	SpanVerifyChain       = "verify chain"
	SpanEnforceRetention  = "enforce retention"
	SpanEnforcePolicy     = "enforce retention policy"
	SpanCheckpointStreams = "checkpoint streams"
	SpanTakeCheckpoint    = "take checkpoint"
	SpanGenerateReport    = "generate compliance report"
	SpanEraseSubject      = "erase subject"
)

// Attribute keys. Every one is namespaced under chronicle.
const (
	// AttrHashScheme is the digest scheme an event was written under, such
	// as chronicle/v4 or chronicle/v5.
	AttrHashScheme = attribute.Key("chronicle.hash.scheme")
	// AttrSealed is whether the event's personal payload was encrypted for
	// crypto-erasure before it was hashed.
	AttrSealed = attribute.Key("chronicle.sealed")
	// AttrStreamID is the opaque stream ID (a TypeID, stream_...). It names
	// an app and tenant's chain, never a person.
	AttrStreamID = attribute.Key("chronicle.stream.id")

	AttrVerifyValid    = attribute.Key("chronicle.verify.valid")
	AttrVerifyVerified = attribute.Key("chronicle.verify.events_checked")
	AttrVerifyGaps     = attribute.Key("chronicle.verify.gaps")
	AttrVerifyTampered = attribute.Key("chronicle.verify.tampered")
	AttrVerifyPartial  = attribute.Key("chronicle.verify.partial")

	AttrRetentionArchive  = attribute.Key("chronicle.retention.archive")
	AttrRetentionExpired  = attribute.Key("chronicle.retention.expired")
	AttrRetentionArchived = attribute.Key("chronicle.retention.archived")
	AttrRetentionPurged   = attribute.Key("chronicle.retention.purged")

	AttrStreamsScanned      = attribute.Key("chronicle.checkpoint.streams_scanned")
	AttrStreamsDue          = attribute.Key("chronicle.checkpoint.streams_due")
	AttrCheckpointsTaken    = attribute.Key("chronicle.checkpoint.taken")
	AttrCheckpointResult    = attribute.Key("chronicle.checkpoint.result")
	AttrCheckpointEvents    = attribute.Key("chronicle.checkpoint.events")
	AttrCheckpointAlgorithm = attribute.Key("chronicle.checkpoint.algorithm")

	AttrReportType   = attribute.Key("chronicle.report.type")
	AttrReportEvents = attribute.Key("chronicle.report.events")

	AttrErasureEventsAffected = attribute.Key("chronicle.erasure.events_affected")
	AttrErasureKeysDestroyed  = attribute.Key("chronicle.erasure.keys_destroyed")
	AttrErasureLegacyRetained = attribute.Key("chronicle.erasure.legacy_key_retained")
	// AttrErasureFailedStep is the step a failed erasure stopped at: count,
	// record, mark, key_usage, destroy_keys or complete.
	AttrErasureFailedStep = attribute.Key("chronicle.erasure.failed_step")
)

// Tracer returns Chronicle's tracer from the global provider.
//
// It is looked up on every call rather than held in a package variable. A
// tracer taken from the global before a provider is installed only follows
// the first provider ever installed, so tests that swap providers, and apps
// that install theirs late, would otherwise lose spans.
func Tracer() trace.Tracer {
	return otel.Tracer(InstrumentationName)
}

// Start starts an internal span. Pass trace.WithNewRoot for background work
// that must not hang off whatever span the context carries.
func Start(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	opts = append([]trace.SpanStartOption{trace.WithSpanKind(trace.SpanKindInternal)}, opts...)
	return Tracer().Start(ctx, name, opts...)
}

// Sentinel names an error value for [Class].
type Sentinel struct {
	Err  error
	Name string
}

// Class names err for a span's status and its exception.type: the Name of
// the first sentinel err matches, a context error by its package-qualified
// name, and anything else by the Go type of the innermost error in its chain.
//
// It never returns the error's message. Driver and library messages quote the
// values they were given (a duplicate key, a key ID derived from a subject),
// and those must not reach a span.
func Class(err error, known ...Sentinel) string {
	for _, s := range known {
		if errors.Is(err, s.Err) {
			return s.Name
		}
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "context.DeadlineExceeded"
	case errors.Is(err, context.Canceled):
		return "context.Canceled"
	}
	return fmt.Sprintf("%T", innermost(err))
}

// innermost follows err's chain to its end. Where an error wraps several
// (errors.Join, or fmt.Errorf with more than one %w) it follows the first,
// so a batch of failures is named by the type of the first one rather than
// by the joining wrapper.
func innermost(err error) error {
	for {
		switch u := err.(type) { //nolint:errorlint // walking the chain one link at a time is the point
		case interface{ Unwrap() error }:
			next := u.Unwrap()
			if next == nil {
				return err
			}
			err = next
		case interface{ Unwrap() []error }:
			errs := u.Unwrap()
			if len(errs) == 0 || errs[0] == nil {
				return err
			}
			err = errs[0]
		default:
			return err
		}
	}
}

// Fail marks span as failed: an error status whose description is the
// error's class, and an exception event carrying only exception.type. It
// never records the error's message. A nil err does nothing.
func Fail(span trace.Span, err error, known ...Sentinel) {
	if err == nil {
		return
	}
	class := Class(err, known...)
	span.AddEvent(semconv.ExceptionEventName, trace.WithAttributes(semconv.ExceptionType(class)))
	span.SetStatus(codes.Error, class)
}
