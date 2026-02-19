// Package plugin provides the extensibility system for Chronicle.
// Plugins implement subsets of discovery-based interfaces. Chronicle discovers
// which interfaces a plugin implements at registration time and caches the
// dispatch paths for O(1) per-event overhead.
package plugin

import (
	"context"
	"errors"
	"io"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/sink"
)

// ErrSkipEvent is returned by BeforeRecord plugins to skip recording an event.
var ErrSkipEvent = errors.New("chronicle: skip event")

// Plugin is the primary extensibility point for Chronicle.
// Implement any subset of the hook interfaces below.
type Plugin interface {
	Name() string
}

// OnInit is called when Chronicle starts.
type OnInit interface {
	OnInit(ctx context.Context) error
}

// OnShutdown is called when Chronicle stops.
type OnShutdown interface {
	OnShutdown(ctx context.Context) error
}

// BeforeRecord fires BEFORE an event is persisted.
// Use for enrichment (add metadata), filtering (return ErrSkipEvent), or transformation.
type BeforeRecord interface {
	OnBeforeRecord(ctx context.Context, event *audit.Event) error
}

// AfterRecord fires AFTER an event is successfully persisted to the store.
// Use for notifications, alerts, forwarding.
type AfterRecord interface {
	OnAfterRecord(ctx context.Context, event *audit.Event) error
}

// SinkProvider provides a custom sink to be added to the sink fan-out.
type SinkProvider interface {
	Sink() sink.Sink
}

// ComplianceReporter provides a custom compliance report type.
type ComplianceReporter interface {
	ReportType() string
	// Generate is defined with generic types to avoid import cycles with compliance package.
}

// Exporter provides a custom export format.
type Exporter interface {
	Format() string
	Export(ctx context.Context, data any, w io.Writer) error
}

// AlertHandler fires when an event matches alert criteria.
type AlertHandler interface {
	OnAlert(ctx context.Context, event *audit.Event, rule *AlertRule) error
}
