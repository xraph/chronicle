package plugin_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/id"
	"github.com/xraph/chronicle/plugin"
	"github.com/xraph/chronicle/sink"
)

func testEvent() *audit.Event {
	return &audit.Event{
		ID:        id.NewAuditID(),
		Timestamp: time.Now().UTC(),
		Action:    "create",
		Resource:  "user",
		Category:  "auth",
		Outcome:   audit.OutcomeSuccess,
		Severity:  audit.SeverityInfo,
	}
}

// enrichPlugin adds metadata before record.
type enrichPlugin struct{}

func (p *enrichPlugin) Name() string { return "enrich" }
func (p *enrichPlugin) OnBeforeRecord(_ context.Context, event *audit.Event) error {
	if event.Metadata == nil {
		event.Metadata = make(map[string]any)
	}
	event.Metadata["enriched"] = true
	return nil
}

// filterPlugin skips events with action "skip-me".
type filterPlugin struct{}

func (p *filterPlugin) Name() string { return "filter" }
func (p *filterPlugin) OnBeforeRecord(_ context.Context, event *audit.Event) error {
	if event.Action == "skip-me" {
		return plugin.ErrSkipEvent
	}
	return nil
}

// afterPlugin records that it was called.
type afterPlugin struct {
	mu     sync.Mutex
	called int
}

func (p *afterPlugin) Name() string { return "after" }
func (p *afterPlugin) OnAfterRecord(_ context.Context, _ *audit.Event) error {
	p.mu.Lock()
	p.called++
	p.mu.Unlock()
	return nil
}

// errorPlugin always returns an error.
type errorPlugin struct{}

func (p *errorPlugin) Name() string { return "error" }
func (p *errorPlugin) OnBeforeRecord(_ context.Context, _ *audit.Event) error {
	return errors.New("plugin error")
}
func (p *errorPlugin) OnAfterRecord(_ context.Context, _ *audit.Event) error {
	return errors.New("plugin error")
}

// testSink for SinkProvider testing.
type testSink struct {
	name string
}

func (s *testSink) Name() string                                    { return s.name }
func (s *testSink) Write(_ context.Context, _ []*audit.Event) error { return nil }
func (s *testSink) Flush(_ context.Context) error                   { return nil }
func (s *testSink) Close() error                                    { return nil }

// sinkPlugin provides a custom sink.
type sinkPlugin struct {
	s sink.Sink
}

func (p *sinkPlugin) Name() string    { return "sink-provider" }
func (p *sinkPlugin) Sink() sink.Sink { return p.s }

// alertPlugin records alerts.
type alertPlugin struct {
	mu     sync.Mutex
	alerts []string
}

func (p *alertPlugin) Name() string { return "alerter" }
func (p *alertPlugin) OnAlert(_ context.Context, event *audit.Event, rule *plugin.AlertRule) error {
	p.mu.Lock()
	p.alerts = append(p.alerts, event.Action+":"+rule.Severity)
	p.mu.Unlock()
	return nil
}

func TestBeforeRecordEnrichment(t *testing.T) {
	r := plugin.NewRegistry(nil)
	r.Register(&enrichPlugin{})

	event := testEvent()
	err := r.EmitBeforeRecord(context.Background(), event)
	if err != nil {
		t.Fatalf("EmitBeforeRecord: %v", err)
	}

	if event.Metadata["enriched"] != true {
		t.Error("expected metadata to be enriched")
	}
}

func TestBeforeRecordSkipEvent(t *testing.T) {
	r := plugin.NewRegistry(nil)
	r.Register(&filterPlugin{})

	event := testEvent()
	event.Action = "skip-me"

	err := r.EmitBeforeRecord(context.Background(), event)
	if !errors.Is(err, plugin.ErrSkipEvent) {
		t.Errorf("expected ErrSkipEvent, got: %v", err)
	}
}

func TestBeforeRecordErrorDoesNotBlock(t *testing.T) {
	r := plugin.NewRegistry(nil)
	r.Register(&errorPlugin{})
	r.Register(&enrichPlugin{})

	event := testEvent()
	err := r.EmitBeforeRecord(context.Background(), event)
	if err != nil {
		t.Errorf("error plugin should not block pipeline, got: %v", err)
	}

	// Enrichment plugin should still have run.
	if event.Metadata["enriched"] != true {
		t.Error("enrichment plugin should still run after error plugin")
	}
}

func TestAfterRecord(t *testing.T) {
	r := plugin.NewRegistry(nil)
	ap := &afterPlugin{}
	r.Register(ap)

	r.EmitAfterRecord(context.Background(), testEvent())

	ap.mu.Lock()
	count := ap.called
	ap.mu.Unlock()

	if count != 1 {
		t.Errorf("expected afterPlugin called 1 time, got %d", count)
	}
}

func TestAfterRecordErrorDoesNotBlock(t *testing.T) {
	r := plugin.NewRegistry(nil)
	r.Register(&errorPlugin{})
	ap := &afterPlugin{}
	r.Register(ap)

	// Should not panic or block.
	r.EmitAfterRecord(context.Background(), testEvent())

	ap.mu.Lock()
	count := ap.called
	ap.mu.Unlock()

	if count != 1 {
		t.Errorf("afterPlugin should still run, got called %d times", count)
	}
}

func TestSinkProvider(t *testing.T) {
	r := plugin.NewRegistry(nil)
	ts := &testSink{name: "custom"}
	r.Register(&sinkPlugin{s: ts})

	sinks := r.Sinks()
	if len(sinks) != 1 {
		t.Fatalf("expected 1 sink, got %d", len(sinks))
	}
	if sinks[0].Name() != "custom" {
		t.Errorf("sink name = %q, want %q", sinks[0].Name(), "custom")
	}
}

func TestAlertHandler(t *testing.T) {
	r := plugin.NewRegistry(nil)
	ap := &alertPlugin{}
	r.Register(ap)
	r.SetAlertRules([]plugin.AlertRule{
		{Severity: audit.SeverityCritical},
	})

	// Non-matching event.
	r.EmitAfterRecord(context.Background(), testEvent()) // severity=info

	ap.mu.Lock()
	count := len(ap.alerts)
	ap.mu.Unlock()
	if count != 0 {
		t.Errorf("expected 0 alerts for info event, got %d", count)
	}

	// Matching event.
	critical := testEvent()
	critical.Severity = audit.SeverityCritical
	r.EmitAfterRecord(context.Background(), critical)

	ap.mu.Lock()
	count = len(ap.alerts)
	ap.mu.Unlock()
	if count != 1 {
		t.Errorf("expected 1 alert for critical event, got %d", count)
	}
}

func TestRegistryPlugins(t *testing.T) {
	r := plugin.NewRegistry(nil)
	r.Register(&enrichPlugin{})
	r.Register(&filterPlugin{})

	if len(r.Plugins()) != 2 {
		t.Errorf("expected 2 plugins, got %d", len(r.Plugins()))
	}
}
