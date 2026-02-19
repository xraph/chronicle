// Example: Chronicle plugin system.
//
// Demonstrates creating custom plugins that implement BeforeRecord (enrichment),
// AfterRecord (notification), and SinkProvider (custom output sink).
// Plugins are registered with the plugin Registry which dispatches hook calls
// at O(1) cost per event.
package main

import (
	"context"
	"fmt"
	"log"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/plugin"
	"github.com/xraph/chronicle/scope"
	"github.com/xraph/chronicle/sink"
	"github.com/xraph/chronicle/store"
	"github.com/xraph/chronicle/store/memory"
)

// ---------------------------------------------------------------------------
// EnrichmentPlugin: adds environment metadata to every event before recording.
// Implements plugin.Plugin + plugin.BeforeRecord + plugin.AfterRecord.
// ---------------------------------------------------------------------------

type EnrichmentPlugin struct {
	env string
}

func (p *EnrichmentPlugin) Name() string { return "enrichment" }

func (p *EnrichmentPlugin) OnBeforeRecord(_ context.Context, event *audit.Event) error {
	// Enrich: add environment and a normalized action tag.
	if event.Metadata == nil {
		event.Metadata = make(map[string]any)
	}
	event.Metadata["env"] = p.env
	event.Metadata["action_normalized"] = strings.ToLower(strings.ReplaceAll(event.Action, ".", "_"))

	fmt.Printf("  [enrichment] enriched event: action=%s env=%s\n", event.Action, p.env)
	return nil
}

func (p *EnrichmentPlugin) OnAfterRecord(_ context.Context, event *audit.Event) error {
	fmt.Printf("  [enrichment] event persisted: id=%s action=%s seq=%d\n",
		event.ID.String(), event.Action, event.Sequence)
	return nil
}

// ---------------------------------------------------------------------------
// CounterSink: a custom sink that simply counts events written.
// ---------------------------------------------------------------------------

type CounterSink struct {
	mu    sync.Mutex
	count int
}

func (s *CounterSink) Name() string { return "counter" }

func (s *CounterSink) Write(_ context.Context, events []*audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count += len(events)
	fmt.Printf("  [counter-sink] received %d event(s), total=%d\n", len(events), s.count)
	return nil
}

func (s *CounterSink) Flush(_ context.Context) error { return nil }
func (s *CounterSink) Close() error                  { return nil }

func (s *CounterSink) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.count
}

// ---------------------------------------------------------------------------
// SinkPlugin: provides a custom sink via the SinkProvider interface.
// ---------------------------------------------------------------------------

type SinkPlugin struct {
	sink sink.Sink
}

func NewSinkPlugin(s sink.Sink) *SinkPlugin {
	return &SinkPlugin{sink: s}
}

func (p *SinkPlugin) Name() string    { return "custom-sink-provider" }
func (p *SinkPlugin) Sink() sink.Sink { return p.sink }

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	ctx := context.Background()
	ctx = scope.WithAppID(ctx, "myapp")
	ctx = scope.WithTenantID(ctx, "tenant-1")

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))

	// 1. Create the plugin registry.
	registry := plugin.NewRegistry(logger)

	// 2. Register an enrichment plugin (BeforeRecord + AfterRecord).
	enrichPlugin := &EnrichmentPlugin{env: "production"}
	registry.Register(enrichPlugin)
	fmt.Println("Registered plugin: enrichment (BeforeRecord + AfterRecord)")

	// 3. Register a SinkProvider plugin with a custom counter sink.
	counterSink := &CounterSink{}
	sinkPlugin := NewSinkPlugin(counterSink)
	registry.Register(sinkPlugin)
	fmt.Println("Registered plugin: custom-sink-provider (SinkProvider)")

	// 4. List all sinks provided by plugins.
	sinks := registry.Sinks()
	fmt.Printf("\nPlugin-provided sinks: %d\n", len(sinks))
	for _, s := range sinks {
		fmt.Printf("  - %s\n", s.Name())
	}

	// 5. Create Chronicle + memory store.
	mem := memory.New()
	adapter := store.NewAdapter(mem)
	c, err := chronicle.New(chronicle.WithStore(adapter))
	if err != nil {
		log.Fatal(err)
	}

	// 6. Simulate the Chronicle pipeline with plugin hooks.
	fmt.Println("\n--- Recording events with plugin hooks ---")

	events := []struct {
		action   string
		resource string
		category string
	}{
		{"login", "session", "auth"},
		{"read", "document", "data"},
		{"permission.grant", "role", "access"},
	}

	for _, ev := range events {
		fmt.Printf("\nRecording: %s %s\n", ev.action, ev.resource)

		// Build the event using the builder API.
		built := c.Info(ctx, ev.action, ev.resource, "res-1").
			Category(ev.category).
			UserID("user-42").
			Event()

		// Fire BeforeRecord hooks (enrichment).
		if berr := registry.EmitBeforeRecord(ctx, built); berr != nil {
			fmt.Printf("  BeforeRecord returned: %v\n", berr)
			continue
		}

		// Record via Chronicle.
		if rerr := c.Record(ctx, built); rerr != nil {
			log.Fatal(rerr)
		}

		// Fire AfterRecord hooks (notification).
		registry.EmitAfterRecord(ctx, built)

		// Write to plugin-provided sinks.
		for _, s := range sinks {
			if werr := s.Write(ctx, []*audit.Event{built}); werr != nil {
				fmt.Printf("  sink %s error: %v\n", s.Name(), werr)
			}
		}
	}

	// 7. Show enrichment results.
	fmt.Println("\n--- Verifying enrichment ---")
	result, err := c.Query(ctx, &audit.Query{Limit: 100, Order: "asc"})
	if err != nil {
		log.Fatal(err)
	}
	for _, ev := range result.Events {
		fmt.Printf("  action=%-20s env=%v normalized=%v\n",
			ev.Action, ev.Metadata["env"], ev.Metadata["action_normalized"])
	}

	// 8. Show sink stats.
	fmt.Printf("\nCounter sink total: %d events\n", counterSink.Count())

	// 9. List registered plugins.
	fmt.Printf("\nRegistered plugins: %d\n", len(registry.Plugins()))
	for _, p := range registry.Plugins() {
		fmt.Printf("  - %s\n", p.Name())
	}
}
