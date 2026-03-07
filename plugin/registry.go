package plugin

import (
	"context"
	"errors"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/chronicle/audit"
	"github.com/xraph/chronicle/sink"
)

// Registry manages plugins and dispatches hook calls.
type Registry struct {
	plugins    []Plugin
	logger     log.Logger
	alertRules []AlertRule

	// Type-cached dispatch lists (built at registration time).
	onInit        []OnInit
	onShutdown    []OnShutdown
	beforeRecord  []BeforeRecord
	afterRecord   []AfterRecord
	sinkProviders []SinkProvider
	exporters     []Exporter
	alertHandlers []AlertHandler
}

// NewRegistry creates a new plugin Registry.
func NewRegistry(logger log.Logger) *Registry {
	if logger == nil {
		logger = log.NewNoopLogger()
	}
	return &Registry{logger: logger}
}

// Register adds a plugin and discovers its hook implementations.
func (r *Registry) Register(p Plugin) {
	r.plugins = append(r.plugins, p)

	// Type-switch discovery at registration time — O(1) per event dispatch.
	if h, ok := p.(OnInit); ok {
		r.onInit = append(r.onInit, h)
	}
	if h, ok := p.(OnShutdown); ok {
		r.onShutdown = append(r.onShutdown, h)
	}
	if h, ok := p.(BeforeRecord); ok {
		r.beforeRecord = append(r.beforeRecord, h)
	}
	if h, ok := p.(AfterRecord); ok {
		r.afterRecord = append(r.afterRecord, h)
	}
	if h, ok := p.(SinkProvider); ok {
		r.sinkProviders = append(r.sinkProviders, h)
	}
	if h, ok := p.(Exporter); ok {
		r.exporters = append(r.exporters, h)
	}
	if h, ok := p.(AlertHandler); ok {
		r.alertHandlers = append(r.alertHandlers, h)
	}
}

// SetAlertRules sets the alert rules for matching events.
func (r *Registry) SetAlertRules(rules []AlertRule) {
	r.alertRules = rules
}

// EmitInit calls OnInit on all registered plugins.
func (r *Registry) EmitInit(ctx context.Context) error {
	for _, h := range r.onInit {
		if err := h.OnInit(ctx); err != nil {
			r.logger.Error("plugin OnInit error",
				log.String("error", err.Error()),
			)
		}
	}
	return nil
}

// EmitShutdown calls OnShutdown on all registered plugins.
func (r *Registry) EmitShutdown(ctx context.Context) error {
	for _, h := range r.onShutdown {
		if err := h.OnShutdown(ctx); err != nil {
			r.logger.Error("plugin OnShutdown error",
				log.String("error", err.Error()),
			)
		}
	}
	return nil
}

// EmitBeforeRecord calls OnBeforeRecord on all registered plugins.
// Returns ErrSkipEvent if any plugin returns it.
// Other errors are logged but do not block the pipeline.
func (r *Registry) EmitBeforeRecord(ctx context.Context, event *audit.Event) error {
	for _, h := range r.beforeRecord {
		if err := h.OnBeforeRecord(ctx, event); err != nil {
			if errors.Is(err, ErrSkipEvent) {
				return ErrSkipEvent
			}
			r.logger.Error("plugin OnBeforeRecord error",
				log.String("error", err.Error()),
			)
		}
	}
	return nil
}

// EmitAfterRecord calls OnAfterRecord on all registered plugins.
// Errors are logged but do not block the pipeline.
func (r *Registry) EmitAfterRecord(ctx context.Context, event *audit.Event) {
	for _, h := range r.afterRecord {
		if err := h.OnAfterRecord(ctx, event); err != nil {
			r.logger.Error("plugin OnAfterRecord error",
				log.String("error", err.Error()),
			)
		}
	}

	// Check alert rules.
	r.checkAlerts(ctx, event)
}

// Sinks returns all sinks provided by registered plugins.
func (r *Registry) Sinks() []sink.Sink {
	sinks := make([]sink.Sink, 0, len(r.sinkProviders))
	for _, p := range r.sinkProviders {
		sinks = append(sinks, p.Sink())
	}
	return sinks
}

// Plugins returns all registered plugins.
func (r *Registry) Plugins() []Plugin {
	return r.plugins
}

// checkAlerts fires alert handlers for events matching alert rules.
func (r *Registry) checkAlerts(ctx context.Context, event *audit.Event) {
	if len(r.alertHandlers) == 0 || len(r.alertRules) == 0 {
		return
	}

	for i := range r.alertRules {
		rule := &r.alertRules[i]
		if !matchesRule(event, rule) {
			continue
		}
		for _, h := range r.alertHandlers {
			if err := h.OnAlert(ctx, event, rule); err != nil {
				r.logger.Error("plugin OnAlert error",
					log.String("error", err.Error()),
				)
			}
		}
	}
}

// matchesRule checks if an event matches an alert rule.
// All non-empty rule fields must match.
func matchesRule(event *audit.Event, rule *AlertRule) bool {
	if rule.Severity != "" && event.Severity != rule.Severity {
		return false
	}
	if rule.Category != "" && event.Category != rule.Category {
		return false
	}
	if rule.Action != "" && event.Action != rule.Action {
		return false
	}
	if rule.Outcome != "" && event.Outcome != rule.Outcome {
		return false
	}
	return true
}
