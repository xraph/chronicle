// Package extension provides a Forge-compatible extension for Chronicle.
// It implements the forge.Extension interface so Chronicle can be mounted
// into any Forge app with automatic route registration, DI injection,
// metrics, and tracing.
package extension

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/xraph/forge"
	"github.com/xraph/vessel"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/compliance"
	"github.com/xraph/chronicle/handler"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/store"
)

// Extension metadata.
const (
	ExtensionName        = "chronicle"
	ExtensionDescription = "Immutable audit trail with hash chains, GDPR erasure, and compliance reporting"
	ExtensionVersion     = "0.1.0"
)

// Ensure Extension implements forge.Extension at compile time.
var _ forge.Extension = (*Extension)(nil)

// Extension adapts Chronicle as a Forge extension. It implements the
// forge.Extension interface so Chronicle can be mounted into any Forge app.
type Extension struct {
	config    Config
	chronicle *chronicle.Chronicle
	engine    *compliance.Engine
	enforcer  *retention.Enforcer
	api       *handler.API
	store     store.Store
	logger    *slog.Logger
	opts      options

	cancel context.CancelFunc
}

// New creates a new Chronicle Forge extension with the given options.
func New(opts ...Option) *Extension {
	o := defaultOptions()
	for _, opt := range opts {
		opt(&o)
	}
	return &Extension{opts: o}
}

// Name returns the extension name.
func (e *Extension) Name() string { return ExtensionName }

// Description returns the extension description.
func (e *Extension) Description() string { return ExtensionDescription }

// Version returns the extension version.
func (e *Extension) Version() string { return ExtensionVersion }

// Dependencies returns the list of extension names this extension depends on.
func (e *Extension) Dependencies() []string { return []string{} }

// Register implements [forge.Extension]. It initializes the store, creates
// the Chronicle instance, wires up all components, and optionally registers
// HTTP routes into the Forge router.
func (e *Extension) Register(fapp forge.App) error {
	if err := e.init(fapp); err != nil {
		return err
	}

	// Register the Chronicle Emitter in the DI container so other extensions can use it.
	if err := vessel.Provide(fapp.Container(), func() (chronicle.Emitter, error) {
		return e.chronicle, nil
	}); err != nil {
		return fmt.Errorf("chronicle: register emitter in container: %w", err)
	}

	return nil
}

// init builds the Chronicle instance and all sub-components.
func (e *Extension) init(fapp forge.App) error {
	logger := e.opts.logger
	if logger == nil {
		logger = slog.Default()
	}
	e.logger = logger

	// Resolve store.
	s := e.opts.store
	if s == nil {
		return errors.New("chronicle: no store configured (use WithStore option)")
	}
	e.store = s

	// Create the store adapter for Chronicle.
	adapter := store.NewAdapter(s)

	// Build Chronicle options.
	chronicleOpts := []chronicle.Option{
		chronicle.WithStore(adapter),
	}
	if e.opts.batchSize > 0 {
		chronicleOpts = append(chronicleOpts, chronicle.WithBatchSize(e.opts.batchSize))
	}
	if e.opts.flushInterval > 0 {
		chronicleOpts = append(chronicleOpts, chronicle.WithFlushInterval(e.opts.flushInterval))
	}
	if e.opts.enableCryptoErasure {
		chronicleOpts = append(chronicleOpts, chronicle.WithCryptoErasure(true))
	}

	// Create Chronicle.
	c, err := chronicle.New(chronicleOpts...)
	if err != nil {
		return fmt.Errorf("chronicle: create chronicle: %w", err)
	}
	e.chronicle = c

	// Create compliance engine.
	e.engine = compliance.NewEngine(s, s, s, logger)

	// Create retention enforcer.
	e.enforcer = retention.NewEnforcer(s, e.opts.archiveSink, logger)

	// Configure extension settings.
	e.config = Config{
		DisableRoutes:  e.opts.disableRoutes,
		DisableMigrate: e.opts.disableMigrate,
	}

	// Create the API handler with Forge router.
	e.api = handler.New(handler.Dependencies{
		AuditStore:     s,
		VerifyStore:    s,
		ErasureStore:   s,
		RetentionStore: s,
		ReportStore:    s,
		Compliance:     e.engine,
		Retention:      e.enforcer,
		Logger:         logger,
	}, fapp.Router())

	// Register HTTP routes unless disabled.
	if !e.config.DisableRoutes {
		e.api.RegisterRoutes(fapp.Router())
	}

	return nil
}

// Start begins background processing (retention scheduler) and runs
// migrations unless disabled.
func (e *Extension) Start(ctx context.Context) error {
	if e.chronicle == nil {
		return errors.New("chronicle: extension not initialized")
	}

	// Run migrations unless disabled.
	if !e.config.DisableMigrate && e.store != nil {
		if err := e.store.Migrate(ctx); err != nil {
			return fmt.Errorf("chronicle: migration failed: %w", err)
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	e.cancel = cancel

	// Start retention scheduler if configured.
	if e.opts.retentionInterval > 0 {
		go e.runRetentionScheduler(ctx)
	}

	return nil
}

// Stop gracefully shuts down background processing.
func (e *Extension) Stop(_ context.Context) error {
	if e.cancel != nil {
		e.cancel()
	}
	return nil
}

// Health implements [forge.Extension].
func (e *Extension) Health(ctx context.Context) error {
	if e.store == nil {
		return errors.New("chronicle: no store configured")
	}
	return e.store.Ping(ctx)
}

// Handler returns the HTTP handler for all API routes.
// Convenience for standalone use outside Forge.
func (e *Extension) Handler() http.Handler {
	if e.api == nil {
		return http.NotFoundHandler()
	}
	return e.api.Handler()
}

// RegisterRoutes registers all Chronicle API routes into a Forge router.
func (e *Extension) RegisterRoutes(router forge.Router) {
	if e.api != nil {
		e.api.RegisterRoutes(router)
	}
}

// Chronicle returns the Chronicle instance for direct API usage.
func (e *Extension) Chronicle() *chronicle.Chronicle {
	return e.chronicle
}

// Emitter returns the Chronicle Emitter for DI injection.
// Other extensions use this to emit audit events without importing Chronicle internals.
func (e *Extension) Emitter() chronicle.Emitter {
	return e.chronicle
}

// ComplianceEngine returns the compliance engine.
func (e *Extension) ComplianceEngine() *compliance.Engine {
	return e.engine
}

// RetentionEnforcer returns the retention enforcer.
func (e *Extension) RetentionEnforcer() *retention.Enforcer {
	return e.enforcer
}

// API returns the API handler.
func (e *Extension) API() *handler.API {
	return e.api
}

func (e *Extension) runRetentionScheduler(ctx context.Context) {
	ticker := time.NewTicker(e.opts.retentionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			result, err := e.enforcer.Enforce(ctx)
			if err != nil {
				e.logger.ErrorContext(ctx, "retention enforcement failed", "error", err)
				continue
			}
			if result.Archived > 0 || result.Purged > 0 {
				e.logger.InfoContext(ctx, "retention enforcement complete",
					"archived", result.Archived,
					"purged", result.Purged,
				)
			}
		}
	}
}
