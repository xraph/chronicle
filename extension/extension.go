// Package extension provides a Forge-compatible extension for Chronicle.
// It implements the forge.Extension interface so Chronicle can be mounted
// into any Forge app with automatic route registration, DI injection,
// metrics, and tracing.
//
// Configuration can be provided programmatically via Option functions
// or via YAML configuration files under "extensions.chronicle" or "chronicle" keys.
package extension

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/xraph/forge"
	dashboard "github.com/xraph/forge/extensions/dashboard"
	"github.com/xraph/forge/extensions/dashboard/contributor"
	"github.com/xraph/grove"
	"github.com/xraph/grove/kv"
	"github.com/xraph/vessel"

	"github.com/xraph/chronicle"
	"github.com/xraph/chronicle/compliance"
	chronicledash "github.com/xraph/chronicle/dashboard"
	"github.com/xraph/chronicle/handler"
	"github.com/xraph/chronicle/retention"
	"github.com/xraph/chronicle/sink"
	"github.com/xraph/chronicle/store"
	mongostore "github.com/xraph/chronicle/store/mongo"
	pgstore "github.com/xraph/chronicle/store/postgres"
	redisstore "github.com/xraph/chronicle/store/redis"
	sqlitestore "github.com/xraph/chronicle/store/sqlite"
)

// Extension metadata.
const (
	ExtensionName        = "chronicle"
	ExtensionDescription = "Immutable audit trail with hash chains, GDPR erasure, and compliance reporting"
	ExtensionVersion     = "0.1.0"
)

// Ensure Extension implements forge.Extension and dashboard.DashboardAware at compile time.
var (
	_ forge.Extension          = (*Extension)(nil)
	_ dashboard.DashboardAware = (*Extension)(nil)
)

// internalOpts holds non-config options that are set programmatically only.
type internalOpts struct {
	store       store.Store
	archiveSink sink.Sink
}

// Extension adapts Chronicle as a Forge extension. It implements the
// forge.Extension interface so Chronicle can be mounted into any Forge app.
type Extension struct {
	*forge.BaseExtension

	config     Config
	opts       internalOpts
	chronicle  *chronicle.Chronicle
	engine     *compliance.Engine
	enforcer   *retention.Enforcer
	api        *handler.API
	store      store.Store
	useGrove   bool
	useGroveKV bool

	cancel context.CancelFunc
}

// New creates a new Chronicle Forge extension with the given options.
func New(opts ...Option) *Extension {
	e := &Extension{
		BaseExtension: forge.NewBaseExtension(ExtensionName, ExtensionVersion, ExtensionDescription),
	}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Register implements [forge.Extension]. It initializes the store, creates
// the Chronicle instance, wires up all components, and optionally registers
// HTTP routes into the Forge router.
func (e *Extension) Register(fapp forge.App) error {
	if err := e.BaseExtension.Register(fapp); err != nil {
		return err
	}

	if err := e.loadConfiguration(); err != nil {
		return err
	}

	// Resolve store from grove DI if configured.
	// DB takes precedence over KV when both are configured.
	if e.opts.store == nil && e.useGrove {
		groveDB, err := e.resolveGroveDB(fapp)
		if err != nil {
			return fmt.Errorf("chronicle: %w", err)
		}
		s, err := e.buildStoreFromGroveDB(groveDB)
		if err != nil {
			return err
		}
		e.opts.store = s
	}
	if e.opts.store == nil && e.useGroveKV {
		kvStore, err := e.resolveGroveKV(fapp)
		if err != nil {
			return fmt.Errorf("chronicle: %w", err)
		}
		e.opts.store = redisstore.New(kvStore)
	}
	if e.opts.store == nil {
		if db, err := vessel.Inject[*grove.DB](fapp.Container()); err == nil {
			// Auto-discover default grove.DB from container (matches authsome/cortex pattern).
			s, err := e.buildStoreFromGroveDB(db)
			if err != nil {
				return err
			}
			e.opts.store = s
			e.Logger().Info("chronicle: auto-discovered grove.DB from container",
				forge.F("driver", db.Driver().Name()),
			)
		}
	}

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
	if e.config.BatchSize > 0 {
		chronicleOpts = append(chronicleOpts, chronicle.WithBatchSize(e.config.BatchSize))
	}
	if e.config.FlushInterval > 0 {
		chronicleOpts = append(chronicleOpts, chronicle.WithFlushInterval(e.config.FlushInterval))
	}
	if e.config.EnableCryptoErasure {
		chronicleOpts = append(chronicleOpts, chronicle.WithCryptoErasure(true))
	}

	// Create Chronicle.
	c, err := chronicle.New(chronicleOpts...)
	if err != nil {
		return fmt.Errorf("chronicle: create chronicle: %w", err)
	}
	e.chronicle = c

	// Sub-components require log.Logger; use the BaseExtension logger.
	logger := e.Logger()

	// Create compliance engine.
	e.engine = compliance.NewEngine(s, s, s, logger)

	// Create retention enforcer.
	e.enforcer = retention.NewEnforcer(s, e.opts.archiveSink, logger)

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
		basePath := e.config.BasePath
		if basePath == "" {
			basePath = "/chronicle"
		}
		e.api.RegisterRoutes(fapp.Router().Group(basePath))
	}

	e.Logger().Info("chronicle extension registered",
		forge.F("disable_routes", e.config.DisableRoutes),
		forge.F("disable_migrate", e.config.DisableMigrate),
	)

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
	if e.config.RetentionInterval > 0 {
		go e.runRetentionScheduler(ctx)
	}

	e.MarkStarted()
	return nil
}

// Stop gracefully shuts down background processing.
func (e *Extension) Stop(_ context.Context) error {
	if e.cancel != nil {
		e.cancel()
	}
	e.MarkStopped()
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

// DashboardContributor implements dashboard.DashboardAware. It returns a
// LocalContributor that renders chronicle pages, widgets, and settings in the
// Forge dashboard using templ + ForgeUI.
func (e *Extension) DashboardContributor() contributor.LocalContributor {
	return chronicledash.New(
		chronicledash.NewManifest(),
		e.store,
		e.engine,
		e.enforcer,
		chronicledash.Config{
			BatchSize:           e.config.BatchSize,
			FlushInterval:       e.config.FlushInterval,
			RetentionInterval:   e.config.RetentionInterval,
			EnableCryptoErasure: e.config.EnableCryptoErasure,
			BasePath:            e.config.BasePath,
		},
	)
}

func (e *Extension) runRetentionScheduler(ctx context.Context) {
	ticker := time.NewTicker(e.config.RetentionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			result, err := e.enforcer.Enforce(ctx)
			if err != nil {
				e.Logger().Error("retention enforcement failed",
					forge.F("error", err.Error()),
				)
				continue
			}
			if result.Archived > 0 || result.Purged > 0 {
				e.Logger().Info("retention enforcement complete",
					forge.F("archived", result.Archived),
					forge.F("purged", result.Purged),
				)
			}
		}
	}
}

// --- Config Loading (mirrors grove/shield extension pattern) ---

// loadConfiguration loads config from YAML files or programmatic sources.
func (e *Extension) loadConfiguration() error {
	programmaticConfig := e.config

	// Try loading from config file.
	fileConfig, configLoaded := e.tryLoadFromConfigFile()

	if !configLoaded {
		if programmaticConfig.RequireConfig {
			return errors.New("chronicle: configuration is required but not found in config files; " +
				"ensure 'extensions.chronicle' or 'chronicle' key exists in your config")
		}

		// Use programmatic config merged with defaults.
		e.config = e.mergeWithDefaults(programmaticConfig)
	} else {
		// Config loaded from YAML -- merge with programmatic options.
		e.config = e.mergeConfigurations(fileConfig, programmaticConfig)
	}

	// Enable grove resolution if YAML config specifies a grove database or KV.
	if e.config.GroveDatabase != "" {
		e.useGrove = true
	}
	if e.config.GroveKV != "" {
		e.useGroveKV = true
	}

	e.Logger().Debug("chronicle: configuration loaded",
		forge.F("disable_routes", e.config.DisableRoutes),
		forge.F("disable_migrate", e.config.DisableMigrate),
		forge.F("base_path", e.config.BasePath),
		forge.F("grove_database", e.config.GroveDatabase),
		forge.F("grove_kv", e.config.GroveKV),
		forge.F("batch_size", e.config.BatchSize),
		forge.F("retention_interval", e.config.RetentionInterval),
	)

	return nil
}

// tryLoadFromConfigFile attempts to load config from YAML files.
func (e *Extension) tryLoadFromConfigFile() (Config, bool) {
	cm := e.App().Config()
	var cfg Config

	// Try "extensions.chronicle" first (namespaced pattern).
	if cm.IsSet("extensions.chronicle") {
		if err := cm.Bind("extensions.chronicle", &cfg); err == nil {
			e.Logger().Debug("chronicle: loaded config from file",
				forge.F("key", "extensions.chronicle"),
			)
			return cfg, true
		}
		e.Logger().Warn("chronicle: failed to bind extensions.chronicle config",
			forge.F("error", "bind failed"),
		)
	}

	// Try legacy "chronicle" key.
	if cm.IsSet("chronicle") {
		if err := cm.Bind("chronicle", &cfg); err == nil {
			e.Logger().Debug("chronicle: loaded config from file",
				forge.F("key", "chronicle"),
			)
			return cfg, true
		}
		e.Logger().Warn("chronicle: failed to bind chronicle config",
			forge.F("error", "bind failed"),
		)
	}

	return Config{}, false
}

// mergeWithDefaults fills zero-valued fields with defaults.
func (e *Extension) mergeWithDefaults(cfg Config) Config {
	defaults := DefaultConfig()
	if cfg.BatchSize == 0 {
		cfg.BatchSize = defaults.BatchSize
	}
	if cfg.FlushInterval == 0 {
		cfg.FlushInterval = defaults.FlushInterval
	}
	if cfg.RetentionInterval == 0 {
		cfg.RetentionInterval = defaults.RetentionInterval
	}
	return cfg
}

// mergeConfigurations merges YAML config with programmatic options.
// YAML config takes precedence for most fields; programmatic bool flags fill gaps.
func (e *Extension) mergeConfigurations(yamlConfig, programmaticConfig Config) Config {
	// Programmatic bool flags override when true.
	if programmaticConfig.DisableRoutes {
		yamlConfig.DisableRoutes = true
	}
	if programmaticConfig.DisableMigrate {
		yamlConfig.DisableMigrate = true
	}
	if programmaticConfig.EnableCryptoErasure {
		yamlConfig.EnableCryptoErasure = true
	}

	// String fields: YAML takes precedence.
	if yamlConfig.BasePath == "" && programmaticConfig.BasePath != "" {
		yamlConfig.BasePath = programmaticConfig.BasePath
	}
	if yamlConfig.GroveDatabase == "" && programmaticConfig.GroveDatabase != "" {
		yamlConfig.GroveDatabase = programmaticConfig.GroveDatabase
	}
	if yamlConfig.GroveKV == "" && programmaticConfig.GroveKV != "" {
		yamlConfig.GroveKV = programmaticConfig.GroveKV
	}

	// Duration/int fields: YAML takes precedence, programmatic fills gaps.
	if yamlConfig.BatchSize == 0 && programmaticConfig.BatchSize != 0 {
		yamlConfig.BatchSize = programmaticConfig.BatchSize
	}
	if yamlConfig.FlushInterval == 0 && programmaticConfig.FlushInterval != 0 {
		yamlConfig.FlushInterval = programmaticConfig.FlushInterval
	}
	if yamlConfig.RetentionInterval == 0 && programmaticConfig.RetentionInterval != 0 {
		yamlConfig.RetentionInterval = programmaticConfig.RetentionInterval
	}

	// Fill remaining zeros with defaults.
	return e.mergeWithDefaults(yamlConfig)
}

// resolveGroveDB resolves a *grove.DB from the DI container.
// If GroveDatabase is set, it looks up the named DB; otherwise it uses the default.
func (e *Extension) resolveGroveDB(fapp forge.App) (*grove.DB, error) {
	if e.config.GroveDatabase != "" {
		db, err := vessel.InjectNamed[*grove.DB](fapp.Container(), e.config.GroveDatabase)
		if err != nil {
			return nil, fmt.Errorf("grove database %q not found in container: %w", e.config.GroveDatabase, err)
		}
		return db, nil
	}
	db, err := vessel.Inject[*grove.DB](fapp.Container())
	if err != nil {
		return nil, fmt.Errorf("default grove database not found in container: %w", err)
	}
	return db, nil
}

// resolveGroveKV resolves a *kv.Store from the DI container.
// If GroveKV is set, it looks up the named KV store; otherwise it uses the default.
func (e *Extension) resolveGroveKV(fapp forge.App) (*kv.Store, error) {
	if e.config.GroveKV != "" {
		kvStore, err := vessel.InjectNamed[*kv.Store](fapp.Container(), e.config.GroveKV)
		if err != nil {
			return nil, fmt.Errorf("grove KV store %q not found in container: %w", e.config.GroveKV, err)
		}
		return kvStore, nil
	}
	kvStore, err := vessel.Inject[*kv.Store](fapp.Container())
	if err != nil {
		return nil, fmt.Errorf("default grove KV store not found in container: %w", err)
	}
	return kvStore, nil
}

// buildStoreFromGroveDB constructs the appropriate store backend
// based on the grove driver type (pg, sqlite, mongo).
func (e *Extension) buildStoreFromGroveDB(db *grove.DB) (store.Store, error) {
	driverName := db.Driver().Name()
	switch driverName {
	case "pg":
		return pgstore.New(db), nil
	case "sqlite":
		return sqlitestore.New(db), nil
	case "mongo":
		return mongostore.New(db), nil
	default:
		return nil, fmt.Errorf("chronicle: unsupported grove driver %q", driverName)
	}
}
