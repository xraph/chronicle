package extension

import (
	"time"

	"github.com/xraph/chronicle/sink"
	"github.com/xraph/chronicle/store"
)

// Option configures the Chronicle Forge extension.
type Option func(*Extension)

// WithStore provides the composite store for the extension.
func WithStore(s store.Store) Option {
	return func(e *Extension) { e.opts.store = s }
}

// WithBatchSize sets the event batch size.
func WithBatchSize(n int) Option {
	return func(e *Extension) { e.config.BatchSize = n }
}

// WithFlushInterval sets the batch flush interval.
func WithFlushInterval(d time.Duration) Option {
	return func(e *Extension) { e.config.FlushInterval = d }
}

// WithCryptoErasure enables GDPR crypto-erasure support.
func WithCryptoErasure(enabled bool) Option {
	return func(e *Extension) { e.config.EnableCryptoErasure = enabled }
}

// WithRetentionInterval sets how often retention policies are enforced.
// Set to 0 to disable automatic retention.
func WithRetentionInterval(d time.Duration) Option {
	return func(e *Extension) { e.config.RetentionInterval = d }
}

// WithArchiveSink sets the archive sink for retention.
func WithArchiveSink(s sink.Sink) Option {
	return func(e *Extension) { e.opts.archiveSink = s }
}

// WithConfig sets the Forge extension configuration.
func WithConfig(cfg Config) Option {
	return func(e *Extension) { e.config = cfg }
}

// WithDisableRoutes prevents HTTP route registration.
func WithDisableRoutes() Option {
	return func(e *Extension) { e.config.DisableRoutes = true }
}

// WithDisableMigrate prevents auto-migration on start.
func WithDisableMigrate() Option {
	return func(e *Extension) { e.config.DisableMigrate = true }
}

// WithBasePath sets the URL prefix for chronicle routes.
func WithBasePath(path string) Option {
	return func(e *Extension) { e.config.BasePath = path }
}

// WithRequireConfig requires config to be present in YAML files.
// If true and no config is found, Register returns an error.
func WithRequireConfig(require bool) Option {
	return func(e *Extension) { e.config.RequireConfig = require }
}

// WithGroveDatabase sets the name of the grove.DB to resolve from the DI container.
// The extension will auto-construct the appropriate store backend (postgres/sqlite/mongo)
// based on the grove driver type. Pass an empty string to use the default (unnamed) grove.DB.
func WithGroveDatabase(name string) Option {
	return func(e *Extension) {
		e.config.GroveDatabase = name
		e.useGrove = true
	}
}

// WithGroveKV sets the name of the grove/kv.Store to resolve from the DI container.
// The extension will construct a Redis-backed Chronicle store from the KV store.
// Pass an empty string to use the default (unnamed) grove/kv.Store.
func WithGroveKV(name string) Option {
	return func(e *Extension) {
		e.config.GroveKV = name
		e.useGroveKV = true
	}
}
