package extension

import (
	"time"

	"github.com/xraph/chronicle/crypto"
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
//
// Requires [WithKeyStore]; without one startup fails with [ErrKeyStoreRequired].
// With both, each subject's metadata, reason and IP are encrypted before being
// hashed and stored, the store is wrapped so reads come back decrypted, and an
// erasure request destroys the subject's key. See crypto.Sealer for exactly which
// fields are covered and which deliberately are not.
func WithCryptoErasure(enabled bool) Option {
	return func(e *Extension) { e.config.EnableCryptoErasure = enabled }
}

// WithKeyStore supplies the per-subject key store used by crypto-erasure.
//
// Required when EnableCryptoErasure is set. The key store's durability decides
// whether sealed events can ever be read again: losing it is indistinguishable
// from erasing every subject, so an in-memory store is only suitable for tests.
func WithKeyStore(ks crypto.KeyStore) Option {
	return func(e *Extension) { e.opts.keyStore = ks }
}

// WithAuth protects the admin API with a registered forge auth provider,
// requiring the given scopes per operation class.
//
// Classes are graded by blast radius: read observes, write creates records that
// destroy nothing, and admin covers the irreversible operations (enforcing
// retention, deleting a policy, requesting an erasure). Pass nil for a class to
// require authentication without any particular scope.
//
//	extension.WithAuth("jwt",
//	    []string{"chronicle:read"},
//	    []string{"chronicle:write"},
//	    []string{"chronicle:admin"},
//	)
func WithAuth(provider string, readScopes, writeScopes, adminScopes []string) Option {
	return func(e *Extension) {
		e.config.Auth.Provider = provider
		e.config.Auth.ReadScopes = readScopes
		e.config.Auth.WriteScopes = writeScopes
		e.config.Auth.AdminScopes = adminScopes
	}
}

// WithUnauthenticatedAPI mounts the admin API with no authentication.
//
// Only appropriate when something in front of Chronicle already authenticates
// every request, or in local development. Without this (or [WithAuth]) the
// extension refuses to start, because the API can purge audit history. See
// [ErrAuthNotConfigured].
func WithUnauthenticatedAPI() Option {
	return func(e *Extension) { e.config.Auth.AllowUnauthenticated = true }
}

// WithDashboardMutations allows the dashboard's write actions: creating and
// deleting retention policies, running enforcement, and generating reports.
//
// The dashboard is read-only by default. Chronicle cannot authenticate the
// dashboard route (Forge's dashboard extension owns it), so enabling this
// asserts that something else already protects it. Dashboard enforcement purges
// audit events.
func WithDashboardMutations() Option {
	return func(e *Extension) { e.config.DashboardMutations = true }
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
