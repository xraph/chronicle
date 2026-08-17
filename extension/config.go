package extension

import "time"

// Config holds the Chronicle extension configuration.
// Fields can be set programmatically via Option functions or loaded from
// YAML configuration files (under "extensions.chronicle" or "chronicle" keys).
type Config struct {
	// DisableRoutes prevents HTTP route registration.
	DisableRoutes bool `json:"disable_routes" mapstructure:"disable_routes" yaml:"disable_routes"`

	// DisableMigrate prevents auto-migration on start.
	DisableMigrate bool `json:"disable_migrate" mapstructure:"disable_migrate" yaml:"disable_migrate"`

	// BasePath is the URL prefix for chronicle routes (default: "/chronicle").
	BasePath string `json:"base_path" mapstructure:"base_path" yaml:"base_path"`

	// BatchSize is the event batch size for the Chronicle emitter.
	BatchSize int `json:"batch_size" mapstructure:"batch_size" yaml:"batch_size"`

	// FlushInterval is the batch flush interval.
	FlushInterval time.Duration `json:"flush_interval" mapstructure:"flush_interval" yaml:"flush_interval"`

	// RetentionInterval sets how often retention policies are enforced.
	// Set to 0 to disable automatic retention.
	RetentionInterval time.Duration `json:"retention_interval" mapstructure:"retention_interval" yaml:"retention_interval"`

	// EnableCryptoErasure enables GDPR crypto-erasure support. Requires a key
	// store; see [WithKeyStore] and [ErrKeyStoreRequired].
	EnableCryptoErasure bool `json:"enable_crypto_erasure" mapstructure:"enable_crypto_erasure" yaml:"enable_crypto_erasure"`

	// GroveDatabase is the name of a grove.DB registered in the DI container.
	// When set, the extension resolves this named database and auto-constructs
	// the appropriate store based on the driver type (pg/sqlite/mongo).
	// When empty and WithGroveDatabase was called, the default (unnamed) DB is used.
	GroveDatabase string `json:"grove_database" mapstructure:"grove_database" yaml:"grove_database"`

	// GroveKV is the name of a grove/kv.Store registered in the DI container.
	// When set, the extension resolves this named KV store and constructs
	// a Redis-backed Chronicle store. When empty and WithGroveKV was called,
	// the default (unnamed) KV store is used.
	GroveKV string `json:"grove_kv" mapstructure:"grove_kv" yaml:"grove_kv"`

	// Auth controls who may call the admin API.
	Auth AuthConfig `json:"auth" mapstructure:"auth" yaml:"auth"`

	// DashboardMutations permits the dashboard's write actions: creating and
	// deleting retention policies, running enforcement, and generating reports.
	//
	// Defaults to false, leaving the dashboard read-only. Chronicle cannot
	// authenticate the dashboard — Forge's dashboard extension owns that route —
	// so enabling this asserts that the route is already protected. Dashboard
	// enforcement purges audit events.
	DashboardMutations bool `json:"dashboard_mutations" mapstructure:"dashboard_mutations" yaml:"dashboard_mutations"`

	// RequireConfig requires config to be present in YAML files.
	// If true and no config is found, Register returns an error.
	RequireConfig bool `json:"-" yaml:"-"`
}

// AuthConfig configures authentication and authorisation for the admin API.
//
// The API exposes operations that permanently destroy audit data — enforcing
// retention purges events, deleting a policy silently disables retention, and an
// erasure request cannot be undone. Chronicle's per-request scope check only
// stops one tenant reaching another's data; it does nothing to stop an
// authenticated caller from destroying their own app's history. So the extension
// refuses to start unless either Provider is set or AllowUnauthenticated is
// explicitly true.
type AuthConfig struct {
	// Provider is the name of a forge auth provider registered in the auth
	// extension's registry. Empty means no authentication.
	Provider string `json:"provider" mapstructure:"provider" yaml:"provider"`

	// ReadScopes are required to observe: list and fetch events, stats, reports,
	// policies and archives, and verify a chain.
	ReadScopes []string `json:"read_scopes" mapstructure:"read_scopes" yaml:"read_scopes"`

	// WriteScopes are required to create records that destroy nothing: saving a
	// retention policy, generating a compliance report.
	WriteScopes []string `json:"write_scopes" mapstructure:"write_scopes" yaml:"write_scopes"`

	// AdminScopes are required for the irreversible operations: enforcing
	// retention, deleting a policy, and requesting an erasure.
	AdminScopes []string `json:"admin_scopes" mapstructure:"admin_scopes" yaml:"admin_scopes"`

	// AllowUnauthenticated mounts the API with no authentication at all.
	//
	// Only appropriate when something in front of Chronicle already
	// authenticates every request, or in local development. Setting it is an
	// explicit acknowledgement that any caller reaching these routes can purge
	// audit history.
	AllowUnauthenticated bool `json:"allow_unauthenticated" mapstructure:"allow_unauthenticated" yaml:"allow_unauthenticated"`
}

// Configured reports whether an auth provider was named.
func (c AuthConfig) Configured() bool { return c.Provider != "" }

// Validate checks that the operator made a deliberate choice about API access.
func (c AuthConfig) Validate(routesEnabled bool) error {
	// With no routes mounted there is nothing to protect.
	if !routesEnabled {
		return nil
	}
	if c.Configured() || c.AllowUnauthenticated {
		return nil
	}
	return ErrAuthNotConfigured
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		BatchSize:         100,
		FlushInterval:     time.Second,
		RetentionInterval: 24 * time.Hour,
	}
}
