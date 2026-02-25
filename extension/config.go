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

	// EnableCryptoErasure enables GDPR crypto-erasure support.
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

	// RequireConfig requires config to be present in YAML files.
	// If true and no config is found, Register returns an error.
	RequireConfig bool `json:"-" yaml:"-"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		BatchSize:         100,
		FlushInterval:     time.Second,
		RetentionInterval: 24 * time.Hour,
	}
}
