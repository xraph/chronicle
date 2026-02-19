package chronicle

import "time"

// Config holds the configuration for a Chronicle instance.
type Config struct {
	// BatchSize is the maximum number of events to accumulate before flushing.
	BatchSize int

	// FlushInterval is the maximum time to wait before flushing accumulated events.
	FlushInterval time.Duration

	// ShutdownTimeout is the maximum time to wait for graceful shutdown.
	ShutdownTimeout time.Duration

	// EnableCryptoErasure enables per-subject encryption for GDPR compliance.
	EnableCryptoErasure bool

	// RetentionCheckInterval is how often the retention enforcer runs.
	RetentionCheckInterval time.Duration
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		BatchSize:              100,
		FlushInterval:          time.Second,
		ShutdownTimeout:        30 * time.Second,
		EnableCryptoErasure:    false,
		RetentionCheckInterval: 24 * time.Hour,
	}
}
